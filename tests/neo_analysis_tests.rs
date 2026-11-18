use neo::memory::{
    CpuidGate, CpuidRecord, InterceptionRequest, decode_page_batch, interception_packet,
};
use neo::protocol::memory::*;
use neo::unwind::{UnwindContext, unwind};
use neo::user::{self, Export, MemoryReader, Module, Pattern, PatternScanner, Section};
use std::collections::BTreeMap;

const BASE: u64 = 0x180000000;
const STACK: u64 = 0x100000;

#[derive(Default)]
struct Memory {
    regions: BTreeMap<u64, Vec<u8>>,
    reads: usize,
}

impl MemoryReader for Memory {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        assert!(HEADER_BYTES + ITEM_BYTES + length <= BUFFER_BYTES);
        self.reads += 1;
        let (base, bytes) = self
            .regions
            .range(..=address)
            .next_back()
            .ok_or("unmapped fixture")?;
        let offset = (address - base) as usize;
        bytes
            .get(offset..offset + length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "unmapped fixture".into())
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn pe() -> Vec<u8> {
    let mut bytes = vec![0; 0x5000];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 60, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 1);
    put16(&mut bytes, 0x94, 240);
    let optional = 0x98;
    put16(&mut bytes, optional, 0x20b);
    put32(&mut bytes, optional + 16, 0x1000);
    put32(&mut bytes, optional + 56, 0x5000);
    put32(&mut bytes, optional + 108, 16);
    let section = optional + 240;
    bytes[section..section + 5].copy_from_slice(b".text");
    put32(&mut bytes, section + 8, 0x1000);
    put32(&mut bytes, section + 12, 0x1000);
    put32(&mut bytes, section + 36, 0x60000020);
    bytes
}

fn module() -> Module {
    Module {
        base: BASE,
        size: 0x5000,
        entry_point: BASE + 0x1000,
        name: "sample.dll".into(),
        path: "sample.dll".into(),
        sections: vec![Section {
            name: ".text".into(),
            start: BASE + 0x1000,
            size: 0x1000,
            characteristics: 0x60000020,
        }],
        exports: vec![],
        export_error: None,
        exception_rva: 0x3000,
        exception_size: 12,
    }
}

fn unwind_fixture(codes: &[u8], prolog_size: u8, frame: u8) -> (Memory, Module) {
    let mut bytes = pe();
    put32(&mut bytes, 0x3000, 0x1000);
    put32(&mut bytes, 0x3004, 0x1100);
    put32(&mut bytes, 0x3008, 0x3100);
    bytes[0x3100] = 1;
    bytes[0x3101] = prolog_size;
    bytes[0x3102] = (codes.len() / 2) as u8;
    bytes[0x3103] = frame;
    bytes[0x3104..0x3104 + codes.len()].copy_from_slice(codes);
    bytes[0x1000..0x1100].fill(0x90);
    let mut memory = Memory::default();
    memory.regions.insert(BASE, bytes);
    memory.regions.insert(STACK, vec![0; 0x1000]);
    (memory, module())
}

fn context(offset: u64) -> UnwindContext {
    let mut registers = [0; 16];
    registers[4] = STACK;
    UnwindContext {
        rip: BASE + offset,
        rsp: STACK,
        registers,
    }
}

#[test]
fn live_and_captured_unwind_support_large_static_tables_without_bulk_reads() {
    let count = 782_976u32;
    let table_rva = 0x0200_0000u32;
    let mut entries = vec![0; count as usize * 12];
    for index in 0..count {
        let offset = index as usize * 12;
        let begin = 0x1000 + index * 16;
        put32(&mut entries, offset, begin);
        put32(&mut entries, offset + 4, begin + 16);
        put32(&mut entries, offset + 8, 0x100);
    }
    let begin = 0x1000 + (count - 1) * 16;
    let mut image = module();
    image.size = 0x0300_0000;
    image.exception_rva = table_rva;
    image.exception_size = count * 12;
    image.sections[0].size = begin + 16 - 0x1000;
    let mut memory = Memory::default();
    memory.regions.insert(BASE + u64::from(table_rva), entries);
    memory.regions.insert(BASE + 0x100, vec![1, 0, 0, 0]);
    memory
        .regions
        .insert(BASE + u64::from(begin), vec![0x90; 16]);
    memory.regions.insert(STACK, vec![0; 16]);
    for captured in [false, true] {
        memory.reads = 0;
        let result = neo::unwind::unwind_with_tables(
            &mut |address, length| {
                let unused_page = BASE + u64::from(table_rva) + 4096;
                if address < unused_page + 4096 && address + length as u64 > unused_page {
                    return Err("PARTIAL_TRANSFER: unrelated table page is not resident".into());
                }
                memory.read(address, length)
            },
            std::slice::from_ref(&image),
            &[],
            context(u64::from(begin) + 4),
            8,
            captured,
        );
        assert!(result.complete, "{}", result.stop);
        assert_eq!(result.frames[0].method, "pdata");
        assert!(memory.reads < 40, "large tables must use sparse lookup");
    }
    let unavailable = unwind(
        &mut |address, length| {
            if address >= BASE + u64::from(table_rva) {
                Err("PARTIAL_TRANSFER: required table page is not resident".into())
            } else {
                memory.read(address, length)
            }
        },
        std::slice::from_ref(&image),
        context(u64::from(begin) + 4),
        8,
    );
    assert!(!unavailable.complete);
    assert!(unavailable.stop.contains("PARTIAL_TRANSFER"));

    image.exception_size += 1;
    let malformed = neo::unwind::unwind_with_tables(
        &mut memory,
        std::slice::from_ref(&image),
        &[],
        context(u64::from(begin) + 4),
        8,
        true,
    );
    assert!(!malformed.complete);
    image.exception_size = count * 12;
    image.size = table_rva + image.exception_size - 1;
    let outside_image = neo::unwind::unwind_with_tables(
        &mut memory,
        &[image],
        &[],
        context(u64::from(begin) + 4),
        8,
        true,
    );
    assert!(!outside_image.complete);
}

#[test]
fn cpuid_wire_records_have_reserved_padding_and_optional_debug_gate() {
    let mut request = InterceptionRequest {
        operation: CPUID_SET,
        cr3: 0x2000,
        token: 7,
        cpuid_records: vec![CpuidRecord {
            leaf: 7,
            subleaf: 1,
            subleaf_mask: u32::MAX,
            values: [1, 2, 4, 8],
            keep_masks: [!1, !2, !4, !8],
        }],
        ..Default::default()
    };
    let packet = interception_packet(&request).unwrap();
    assert_eq!(packet.len(), HEADER_BYTES + 48);
    assert_eq!(word(&packet, HEADER_BYTES + 12), 0);
    assert_eq!(word(&packet, HEADER_BYTES + 16), 1);
    assert_eq!(word(&packet, HEADER_BYTES + 32), !1);
    assert_eq!(quad(&packet, 24), 0);
    request.cpuid_gate = Some(CpuidGate {
        dr3: 0x7ffe0ff0,
        dr7_mask: 0xff,
        dr7_value: 0x40,
    });
    let packet = interception_packet(&request).unwrap();
    assert_eq!(quad(&packet, 24), 0x7ffe0ff0);
    assert_eq!(quad(&packet, 144), 0xff);
    assert_eq!(quad(&packet, 152), 0x40);
    request.cpuid_records.push(request.cpuid_records[0].clone());
    assert!(interception_packet(&request).is_err());
    request.cpuid_records.truncate(1);
    request.cpuid_records[0].leaf = MEMORY_LEAF;
    assert!(interception_packet(&request).is_err());
    request.operation = CPUID_CLEAR;
    assert_eq!(interception_packet(&request).unwrap().len(), HEADER_BYTES);
}

#[test]
fn resident_batches_allow_streaming_beyond_tracking_capacity_and_reject_bad_cursors() {
    let mut bytes = neo::memory::tracking_packet(AD_ENUMERATE, 0, TRACK_MAX_PAGES).unwrap();
    put64(&mut bytes, 16, 0x401000);
    put64(&mut bytes, 72, 0x800000000000);
    put32(&mut bytes, 32, 1);
    put64(&mut bytes, HEADER_BYTES, 0x2000);
    put64(&mut bytes, HEADER_BYTES + 8, 0x400000);
    let batch = decode_page_batch(&bytes, 0x2000, 0x400000).unwrap();
    assert_eq!(batch.pages, vec![(0x2000, 0x400000)]);
    assert_eq!(batch.next, 0x401000);
    put64(&mut bytes, 16, 0x400000);
    assert!(decode_page_batch(&bytes, 0x2000, 0x400000).is_err());
    assert!(decode_page_batch(&bytes[..100], 0x2000, 0).is_err());
    let limit = 1 << 47;
    put64(&mut bytes, 16, limit);
    put32(&mut bytes, 32, 0);
    let end = decode_page_batch(&bytes, 0x2000, limit).unwrap();
    assert_eq!(end.next, limit);
    assert!(end.pages.is_empty());
}

#[test]
fn scan_finds_overlapping_wildcards_across_contiguous_batches_but_never_across_gaps() {
    let mut scanner = PatternScanner::new(Pattern::parse("AA ?? AA").unwrap());
    assert!(scanner.feed(0x1ffe, &[0xaa, 1], 10).is_empty());
    assert_eq!(
        scanner.feed(0x2000, &[0xaa, 2, 0xaa], 10),
        vec![0x1ffe, 0x2000]
    );
    scanner.gap();
    assert!(scanner.feed(0x2003, &[0xaa], 10).is_empty());
    assert!(scanner.feed(0x3000, &[1, 0xaa], 10).is_empty());
    assert!(Pattern::parse("?? ??").is_err());
    assert!(Pattern::parse("GG").is_err());
    assert!(Pattern::parse("A?").is_err());
}

#[test]
fn pe_exports_sections_forwarders_and_symbolic_addresses_are_resolved() {
    let mut bytes = pe();
    put32(&mut bytes, 0x98 + 112, 0x2000);
    put32(&mut bytes, 0x98 + 116, 0x400);
    put32(&mut bytes, 0x2010, 1);
    put32(&mut bytes, 0x2014, 2);
    put32(&mut bytes, 0x2018, 2);
    put32(&mut bytes, 0x201c, 0x2040);
    put32(&mut bytes, 0x2020, 0x2050);
    put32(&mut bytes, 0x2024, 0x2060);
    put32(&mut bytes, 0x2040, 0x1000);
    put32(&mut bytes, 0x2044, 0x2090);
    put32(&mut bytes, 0x2050, 0x2070);
    put32(&mut bytes, 0x2054, 0x2080);
    put16(&mut bytes, 0x2060, 0);
    put16(&mut bytes, 0x2062, 1);
    bytes[0x2070..0x2074].copy_from_slice(b"Foo\0");
    bytes[0x2080..0x2084].copy_from_slice(b"Bar\0");
    bytes[0x2090..0x209a].copy_from_slice(b"other.Baz\0");
    let mut memory = Memory::default();
    memory.regions.insert(BASE, bytes);
    let sample = user::read_module(
        &mut memory,
        BASE,
        0x5000,
        "sample.dll".into(),
        "sample.dll".into(),
    )
    .unwrap();
    assert_eq!(sample.sections[0].start, BASE + 0x1000);
    assert_eq!(sample.exports[1].forwarder.as_deref(), Some("other.Baz"));
    let mut missing_name = |address, length| {
        if address == BASE + 0x2080 {
            Err("export name page is not resident".into())
        } else {
            memory.read(address, length)
        }
    };
    let partial = user::read_module(
        &mut missing_name,
        BASE,
        0x5000,
        "sample.dll".into(),
        "sample.dll".into(),
    )
    .unwrap();
    assert_eq!(
        partial.export_error.as_deref(),
        Some("export name page is not resident")
    );
    let partial = [partial];
    assert_eq!(
        user::resolve_address(&partial, "sample!Foo").unwrap(),
        BASE + 0x1000
    );
    assert!(
        user::resolve_address(&partial, "sample!Bar")
            .unwrap_err()
            .contains("export table is incomplete")
    );
    let mut other = module();
    other.base += 0x10000;
    other.name = "other.dll".into();
    other.exports.push(Export {
        name: Some("Baz".into()),
        ordinal: 1,
        address: Some(other.base + 0x1000),
        forwarder: None,
    });
    let modules = [sample, other];
    assert_eq!(
        user::resolve_address(&modules, "SAMPLE!Foo").unwrap(),
        BASE + 0x1000
    );
    assert_eq!(
        user::resolve_address(&modules, "sample.dll+0x20").unwrap(),
        BASE + 0x20
    );
    assert_eq!(
        user::resolve_address(&modules, "sample!#1").unwrap(),
        BASE + 0x1000
    );
    assert_eq!(
        user::resolve_address(&modules, "sample!Bar").unwrap(),
        BASE + 0x11000
    );
    assert!(user::resolve_address(&modules, "sample!foo").is_err());
    assert!(user::resolve_address(&modules, "sample+0xffff").is_err());
    assert!(memory.reads < 30);
}

#[test]
fn suspended_loader_state_is_distinct_from_corruption_and_an_initialized_empty_list() {
    let mut memory = Memory::default();
    memory.regions.insert(0x200000, vec![0; 0x1000]);
    assert!(
        user::initialized_modules(&mut memory, 0x200000)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        user::modules(&mut memory, 0x200000).unwrap_err(),
        "loader is not initialized"
    );
    put64(memory.regions.get_mut(&0x200000).unwrap(), 0x18, 0x200101);
    assert!(
        user::initialized_modules(&mut memory, 0x200000)
            .unwrap_err()
            .contains("invalid native x64 loader")
    );
    let loader = memory.regions.get_mut(&0x200000).unwrap();
    put64(loader, 0x18, 0x200100);
    put64(loader, 0x120, 0x200120);
    put64(loader, 0x128, 0x200120);
    assert!(
        user::initialized_modules(&mut memory, 0x200000)
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(user::initialized_modules(&mut memory, 0).is_err());
    assert!(user::initialized_modules(&mut memory, 0x300000).is_err());
}

#[test]
fn malformed_pe_and_loader_cycles_fail_without_unbounded_reads() {
    let mut memory = Memory::default();
    let mut bytes = pe();
    put32(&mut bytes, 60, u32::MAX);
    memory.regions.insert(BASE, bytes);
    assert!(user::read_module(&mut memory, BASE, 0x5000, "bad".into(), "bad".into()).is_err());
    let mut loader = vec![0; 0x1000];
    put64(&mut loader, 0x18, 0x200100);
    put64(&mut loader, 0x120, 0x200210);
    put64(&mut loader, 0x128, 0x200210);
    put64(&mut loader, 0x210, 0x200210);
    put64(&mut loader, 0x218, 0x200120);
    put64(&mut loader, 0x230, BASE);
    put32(&mut loader, 0x240, 0x5000);
    memory.regions.insert(0x200000, loader);
    memory.regions.insert(BASE, pe());
    assert!(
        user::modules(&mut memory, 0x200000)
            .unwrap_err()
            .contains("loader list")
    );
}

#[test]
fn disassembly_labels_rip_relative_memory_and_calls_without_treating_constants_as_addresses() {
    let bytes = [
        0xe8, 0xfb, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00,
        0x00, 0x00,
    ];
    let instructions = user::disassemble(&[module()], BASE + 0x1000, &bytes, 20);
    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[0].targets[0].0, BASE + 0x1100);
    assert_eq!(instructions[1].targets[0].0, BASE + 0x101c);
    assert!(instructions[2].targets.is_empty());
    assert!(user::disassemble(&[], BASE, &[0x0f], 20).is_empty());
}

#[test]
fn pdata_unwinds_optimized_frames_without_rbp_and_handles_partial_prologs() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(
        &mut memory,
        std::slice::from_ref(&module),
        context(0x1020),
        8,
    );
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames.len(), 2);
    assert_eq!(result.frames[0].method, "pdata");
    assert_eq!(result.frames[1].rsp, STACK + 48);
    assert_eq!(result.frames[1].method, "leaf");
    let result = unwind(&mut memory, &[module], context(0x1002), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames.len(), 1);
}

#[test]
fn epilog_simulation_uses_the_current_stack_instead_of_undoing_the_prolog_twice() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x1020..0x1026]
        .copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0x5b, 0xc3]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, 0x1234);
    put64(memory.regions.get_mut(&STACK).unwrap(), 48, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "epilog");
    assert_eq!(result.frames[1].rsp, STACK + 56);
}

#[test]
fn caller_frames_use_return_address_metadata_even_when_its_code_was_not_captured() {
    let (mut memory, mut module) = unwind_fixture(&[4, 0x42], 4, 0);
    module.exception_size = 24;
    let image = memory.regions.get_mut(&BASE).unwrap();
    put32(image, 0x300c, 0x1200);
    put32(image, 0x3010, 0x1300);
    put32(image, 0x3014, 0x3200);
    image[0x3200..0x3206].copy_from_slice(&[1, 4, 1, 0, 4, 0x42]);
    image[0x1280..0x1285].copy_from_slice(&[0x48, 0x83, 0xc4, 8, 0xc3]);
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 40, BASE + 0x1280);
    put64(stack, 88, BASE + 0x1400);
    for sparse in [false, true] {
        if sparse {
            let image = memory.regions.remove(&BASE).unwrap();
            memory
                .regions
                .insert(BASE + 0x1000, image[0x1000..0x1100].to_vec());
            memory
                .regions
                .insert(BASE + 0x3000, image[0x3000..0x3300].to_vec());
        }
        let result = unwind(
            &mut memory,
            std::slice::from_ref(&module),
            context(0x1020),
            8,
        );
        assert!(result.complete, "{}", result.stop);
        assert_eq!(result.frames.len(), 3);
        assert_eq!(result.frames[1].method, "pdata");
        assert_eq!(result.frames[2].rsp, STACK + 96);
    }
}

#[test]
fn version_two_epilogs_unwind_from_the_remaining_pops_without_code_bytes() {
    let codes = [4, 0x16, 0x30, 6, 6, 0x32, 4, 0xc0, 2, 0x10];
    let (mut memory, module) = unwind_fixture(&codes, 6, 0);
    let mut image = memory.regions.remove(&BASE).unwrap();
    image[0x3100] = 2;
    memory
        .regions
        .insert(BASE + 0x3000, image[0x3000..0x3300].to_vec());
    put64(memory.regions.get_mut(&STACK).unwrap(), 16, BASE + 0x1200);
    for (rip, already_popped) in [(0x10d0, 0), (0x10fc, 0), (0x10fe, 8), (0x10ff, 16)] {
        let mut current = context(rip);
        current.rsp += already_popped;
        current.registers[4] = current.rsp;
        let result = unwind(&mut memory, std::slice::from_ref(&module), current, 8);
        assert!(result.complete, "{rip:#x} {}", result.stop);
        assert_eq!(result.frames[0].method, "epilog");
        assert_eq!(result.frames[1].rip, BASE + 0x1200);
        assert_eq!(result.frames[1].rsp, STACK + 24);
    }
    put64(memory.regions.get_mut(&STACK).unwrap(), 48, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], context(0x1040), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "pdata");
    assert_eq!(result.frames[1].rsp, STACK + 56);
}

#[test]
fn version_two_epilogs_follow_chains_and_restore_machine_frames() {
    let (mut memory, module) = unwind_fixture(&[1, 0x16, 0, 6], 0, 0);
    let image = memory.regions.get_mut(&BASE).unwrap();
    image[0x3100] = 2 | (4 << 3);
    put32(image, 0x3108, 0x1300);
    put32(image, 0x310c, 0x1400);
    put32(image, 0x3110, 0x3200);
    image[0x3200..0x3206].copy_from_slice(&[1, 0, 1, 0, 0, 0x1a]);
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0, BASE + 0x1200);
    put64(stack, 8, 0x33);
    put64(stack, 24, STACK + 0x100);
    let result = unwind(&mut memory, &[module], context(0x10ff), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "epilog");
    assert_eq!(result.frames[1].rsp, STACK + 0x100);
}

#[test]
fn version_two_epilogs_pop_registers_across_chained_records() {
    let (mut memory, module) = unwind_fixture(&[4, 0x16, 0, 6, 2, 0xc0], 2, 0);
    let image = memory.regions.get_mut(&BASE).unwrap();
    image[0x3100] = 2 | (4 << 3);
    put32(image, 0x310c, 0x1300);
    put32(image, 0x3110, 0x1400);
    put32(image, 0x3114, 0x3200);
    image[0x3200..0x320a].copy_from_slice(&[2, 1, 3, 0, 2, 0x16, 0, 6, 1, 0x30]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 16, BASE + 0x1200);
    for (rip, already_popped) in [(0x10fc, 0), (0x10fe, 8), (0x10ff, 16)] {
        let mut current = context(rip);
        current.rsp += already_popped;
        current.registers[4] = current.rsp;
        let result = unwind(&mut memory, std::slice::from_ref(&module), current, 8);
        assert!(result.complete, "{rip:#x} {}", result.stop);
        assert_eq!(result.frames[0].method, "epilog");
        assert_eq!(result.frames[1].rip, BASE + 0x1200);
        assert_eq!(result.frames[1].rsp, STACK + 24);
    }
}

#[test]
fn version_two_epilogs_pop_flags_before_a_machine_frame_without_saved_registers() {
    let (mut memory, module) = unwind_fixture(&[3, 0x16, 0, 6, 3, 2, 0, 0x1a], 3, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 2;
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0, 0x202);
    put64(stack, 8, BASE + 0x1200);
    put64(stack, 16, 0x33);
    put64(stack, 32, STACK + 0x100);
    for (rip, already_popped) in [(0x10fd, 0), (0x10fe, 8)] {
        let mut current = context(rip);
        current.rsp += already_popped;
        current.registers[4] = current.rsp;
        let result = unwind(&mut memory, std::slice::from_ref(&module), current, 8);
        assert!(result.complete, "{rip:#x} {}", result.stop);
        assert_eq!(result.frames[0].method, "epilog");
        assert_eq!(result.frames[1].rip, BASE + 0x1200);
        assert_eq!(result.frames[1].rsp, STACK + 0x100);
    }
}

#[test]
fn version_two_epilogs_reject_descriptors_outside_the_function() {
    let (mut memory, module) = unwind_fixture(&[5, 6, 4, 6], 0, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 2;
    let result = unwind(&mut memory, &[module], context(0x10ff), 8);
    assert!(!result.complete);
    assert_eq!(result.stop, "invalid version 2 epilog range");
}

#[test]
fn unsupported_metadata_and_unmapped_stacks_return_partial_results() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 3;
    let result = unwind(
        &mut memory,
        std::slice::from_ref(&module),
        context(0x1020),
        8,
    );
    assert!(!result.complete);
    assert_eq!(result.frames.len(), 1);
    assert!(result.stop.contains("version 3"));
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 1;
    memory.regions.remove(&STACK);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(!result.complete);
    assert!(result.stop.contains("unmapped"));
}

#[test]
fn chained_unwind_metadata_is_applied_and_cycles_are_reported() {
    let (mut memory, module) = unwind_fixture(&[], 0, 0);
    let bytes = memory.regions.get_mut(&BASE).unwrap();
    bytes[0x3100] = 1 | (4 << 3);
    put32(bytes, 0x3104, 0x1800);
    put32(bytes, 0x3108, 0x1900);
    put32(bytes, 0x310c, 0x3200);
    bytes[0x3200..0x3206].copy_from_slice(&[1, 4, 1, 0, 4, 0x42]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(
        &mut memory,
        std::slice::from_ref(&module),
        context(0x1020),
        8,
    );
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 48);
    put32(memory.regions.get_mut(&BASE).unwrap(), 0x310c, 0x3100);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(!result.complete);
    assert!(result.stop.contains("cyclic"));
}

#[test]
fn dynamic_frame_pointers_restore_saved_registers_from_the_fixed_frame_base() {
    let (mut memory, module) = unwind_fixture(&[8, 0x34, 2, 0, 4, 3, 2, 0x32, 1, 0x50], 8, 0x15);
    let mut current = context(0x1020);
    current.registers[5] = STACK + 0x110;
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0x110, 0xabcdef);
    put64(stack, 0x120, 0);
    put64(stack, 0x128, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], current, 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 0x130);
}

#[test]
fn chained_saves_use_the_frame_pointer_established_in_the_parent() {
    let (mut memory, mut module) = unwind_fixture(&[4, 0xc4, 2, 0], 4, 0x15);
    let image = memory.regions.get_mut(&BASE).unwrap();
    image[0x3100] |= 4 << 3;
    put32(image, 0x3108, 0x1800);
    put32(image, 0x310c, 0x1900);
    put32(image, 0x3110, 0x3200);
    image[0x3200..0x320a].copy_from_slice(&[1, 4, 3, 0x15, 4, 3, 2, 0x32, 1, 0x50]);
    module.exception_size = 24;
    put32(image, 0x300c, 0x1200);
    put32(image, 0x3010, 0x1300);
    put32(image, 0x3014, 0x3300);
    image[0x3300..0x3306].copy_from_slice(&[1, 1, 1, 0xc, 1, 3]);
    let mut current = context(0x1020);
    current.registers[5] = STACK + 0x110;
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0x110, STACK + 0x200);
    put64(stack, 0x128, BASE + 0x1280);
    let result = unwind(&mut memory, &[module], current, 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames.len(), 2);
    assert_eq!(result.frames[1].rsp, STACK + 0x130);
}

#[test]
fn indirect_tail_epilogs_follow_the_windows_rex_w_and_bnd_rules() {
    for (encoding, method) in [
        (&[0xff, 0xe0][..], "pdata"),
        (&[0x41, 0xff, 0xe2], "pdata"),
        (&[0x49, 0xff, 0xe2], "epilog"),
        (&[0xf2, 0x48, 0xff, 0xe0], "epilog"),
        (&[0xf2, 0xff, 0x25, 0, 0, 0, 0], "epilog"),
    ] {
        let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
        memory.regions.get_mut(&BASE).unwrap()[0x1020..0x1020 + encoding.len()]
            .copy_from_slice(encoding);
        let result = unwind(&mut memory, &[module], context(0x1020), 8);
        assert!(result.complete, "{}", result.stop);
        assert_eq!(result.frames[0].method, method, "{encoding:02x?}");
    }
}

#[test]
fn tail_jump_epilogs_and_machine_frames_preserve_the_callers_stack() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x1020..0x1029]
        .copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0xe9, 0xd7, 0x01, 0, 0]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "epilog");
    let (mut memory, module) = unwind_fixture(&[0, 10], 0, 0);
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0, BASE + 0x1200);
    put64(stack, 8, 0x33);
    put64(stack, 24, STACK + 0x100);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 0x100);
}

#[test]
fn context_record_registers_follow_windows_unwind_register_numbers() {
    let mut bytes = vec![0; 208];
    put64(&mut bytes, 24, BASE + 0x1000);
    put64(&mut bytes, 32, STACK);
    put64(&mut bytes, 200, 3);
    for index in 0..15 {
        put64(&mut bytes, 72 + index * 8, index as u64 + 100);
    }
    let context = UnwindContext::from_record(&bytes).unwrap();
    assert_eq!(context.registers[4], STACK);
    assert_eq!(context.registers[5], 104);
    assert_eq!(context.registers[15], 114);
    put64(&mut bytes, 200, 0);
    assert!(UnwindContext::from_record(&bytes).is_err());
}

#[test]
fn large_metadata_reads_are_split_with_room_for_the_header_and_descriptor() {
    let mut memory = Memory::default();
    memory.regions.insert(BASE, vec![0x5a; 150_000]);
    let bytes = user::read_exact(&mut memory, BASE, 150_000).unwrap();
    assert_eq!(bytes, vec![0x5a; 150_000]);
    assert_eq!(memory.reads, 3);
    assert!(user::read_exact(&mut memory, u64::MAX - 10, 20).is_err());
    assert!(user::read_exact(&mut memory, BASE, 16 * 1024 * 1024 + 1).is_err());
}

#[test]
fn dynamic_unwind_uses_captured_runtime_entries_outside_loaded_modules() {
    let (mut memory, _) = unwind_fixture(&[4, 0x42], 4, 0);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, 0);
    let table = neo::unwind::DynamicTable {
        base: BASE,
        start: BASE + 0x1000,
        end: BASE + 0x1100,
        address: BASE + 0x3000,
        count: 1,
        kind: 0,
    };
    let result = neo::unwind::unwind_with_tables(
        &mut memory,
        &[],
        std::slice::from_ref(&table),
        context(0x1020),
        8,
        true,
    );
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "dynamic_pdata");
    let result = neo::unwind::unwind_with_tables(
        &mut memory,
        &[],
        &[neo::unwind::DynamicTable { kind: 2, ..table }],
        context(0x1020),
        8,
        true,
    );
    assert!(!result.complete);
    assert!(result.stop.contains("callback provider"));
}
