use super::*;
use std::collections::BTreeMap;

fn layout() -> VadLayout {
    VadLayout {
        root_offset: 0,
        node_offset: 0,
        left_offset: 0,
        right_offset: 8,
        start_offset: 16,
        end_offset: 20,
        start_high_offset: 24,
        end_high_offset: 25,
        flags_offset: 28,
        commit: VadCommit::Charge {
            offset: 32,
            high_offset: 26,
        },
        protection_mask: 0x1f,
        private_mask: 1 << 8,
        bytes: 40,
    }
}

fn row(start: u32, end: u32, flags: u32, charge: u32) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    for (offset, value) in [(16, start), (20, end), (28, flags), (32, charge)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn vad_commit_and_protection_do_not_confuse_residency_with_commitment() {
    let layout = layout();
    let full = layout.region(&row(1, 2, 0x100 | 4, 2)).unwrap();
    assert_eq!((full.start, full.end, full.protection), (0x1000, 0x3000, 4));
    assert!(full.private);
    assert_eq!(full.committed, Some(true));
    assert_eq!(layout.region(&row(1, 2, 0x104, 1)).unwrap().committed, None);
    assert_eq!(
        layout.region(&row(1, 2, 0x104, 0)).unwrap().committed,
        Some(false)
    );
    assert_eq!(layout.region(&row(1, 2, 4, 2)).unwrap().committed, None);
    assert!(layout.region(&row(3, 2, 4, 0)).is_err());
    assert!(layout.region(&[0; 20]).is_err());
}

#[test]
fn full_vad_walk_sorts_regions_and_detects_cycles_and_overlaps() {
    let layout = layout();
    let root_address = 0xffff800000001000u64;
    let node = root_address + 0x1000;
    let left = node + 0x1000;
    let mut rows = BTreeMap::new();
    rows.insert(root_address, node.to_le_bytes().to_vec());
    let mut root = row(5, 6, 0x104, 2);
    root[..8].copy_from_slice(&left.to_le_bytes());
    rows.insert(node, root);
    rows.insert(left, row(1, 2, 0x104, 2));
    let reader = |address, length| {
        rows.get(&address)
            .filter(|bytes| bytes.len() == length)
            .cloned()
            .ok_or_else(|| "invalid fixture read".to_string())
    };
    let regions = layout.regions(root_address, &mut { reader }).unwrap();
    assert_eq!(
        regions
            .iter()
            .map(|region| region.start)
            .collect::<Vec<_>>(),
        [0x1000, 0x5000]
    );
    rows.get_mut(&left).unwrap()[..8].copy_from_slice(&node.to_le_bytes());
    let error = layout
        .regions(root_address, &mut |address, _| {
            rows.get(&address).cloned().ok_or("missing node".into())
        })
        .unwrap_err();
    assert!(error.contains("VAD tree"));
    rows.insert(left, row(4, 5, 0x104, 2));
    assert!(
        layout
            .regions(root_address, &mut |address, _| rows
                .get(&address)
                .cloned()
                .ok_or("missing node".into()))
            .is_err()
    );
}

const KERNEL_ROOT: u64 = 0x1000;
const LIST_HEAD: u64 = 0xffff_8000_0000_0400;
const FIRST_PROCESS: u64 = 0xffff_8000_0000_1000;
const PROCESS_PEB: u64 = 0x20000;

struct ResolutionFixture {
    symbols: KernelSymbols,
    rows: BTreeMap<(u64, u64), Vec<u8>>,
    roots: Vec<u64>,
}

impl ResolutionFixture {
    fn new(processes: &[(u64, &str)]) -> Self {
        let symbols = KernelSymbols {
            vad: layout(),
            image: ImageIdentity {
                identity: Identity {
                    guid: String::new(),
                    age: 0,
                    name: String::new(),
                },
                record_rva: 0,
                record_bytes: 0,
                timestamp: 0,
                image_bytes: 0,
            },
            initial_process: 0,
            active_process_head: None,
            syscall_rvas: Vec::new(),
            process_bytes: 88,
            pid_offset: 0,
            creation_offset: 8,
            exit_offset: 16,
            thread_id_offset: None,
            links_offset: 24,
            name_offset: 40,
            name_bytes: 15,
            directory_offset: 56,
            user_directory_offset: Some(64),
            peb_offset: 72,
            wow64_offset: Some(80),
            soft_layout: SoftPteLayout::default(),
        };
        let mut rows = BTreeMap::new();
        let process_link =
            |index: usize| FIRST_PROCESS + index as u64 * 0x1000 + symbols.links_offset as u64;
        let head = if processes.is_empty() {
            [LIST_HEAD; 2]
        } else {
            [process_link(0), process_link(processes.len() - 1)]
        };
        rows.insert(
            (KERNEL_ROOT, LIST_HEAD),
            head.into_iter().flat_map(u64::to_le_bytes).collect(),
        );
        let mut roots = vec![KERNEL_ROOT];
        for (index, (pid, name)) in processes.iter().enumerate() {
            let object = FIRST_PROCESS + index as u64 * 0x1000;
            let next = if index + 1 == processes.len() {
                LIST_HEAD
            } else {
                process_link(index + 1)
            };
            let previous = if index == 0 {
                LIST_HEAD
            } else {
                process_link(index - 1)
            };
            let root = (index as u64 + 2) * 0x1000;
            roots.push(root);
            let mut row = vec![0; symbols.process_bytes];
            for (offset, value) in [
                (0, *pid),
                (8, *pid + 100),
                (24, next),
                (32, previous),
                (56, root),
                (64, root),
                (72, PROCESS_PEB),
            ] {
                row[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            let length = name.len().min(symbols.name_bytes - 1);
            row[40..40 + length].copy_from_slice(&name.as_bytes()[..length]);
            rows.insert((KERNEL_ROOT, object), row);

            // Processes deliberately share PEB/image virtual addresses in separate roots.
            let image = 0x100000u64;
            let parameters = 0x30000u64;
            let path_buffer = 0x40000u64;
            let mut peb = vec![0; 0x28];
            peb[0x10..0x18].copy_from_slice(&image.to_le_bytes());
            peb[0x20..0x28].copy_from_slice(&parameters.to_le_bytes());
            rows.insert((root, PROCESS_PEB), peb);
            let mut dos = vec![0; 64];
            dos[..2].copy_from_slice(b"MZ");
            dos[60..64].copy_from_slice(&0x80u32.to_le_bytes());
            rows.insert((root, image), dos);
            let mut pe = vec![0; 84];
            pe[..4].copy_from_slice(b"PE\0\0");
            pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
            pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
            pe[80..84].copy_from_slice(&0x20000u32.to_le_bytes());
            rows.insert((root, image + 0x80), pe);
            let path: Vec<u8> = format!("C:\\Apps\\{name}")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut descriptor = vec![0; 16];
            descriptor[..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
            descriptor[2..4].copy_from_slice(&(path.len() as u16).to_le_bytes());
            descriptor[8..16].copy_from_slice(&path_buffer.to_le_bytes());
            rows.insert((root, parameters + 0x60), descriptor);
            rows.insert((root, path_buffer), path);
        }
        Self {
            symbols,
            rows,
            roots,
        }
    }

    fn resolve(&self, selector: &str) -> Result<Process, String> {
        self.resolve_with_root(selector, 0)
    }

    fn resolve_with_root(&self, selector: &str, target_cr3: u64) -> Result<Process, String> {
        self.symbols.resolve_list_with(
            selector,
            target_cr3,
            KERNEL_ROOT,
            LIST_HEAD,
            &self.roots,
            &mut |root, address, length| {
                let ((stored_root, base), bytes) = self
                    .rows
                    .range(..=(root, address))
                    .next_back()
                    .ok_or("missing fixture memory")?;
                if *stored_root != root {
                    return Err("unmapped fixture root".into());
                }
                bytes_at(bytes, (address - base) as usize, length).map(Vec::from)
            },
        )
    }
}

#[test]
fn resolves_full_names_after_the_kernel_image_name_is_truncated() {
    for name in [
        "FortniteClient-Win64-Shipping.exe",
        "EasyAntiCheat_EOS.exe",
        "abcdefghij.exe",  // Exactly 14 bytes.
        "abcdefghijk.exe", // Exactly 15 bytes.
    ] {
        let fixture = ResolutionFixture::new(&[(42, name)]);
        let process = fixture.resolve(&name.to_uppercase()).unwrap();
        assert_eq!(process.pid, 42);
        assert!(process.name.eq_ignore_ascii_case(name));
        if name.len() > 14 {
            assert!(!process.name_truncated);
            assert_eq!(process.validated_user_cr3, Some(0x2000));
        }
    }
}

#[test]
fn full_names_disambiguate_processes_sharing_the_same_kernel_prefix() {
    let fixture = ResolutionFixture::new(&[
        (41, "ExampleClient-Win64-Editor.exe"),
        (42, "ExampleClient-Win64-Shipping.exe"),
    ]);
    let process = fixture.resolve("ExampleClient-Win64-Shipping.exe").unwrap();
    assert_eq!(process.pid, 42);
    assert_eq!(process.user_root(), 0x3000);
    assert_eq!(
        fixture
            .resolve_with_root("ExampleClient-Win64-Shipping.exe", 0x3007)
            .unwrap()
            .pid,
        42
    );
    assert!(
        fixture
            .resolve_with_root("ExampleClient-Win64-Shipping.exe", 0x2000)
            .err()
            .unwrap()
            .contains("CR3 does not belong")
    );
    assert!(
        fixture
            .resolve("ExampleClient-Win64-Missing.exe")
            .err()
            .unwrap()
            .contains("was not found")
    );
    assert!(
        fixture
            .resolve("ExampleClient-")
            .err()
            .unwrap()
            .contains("multiple processes")
    );
}

#[test]
fn duplicate_full_names_still_require_a_pid() {
    let name = "ExampleClient-Win64-Shipping.exe";
    let fixture = ResolutionFixture::new(&[(41, name), (42, name)]);
    assert!(
        fixture
            .resolve(name)
            .err()
            .unwrap()
            .contains("multiple processes")
    );
    assert_eq!(fixture.resolve_with_root(name, 0x3007).unwrap().pid, 42);
}

#[test]
fn explicit_root_selects_its_owner_when_a_homonym_shares_the_same_peb_address() {
    let name = "ExampleClient-Win64-Shipping.exe";
    let mut fixture = ResolutionFixture::new(&[(41, name), (42, name)]);
    fixture.rows.remove(&(0x2000, PROCESS_PEB));
    let process = fixture.resolve_with_root(name, 0x3007).unwrap();
    assert_eq!(process.pid, 42);
    assert_eq!(process.user_root(), 0x3000);
}

#[test]
fn explicit_root_checks_both_directories_without_a_native_peb() {
    let mut fixture = ResolutionFixture::new(&[(41, "example.exe"), (42, "example.exe")]);
    fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap()[64..72]
        .copy_from_slice(&0x4000u64.to_le_bytes());
    for (peb, wow64) in [(PROCESS_PEB, 1u64), (0, 0)] {
        let row = fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap();
        row[72..80].copy_from_slice(&peb.to_le_bytes());
        row[80..88].copy_from_slice(&wow64.to_le_bytes());
        let error = fixture.resolve_with_root("41", 0x3007).err().unwrap();
        assert!(
            error.starts_with("CR3 does not belong to pid=41"),
            "{error}"
        );
        for root in [0x2007, 0x4007] {
            assert_eq!(fixture.resolve_with_root("41", root).unwrap().pid, 41);
        }
    }
    for root in [7, 0x4000_0000_0000_2007] {
        let error = fixture.resolve_with_root("41", root).err().unwrap();
        assert_eq!(error, format!("invalid process CR3 {root:#x}"));
    }
}

#[test]
fn terminated_objects_and_the_list_head_are_excluded_from_process_selection() {
    let mut fixture = ResolutionFixture::new(&[(41, "similar.exe"), (42, "similar.exe")]);
    fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap()[16..24]
        .copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(fixture.resolve("similar.exe").unwrap().pid, 42);
    for selector in ["0", "41", "missing.exe"] {
        assert!(
            fixture
                .resolve(selector)
                .err()
                .unwrap()
                .contains("was not found")
        );
    }
}

#[test]
fn pdb_extensions_are_case_insensitive() {
    let mut rsds = b"RSDS".to_vec();
    rsds.extend([0; 20]);
    rsds.extend(b"C:\\Symbols\\Example.PDB\0");
    assert_eq!(Identity::parse(&rsds).unwrap().name, "Example.PDB");
}

#[test]
fn long_names_require_a_readable_and_valid_full_image_name() {
    let name = "ExampleClient-Win64-Shipping.exe";
    let mut fixture = ResolutionFixture::new(&[(42, name)]);
    fixture.rows.remove(&(0x2000, PROCESS_PEB));
    assert!(
        fixture
            .resolve(name)
            .err()
            .unwrap()
            .contains("was not found")
    );
    // PID and exact short-name selection must not require user-mode memory.
    for selector in ["42", "0x2a", "EXAMPLECLIENT-"] {
        assert_eq!(fixture.resolve(selector).unwrap().pid, 42);
    }
    assert!(fixture.resolve("ExampleClient").is_err());
    let mut fixture = ResolutionFixture::new(&[(42, name)]);
    fixture.rows.get_mut(&(0x2000, 0x30060)).unwrap()[0] |= 1;
    assert!(fixture.resolve(name).is_err());
}

#[test]
fn long_names_can_use_an_observed_root_when_reported_roots_are_unusable() {
    let name = "ExampleClient-Win64-Shipping.exe";
    let mut fixture = ResolutionFixture::new(&[(42, name)]);
    let row = fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap();
    for offset in [56, 64] {
        row[offset..offset + 8].copy_from_slice(&0x4000_0000_1234_5000u64.to_le_bytes());
    }
    let process = fixture.resolve(name).unwrap();
    assert_eq!(process.pid, 42);
    assert_eq!(process.user_root(), 0x2000);
    assert_eq!(process.kernel_access_root(), KERNEL_ROOT);
}

#[test]
fn a_full_kernel_name_buffer_does_not_require_a_null_terminator() {
    let name = "ExampleClient-Win64-Shipping.exe";
    let mut fixture = ResolutionFixture::new(&[(42, name)]);
    let row = fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap();
    row[40..55].copy_from_slice(&name.as_bytes()[..15]);
    assert_eq!(fixture.resolve(name).unwrap().pid, 42);
}

#[test]
fn cached_roots_resolve_idle_processes_after_history_eviction_and_reject_pid_reuse() {
    let pid = 0x1000_0000_0000 + u64::from(std::process::id());
    let name = "ExampleClient-Win64-Shipping.exe";
    let mut fixture = ResolutionFixture::new(&[(pid, name)]);
    let process = fixture.resolve(name).unwrap();
    crate::memory::cache_process_root(&process);
    assert_eq!(
        crate::memory::cached_process_root(process.root_identity()),
        Some(0x2000)
    );
    fixture.roots = vec![KERNEL_ROOT];
    let row = fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap();
    for offset in [56, 64] {
        row[offset..offset + 8].copy_from_slice(&0x4000_0000_1234_5000u64.to_le_bytes());
    }
    let idle = fixture.resolve(name).unwrap();
    assert_eq!(idle.pid, pid);
    assert_eq!(idle.user_root(), 0x2000);
    let row = fixture.rows.get_mut(&(KERNEL_ROOT, FIRST_PROCESS)).unwrap();
    row[8..16].copy_from_slice(&(process.creation_time + 1).to_le_bytes());
    assert!(fixture.resolve(name).is_err());
    let path = std::env::temp_dir()
        .join("neo-process-roots-v1")
        .join(format!("{pid}.bin"));
    std::fs::remove_file(path).unwrap();
}
