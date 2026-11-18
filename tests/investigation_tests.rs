use crate::investigation::{Snapshot, compare_events, decode};
use neo::protocol::memory::*;
use neo::user::MemoryReader;

#[test]
fn argument_address_expressions_preserve_registers_and_signed_offsets() {
    for (expression, expected) in [
        ("rdx", (2, 0)),
        ("rdx+0x08", (2, 8)),
        ("[RDX+0x08]", (2, 8)),
        ("rbx-8", (3, -8)),
        ("r8+32767", (8, 32767)),
        ("rsp-32768", (4, -32768)),
    ] {
        assert_eq!(
            super::argument_location(expression, false).unwrap(),
            expected
        );
    }
    assert_eq!(super::argument_location("0x28+8", true).unwrap(), (0x28, 8));
    for expression in [
        "rdx+32768",
        "rdx-32769",
        "[rdx+8",
        "rdx+8]",
        "rdx+",
        "rdx+8+8",
        "r16",
        "-rdx",
    ] {
        assert!(
            super::argument_location(expression, false).is_err(),
            "{expression}"
        );
    }
}

#[test]
fn event_decoder_preserves_signed_displacement_separately_from_pointer_depth() {
    let mut record = vec![0; EVENT_RECORD_BYTES];
    put64(&mut record, CONTEXT_RECORD_BYTES + 56, EVENT_FORMAT_VERSION);
    let argument =
        EVENT_RECORD_HEADER + 2 * EVENT_SEGMENT_HEADER + EVENT_CODE_BYTES + EVENT_STACK_BYTES;
    put64(&mut record, argument + 16, 2);
    put64(
        &mut record,
        argument + 48,
        2 | (u64::from((-8i16) as u16) << 48),
    );
    put64(&mut record, argument + 56, ARGUMENT_REGISTER);
    let decoded = decode(&record).unwrap();
    assert_eq!(decoded["segments"][2]["argument"]["pointer_depth"], 2);
    assert_eq!(decoded["segments"][2]["argument"]["pointer_offset"], -8);
}

#[test]
fn module_catalog_retains_binary_identity_and_unwind_directory_from_loaded_pe_headers() {
    let mut bytes = vec![0; 0x5000];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 60, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    put32(&mut bytes, 0x80 + 80, 0x5000);
    put32(&mut bytes, 0x80 + 8, 12345);
    put32(&mut bytes, 0x80 + 132, 16);
    put32(&mut bytes, 0x80 + 184, 0x1000);
    put32(&mut bytes, 0x80 + 188, 28);
    let mut rsds = b"RSDS".to_vec();
    rsds.extend_from_slice(&[0x12; 16]);
    rsds.extend_from_slice(&1u32.to_le_bytes());
    rsds.extend_from_slice(b"fixture.pdb\0");
    put32(&mut bytes, 0x1000 + 12, 2);
    put32(&mut bytes, 0x1000 + 16, rsds.len() as u32);
    put32(&mut bytes, 0x1000 + 20, 0x1800);
    bytes[0x1800..0x1800 + rsds.len()].copy_from_slice(&rsds);
    let module = neo::user::Module {
        base: 0x100000,
        size: 0x5000,
        entry_point: 0x101000,
        name: "fixture.exe".into(),
        path: "fixture.exe".into(),
        sections: vec![],
        exports: vec![],
        export_error: None,
        exception_rva: 0x3000,
        exception_size: 12,
    };
    let mut reader = |address: u64, length: usize| -> Result<Vec<u8>, String> {
        let offset = usize::try_from(address.checked_sub(module.base).ok_or("invalid address")?)
            .map_err(|_| "invalid address")?;
        Ok(bytes
            .get(offset..offset + length)
            .ok_or("unmapped")?
            .to_vec())
    };
    let identity = super::module_identity(&mut reader, &module).unwrap();
    assert_eq!(identity["debug_identity"]["pdb"], "fixture.pdb");
    assert_eq!(identity["debug_identity"]["age"], 1);
    assert_eq!(identity["timestamp"], 12345);
    assert_eq!(identity["unwind"]["rva"], 0x3000);
    assert_eq!(identity["unwind"]["bytes"], 12);
    assert_eq!(identity["headers_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        identity["memory_consistency"],
        "collection_start_observational"
    );
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn disassembly_joins_instruction_bytes_across_snapshot_pages() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let mut captured = event(1);
    let rip = 0x40_1fff;
    captured["context"]["rip"] = json!(crate::output::hex(rip));
    let page = |index: usize, byte: u8| {
        let address = crate::output::hex(rip + index as u64);
        json!({ "address": address, "physical": address, "pte_fingerprint": "0x0",
            "requested": 1, "copied": 1, "status": 0, "permissions": 5,
            "offset": index, "page_size": 4096,
            "sha256": crate::analysis_cli::hex_bytes(&Sha256::digest([byte])) })
    };
    captured["segments"][0] = json!({
        "address": crate::output::hex(rip), "requested": 2, "copied": 2, "status": 0,
        "bytes": "6690", "pages": [page(0, 0x66), page(1, 0x90)],
    });
    let analysis = super::Analysis {
        disasm: true,
        ..Default::default()
    };
    analysis.apply(&mut captured).unwrap();
    assert_eq!(captured["instructions"].as_array().unwrap().len(), 1);
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn event(sequence: u64) -> serde_json::Value {
    let mut record = vec![0; EVENT_RECORD_BYTES];
    put64(&mut record, 0, sequence);
    put64(&mut record, 8, sequence * 100);
    put64(&mut record, 16, 0x3000);
    put64(&mut record, 24, 0x401000);
    put64(&mut record, 200, 3);
    put64(&mut record, CONTEXT_RECORD_BYTES, EVENT_INSTRUCTION);
    put64(&mut record, CONTEXT_RECORD_BYTES + 56, EVENT_FORMAT_VERSION);
    put64(&mut record, CONTEXT_RECORD_BYTES + 104, 42);
    put64(&mut record, CONTEXT_RECORD_BYTES + 112, 123456);
    let offset =
        EVENT_RECORD_HEADER + 2 * EVENT_SEGMENT_HEADER + EVENT_CODE_BYTES + EVENT_STACK_BYTES;
    put64(&mut record, offset, 0x600ff8);
    record[offset + 8..offset + 10].copy_from_slice(&16u16.to_le_bytes());
    record[offset + 10..offset + 12].copy_from_slice(&16u16.to_le_bytes());
    for index in 0..2 {
        let page = offset + 64 + index * EVENT_PAGE_BYTES;
        put64(&mut record, page, 0x600ff8 + index as u64 * 8);
        put64(&mut record, page + 8, 0x800ff8 + index as u64 * 8);
        put64(&mut record, page + 16, 123 + index as u64);
        put32(&mut record, page + 24, 8);
        put32(&mut record, page + 28, 8);
        put32(&mut record, page + 36, 15);
        put32(&mut record, page + 40, index as u32 * 8);
        put32(&mut record, page + 44, 4096);
    }
    record[offset + EVENT_SEGMENT_HEADER..offset + EVENT_SEGMENT_HEADER + 16]
        .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    decode(&record).unwrap()
}

#[test]
fn event_snapshots_preserve_hashes_identity_and_sparse_page_boundaries() {
    let mut event = event(1);
    assert_eq!(event["target_identity"]["validated"], true);
    assert_eq!(event["snapshot_phase"], "hit");
    assert_eq!(event["process_atomic"], false);
    assert!(
        event["consistency_note"]
            .as_str()
            .unwrap()
            .contains("not an atomic snapshot")
    );
    let mut snapshot = Snapshot::parse(&event).unwrap();
    assert_eq!(
        snapshot.read(0x600ffc, 8).unwrap(),
        [5, 6, 7, 8, 9, 10, 11, 12]
    );
    event["segments"][2]["pages"][0]["sha256"] = serde_json::json!("invalid");
    assert!(
        Snapshot::parse(&event)
            .err()
            .unwrap()
            .contains("hash mismatch")
    );
}

#[test]
fn comparison_detects_mutations_remapping_and_process_identity_reuse() {
    let before = event(1);
    let mut after = event(2);
    assert_eq!(compare_events(&before, &after).unwrap()["changed_pages"], 0);
    after["segments"][2]["pages"][0]["physical"] = serde_json::json!("0x900ff8");
    let diff = compare_events(&before, &after).unwrap();
    assert_eq!(diff["changed_pages"], 1);
    assert_eq!(diff["pages"][0]["state"], "remapped");
    after["target_identity"]["creation_time"] = serde_json::json!("0x1234");
    assert!(
        compare_events(&before, &after)
            .unwrap_err()
            .contains("execution identities")
    );
}

#[test]
fn snapshot_comparison_distinguishes_content_permissions_coverage_and_unreadable_pages() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let before = event(1);
    let mut changed = event(2);
    changed["segments"][2]["bytes"] = json!("a502030405060708090a0b0c0d0e0f10");
    changed["segments"][2]["pages"][0]["sha256"] =
        json!(crate::analysis_cli::hex_bytes(&Sha256::digest([
            0xa5, 2, 3, 4, 5, 6, 7, 8
        ])));
    assert_eq!(
        compare_events(&before, &changed).unwrap()["pages"][0]["state"],
        "changed"
    );

    let mut unreadable = event(2);
    unreadable["segments"][2]["copied"] = json!(8);
    unreadable["segments"][2]["pages"][0]["copied"] = json!(0);
    unreadable["segments"][2]["pages"][0]["status"] = json!(Error::Permission as u32);
    unreadable["segments"][2]["pages"][0]["sha256"] =
        json!(crate::analysis_cli::hex_bytes(&Sha256::digest([])));
    assert_eq!(
        compare_events(&before, &unreadable).unwrap()["pages"][0]["state"],
        "unreadable"
    );

    let mut permissions = event(2);
    permissions["segments"][2]["pages"][0]["permissions"] = json!(5);
    assert_eq!(
        compare_events(&before, &permissions).unwrap()["pages"][0]["state"],
        "permissions_changed"
    );

    let mut partial = event(2);
    partial["segments"][2]["copied"] = json!(12);
    partial["segments"][2]["pages"][0]["copied"] = json!(4);
    partial["segments"][2]["pages"][0]["sha256"] =
        json!(crate::analysis_cli::hex_bytes(&Sha256::digest([
            1, 2, 3, 4
        ])));
    assert_eq!(
        compare_events(&before, &partial).unwrap()["pages"][0]["state"],
        "coverage_changed"
    );

    let mut remapped = event(2);
    remapped["segments"][2]["pages"][0]["pte_fingerprint"] = json!("0x456");
    assert_eq!(
        compare_events(&before, &remapped).unwrap()["pages"][0]["state"],
        "remapped"
    );

    let mut shortened = event(2);
    let segment = &mut shortened["segments"][2];
    segment["address"] = json!("0x601000");
    segment["requested"] = json!(8);
    segment["copied"] = json!(8);
    segment["bytes"] = json!("090a0b0c0d0e0f10");
    let mut page = segment["pages"][1].clone();
    page["offset"] = json!(0);
    segment["pages"] = json!([page]);
    assert_eq!(
        compare_events(&before, &shortened).unwrap()["pages"][0]["state"],
        "removed"
    );
    assert_eq!(
        compare_events(&shortened, &before).unwrap()["pages"][0]["state"],
        "added"
    );
}

#[test]
fn missing_first_page_does_not_hide_a_later_readable_page() {
    let mut value = event(1);
    let segment = &mut value["segments"][2];
    segment["copied"] = serde_json::json!(8);
    segment["pages"][0]["copied"] = serde_json::json!(0);
    segment["pages"][0]["status"] = serde_json::json!(Error::Unmapped as u32);
    use sha2::{Digest, Sha256};
    segment["pages"][0]["sha256"] =
        serde_json::json!(crate::analysis_cli::hex_bytes(&Sha256::digest([])));
    let mut snapshot = Snapshot::parse(&value).unwrap();
    assert!(snapshot.read(0x600ff8, 1).is_err());
    assert_eq!(
        snapshot.read(0x601000, 8).unwrap(),
        [9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(
        compare_events(&event(2), &value).unwrap()["pages"][0]["state"],
        "missing"
    );
}

#[test]
fn binary_export_retains_structured_metadata_and_exact_page_bytes() {
    use std::io::Write;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("builds/investigation-export-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("capture.jsonl");
    let destination = directory.join("export");
    let mut input = std::fs::File::create(&path).unwrap();
    let header = serde_json::json!({"type": "session", "format": "neo-investigation-v1", "catalog": {
        "modules": [], "binary_identities": [{"name": "fixture.exe", "headers_sha256": "fixture"}]
    }});
    writeln!(input, "{header}").unwrap();
    writeln!(input, "{}", event(1)).unwrap();
    writeln!(
        input,
        "{}",
        serde_json::json!({"type": "end", "complete": true})
    )
    .unwrap();
    drop(input);
    crate::investigation::export(vec![
        path.to_str().unwrap().into(),
        "--output".into(),
        destination.to_str().unwrap().into(),
    ])
    .unwrap();
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(destination.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["session"], header);
    assert_eq!(metadata["format"], "matrixhv-event-export-v2");
    assert!(metadata["events"][0]["segments"][2].get("bytes").is_none());
    let pages = metadata["events"][0]["segments"][2]["pages"]
        .as_array()
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join(pages[0]["buffer"].as_str().unwrap())).unwrap(),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(
        std::fs::read(destination.join(pages[1]["buffer"].as_str().unwrap())).unwrap(),
        [9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert!(
        crate::investigation::export(vec![
            path.to_str().unwrap().into(),
            "--output".into(),
            destination.to_str().unwrap().into()
        ])
        .is_err()
    );
}
