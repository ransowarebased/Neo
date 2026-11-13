use super::*;
use std::collections::BTreeMap;

const ROOT: u64 = 0x3450_0000;
const PROTECTED_ROOT: u64 = 0x4000_0005_655f_9000;
const PEB: u64 = 0x20000;
const IMAGE: u64 = 0x100000;
const PARAMETERS: u64 = 0x30000;
const PATH: u64 = 0x40000;

fn fixture() -> BTreeMap<(u64, u64), Vec<u8>> {
    let mut rows = BTreeMap::new();
    let mut peb = vec![0; 0x28];
    peb[0x10..0x18].copy_from_slice(&IMAGE.to_le_bytes());
    peb[0x20..0x28].copy_from_slice(&PARAMETERS.to_le_bytes());
    rows.insert((ROOT, PEB), peb);
    let mut dos = vec![0; 64];
    dos[..2].copy_from_slice(b"MZ");
    dos[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    rows.insert((ROOT, IMAGE), dos);
    let mut pe = vec![0; 84];
    pe[..4].copy_from_slice(b"PE\0\0");
    pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[80..84].copy_from_slice(&0x20000u32.to_le_bytes());
    rows.insert((ROOT, IMAGE + 0x80), pe);
    let path: Vec<u8> = "C:\\Games\\ExampleClient-Win64-Shipping.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut descriptor = vec![0; 16];
    descriptor[..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(path.len() as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&PATH.to_le_bytes());
    rows.insert((ROOT, PARAMETERS + 0x60), descriptor);
    rows.insert((ROOT, PATH), path);
    rows
}

fn read_fixture(
    rows: &BTreeMap<(u64, u64), Vec<u8>>,
    root: u64,
    address: u64,
    length: usize,
) -> Option<Vec<u8>> {
    rows.get(&(root, address))
        .filter(|bytes| bytes.len() == length)
        .cloned()
}

#[test]
fn validates_observed_root_instead_of_returning_a_protected_directory_field() {
    let rows = fixture();
    let roots = [PROTECTED_ROOT, ROOT | 7, ROOT | 9];
    let result = matched_root_with(
        &roots,
        PEB,
        "ExampleClient",
        true,
        &mut |root, address, len| read_fixture(&rows, root, address, len),
    );
    assert_eq!(result, Some(ROOT));
}

#[test]
fn rejects_a_different_image_and_malformed_pe_or_path_data() {
    let mut rows = fixture();
    let probe = |rows: &BTreeMap<(u64, u64), Vec<u8>>, name: &str| {
        matches_process_image(ROOT, PEB, name, true, &mut |root, address, len| {
            read_fixture(rows, root, address, len)
        })
    };
    assert!(!probe(&rows, "OtherClient"));
    rows.get_mut(&(ROOT, IMAGE + 0x80)).unwrap()[4] = 0;
    assert!(!probe(&rows, "ExampleClient"));
    rows = fixture();
    rows.get_mut(&(ROOT, PARAMETERS + 0x60)).unwrap()[0] |= 1;
    assert!(!probe(&rows, "ExampleClient"));
}

#[test]
fn retries_a_candidate_after_a_transient_read_failure() {
    let rows = fixture();
    let mut fail = true;
    let mut reader = |root, address, len| {
        if fail {
            fail = false;
            return None;
        }
        read_fixture(&rows, root, address, len)
    };
    assert!(matched_root_with(&[ROOT], PEB, "ExampleClient", true, &mut reader).is_none());
    assert_eq!(
        matched_root_with(&[ROOT], PEB, "ExampleClient", true, &mut reader),
        Some(ROOT)
    );
}

#[test]
fn only_truncated_process_names_accept_an_image_name_prefix() {
    let rows = fixture();
    let mut reader = |root, address, len| read_fixture(&rows, root, address, len);
    assert!(!matches_process_image(
        ROOT,
        PEB,
        "ExampleClient",
        false,
        &mut reader
    ));
    assert!(matches_process_image(
        ROOT,
        PEB,
        "ExampleClient",
        true,
        &mut reader
    ));
    assert!(matches_process_image(
        ROOT,
        PEB,
        "exampleclient-win64-shipping.EXE",
        false,
        &mut reader,
    ));
}

#[test]
fn busy_info_transport_is_retried_but_other_errors_are_returned() {
    let mut attempts = 0;
    let info = query_info_with(
        &mut |packet| {
            attempts += 1;
            if attempts < 3 {
                packet[40..44]
                    .copy_from_slice(&(crate::protocol::memory::Error::Busy as u32).to_le_bytes());
                Err("busy".into())
            } else {
                Ok(())
            }
        },
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(attempts, 3);
    assert_eq!(crate::protocol::memory::word(&info, 40), 0);

    let mut attempts = 0;
    let error = query_info_with(
        &mut |_| {
            attempts += 1;
            Err("unavailable".into())
        },
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(error, "unavailable");
    assert_eq!(attempts, 1);
}
