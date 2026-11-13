pub use matrixhv_sdk::memory::*;

use crate::protocol::memory::{HEADER_BYTES, ITEM_BYTES, READ, WRITE};
use crate::symbols::{KernelSymbols, Process};
use std::time::{Duration, Instant};

fn query_info_with(
    submit: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    use crate::protocol::memory::{Error, word};
    let started = Instant::now();
    loop {
        let mut info = info_packet()?;
        match submit(&mut info) {
            Ok(()) => return Ok(info),
            Err(error) => {
                let remaining = timeout.saturating_sub(started.elapsed());
                if word(&info, 40) != Error::Busy as u32 || remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }
    }
}

fn query_info() -> Result<Vec<u8>, String> {
    query_info_with(&mut invoke, Duration::from_secs(1))
}

fn matches_process_image(
    root: u64,
    peb: u64,
    process_name: &str,
    name_truncated: bool,
    read: &mut impl FnMut(u64, u64, usize) -> Option<Vec<u8>>,
) -> bool {
    fn user_range(address: u64, length: usize) -> bool {
        address >= 0x10000
            && address
                .checked_add(length as u64)
                .is_some_and(|end| end <= 0x0000_8000_0000_0000)
    }
    fn check(
        root: u64,
        peb: u64,
        process_name: &str,
        name_truncated: bool,
        read: &mut impl FnMut(u64, u64, usize) -> Option<Vec<u8>>,
    ) -> Option<()> {
        if !user_range(peb, 0x28) || process_name.is_empty() {
            return None;
        }
        let peb_bytes = read(root, peb, 0x28)?;
        let image = crate::user::u64_at(&peb_bytes, 0x10).ok()?;
        let parameters = crate::user::u64_at(&peb_bytes, 0x20).ok()?;
        if !user_range(image, 64) || !user_range(parameters, 0x70) {
            return None;
        }
        let dos = read(root, image, 64)?;
        let offset = crate::user::u32_at(&dos, 60).ok()? as u64;
        if dos.get(..2)? != b"MZ" || !(64..=1024 * 1024).contains(&offset) {
            return None;
        }
        let pe = image.checked_add(offset)?;
        if !user_range(pe, 84) {
            return None;
        }
        let headers = read(root, pe, 84)?;
        let size = crate::user::u32_at(&headers, 80).ok()? as usize;
        if headers.get(..4)? != b"PE\0\0"
            || crate::user::u16_at(&headers, 4).ok()? != 0x8664
            || crate::user::u16_at(&headers, 24).ok()? != 0x20b
            || size < 4096
            || !user_range(image, size)
        {
            return None;
        }
        let descriptor = read(root, parameters.checked_add(0x60)?, 16)?;
        let length = crate::user::u16_at(&descriptor, 0).ok()? as usize;
        let capacity = crate::user::u16_at(&descriptor, 2).ok()? as usize;
        let buffer = crate::user::u64_at(&descriptor, 8).ok()?;
        if length == 0
            || length > 32766
            || length > capacity
            || !length.is_multiple_of(2)
            || !user_range(buffer, length)
        {
            return None;
        }
        let encoded = read(root, buffer, length)?;
        let units: Vec<u16> = encoded
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        let path = String::from_utf16(&units).ok()?;
        let name = path.rsplit(['\\', '/']).next()?;
        let matches = if name_truncated {
            name.get(..process_name.len())?
                .eq_ignore_ascii_case(process_name)
        } else {
            name.eq_ignore_ascii_case(process_name)
        };
        if !matches {
            return None;
        }
        Some(())
    }
    check(root, peb, process_name, name_truncated, read).is_some()
}

fn matched_root_with(
    candidates: &[u64],
    peb: u64,
    process_name: &str,
    name_truncated: bool,
    read: &mut impl FnMut(u64, u64, usize) -> Option<Vec<u8>>,
) -> Option<u64> {
    for (index, candidate) in candidates.iter().enumerate() {
        let root = candidate & !4095;
        if root == 0
            || candidates[..index]
                .iter()
                .any(|previous| previous & !4095 == root)
        {
            continue;
        }
        if matches_process_image(root, peb, process_name, name_truncated, read) {
            return Some(root);
        }
    }
    None
}

fn matched_root(candidates: &[u64], process: &Process) -> Option<u64> {
    matched_root_with(
        candidates,
        process.peb,
        &process.name,
        process.name_truncated,
        &mut |cr3, address, length| {
            read_ranges(cr3, &[(address, length)])
                .ok()?
                .into_iter()
                .next()
        },
    )
}

fn observed_user_root(process: &Process, hints: &[u64]) -> Result<u64, String> {
    use crate::protocol::memory::{ROOT_HISTORY_COUNT, quad};
    let started = Instant::now();
    loop {
        let info = query_info()?;
        let mut candidates = Vec::with_capacity(hints.len() + ROOT_HISTORY_COUNT + 2);
        candidates.extend_from_slice(hints);
        candidates
            .extend((0..ROOT_HISTORY_COUNT).map(|index| quad(&info, HEADER_BYTES + index * 8)));
        candidates.extend([quad(&info, 64), quad(&info, 48)]);
        if let Some(root) = matched_root(&candidates, process) {
            return Ok(root);
        }
        let Some(remaining) = Duration::from_secs(5).checked_sub(started.elapsed()) else {
            return Err("no observed page-table root matches the target PEB and image; retry while the process is running".into());
        };
        if remaining.is_zero() {
            return Err("no observed page-table root matches the target PEB and image; retry while the process is running".into());
        }
        std::thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

pub fn resolve_process(
    symbols: &KernelSymbols,
    selector: &str,
    target_cr3: u64,
    kernel_cr3: Option<u64>,
) -> Result<Process, String> {
    use crate::protocol::memory::{ROOT_HISTORY_COUNT, quad};
    let info = query_info()?;
    let preferred = kernel_cr3.unwrap_or_else(|| {
        let observed = quad(&info, 64);
        if observed != 0 {
            observed
        } else if target_cr3 != 0 {
            target_cr3
        } else {
            quad(&info, 48)
        }
    });
    let mut roots = vec![preferred];
    if kernel_cr3.is_none() {
        roots.extend((0..ROOT_HISTORY_COUNT).map(|index| quad(&info, HEADER_BYTES + index * 8)));
        roots.extend([quad(&info, 48), target_cr3]);
    }
    roots.retain(|root| *root & !4095 != 0);
    roots.sort_unstable();
    roots.dedup();
    let mut process = symbols.resolve(selector, 0, &roots, quad(&info, 56))?;
    let reported_root = process.user_root();
    let requested_root = target_cr3 & !4095;
    let reported_is_unusable = reported_root & !0x000f_ffff_ffff_ffff != 0 || reported_root == 0;
    let requested_is_distinct = target_cr3 != 0
        && requested_root != process.kernel_cr3
        && requested_root != process.user_cr3;
    let requested_is_unusable = target_cr3 != 0 && target_cr3 & !0x000f_ffff_ffff_ffff != 0;
    if process.kernel_cr3 & !0x000f_ffff_ffff_ffff != 0 || process.kernel_cr3 == 0 {
        process.kernel_access_cr3 = process.observed_kernel_cr3;
    }
    if reported_is_unusable || requested_is_distinct || requested_is_unusable {
        if process.wow64 || process.peb == 0 {
            return Err(
                "cannot validate an alternate root without a native 64-bit process PEB".into(),
            );
        }
        let root = if target_cr3 != 0 {
            matched_root(&[target_cr3], &process).ok_or_else(|| {
                format!("CR3 {target_cr3:#x} does not map the target PEB and image")
            })?
        } else {
            observed_user_root(&process, &roots)?
        };
        process.validated_user_cr3 = Some(root);
        process.kernel_access_cr3 = process.observed_kernel_cr3;
    }
    Ok(process)
}

pub fn process_packet(
    symbols: &KernelSymbols,
    process: &Process,
    operation: u32,
    target_cr3: Option<u64>,
    items: &[Item],
) -> Result<Vec<u8>, String> {
    if !matches!(operation, READ | WRITE) {
        return Err("process memory operation must be read or write".into());
    }
    let mut bytes = packet(
        operation,
        process.pid,
        target_cr3.unwrap_or(process.user_root()),
        items,
    )?;
    bytes[64..72].copy_from_slice(&process.kernel_access_root().to_le_bytes());
    if target_cr3.is_none() {
        bytes[72..80].copy_from_slice(&process.user_root().to_le_bytes());
    }
    for (index, field) in symbols.soft_layout.fields().iter().enumerate() {
        bytes[80 + index * 8..88 + index * 8].copy_from_slice(&field.to_le_bytes());
    }
    for (index, item) in items.iter().enumerate() {
        if let Ok(Some(protection)) =
            symbols.committed_protection(process, item.address, item.bytes.len())
        {
            let descriptor = HEADER_BYTES + index * ITEM_BYTES;
            bytes[descriptor + 16..descriptor + 20].copy_from_slice(&1u32.to_le_bytes());
            bytes[descriptor + 20..descriptor + 24].copy_from_slice(&protection.to_le_bytes());
        }
    }
    Ok(bytes)
}

pub fn transfer(
    symbols: &KernelSymbols,
    process: &Process,
    operation: u32,
    target_cr3: Option<u64>,
    items: &[Item],
) -> Result<Vec<Transfer>, String> {
    let mut bytes = process_packet(symbols, process, operation, target_cr3, items)?;
    invoke(&mut bytes)?;
    decode_transfers(&bytes)
}

#[cfg(test)]
#[path = "../tests/neo_memory_tests.rs"]
mod tests;
