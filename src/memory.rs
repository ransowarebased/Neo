pub use matrixhv_client::memory::*;

use crate::protocol::memory::{HEADER_BYTES, ITEM_BYTES, READ, WRITE};
use crate::symbols::{KernelSymbols, Process};

pub fn resolve_process(
    symbols: &KernelSymbols,
    selector: &str,
    target_cr3: u64,
    kernel_cr3: Option<u64>,
) -> Result<Process, String> {
    use crate::protocol::memory::{ROOT_HISTORY_COUNT, quad};
    let mut info = info_packet()?;
    invoke(&mut info)?;
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
    symbols.resolve(selector, target_cr3, &roots, quad(&info, 56))
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
        target_cr3.unwrap_or(process.kernel_cr3),
        items,
    )?;
    bytes[64..72].copy_from_slice(&process.kernel_cr3.to_le_bytes());
    if target_cr3.is_none() {
        bytes[72..80].copy_from_slice(&process.user_cr3.to_le_bytes());
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
