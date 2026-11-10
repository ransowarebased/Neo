use crate::{memory, output};
use neo::memory::{
    InterceptionRequest, Item, enumerate_page_batch, interception_packet, read_ranges,
    resolve_process, transfer_present,
};
use neo::protocol::memory::{
    BUFFER_BYTES, HEADER_BYTES, INTERCEPT_ACTIVE, INTERCEPT_STATUS, ITEM_BYTES, quad, word,
};
use neo::symbols::{self, KernelSymbols, Process};
use neo::user::{self, Module, Pattern, PatternScanner};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Default)]
pub(crate) struct TargetOptions {
    pub selector: Option<String>,
    pub kernel_cr3: Option<u64>,
    pub image: Option<PathBuf>,
    pub cache: Option<PathBuf>,
}

impl TargetOptions {
    pub fn extract(arguments: &mut Vec<String>) -> Result<Self, String> {
        let mut result = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--process" | "--kernel-cr3" | "--kernel-image" | "--symbols" => {
                    let option = arguments[index].clone();
                    let value = arguments
                        .get(index + 1)
                        .ok_or_else(|| format!("{option} requires a value"))?
                        .clone();
                    match option.as_str() {
                        "--process" => result.selector = Some(value),
                        "--kernel-cr3" => result.kernel_cr3 = Some(memory::number(&value)?),
                        "--kernel-image" => result.image = Some(value.into()),
                        _ => result.cache = Some(value.into()),
                    }
                    arguments.drain(index..index + 2);
                }
                _ => index += 1,
            }
        }
        Ok(result)
    }

    pub fn load(&self, selector: &str, cr3: u64) -> Result<(KernelSymbols, Process), String> {
        let mut info = neo::memory::info_packet()?;
        memory::invoke(&mut info)?;
        let image = self
            .image
            .clone()
            .map(Ok)
            .unwrap_or_else(symbols::default_kernel_image)?;
        let cache = self
            .cache
            .clone()
            .map(Ok)
            .unwrap_or_else(symbols::default_cache)?;
        let symbols = KernelSymbols::load(&image, &cache)?;
        let process = resolve_process(&symbols, selector, cr3, self.kernel_cr3)?;
        Ok((symbols, process))
    }
}

pub(crate) fn load_modules(process: &Process) -> Result<Vec<Module>, String> {
    if process.wow64 {
        return Err(
            "user analysis currently requires a native AMD64 process; WOW64 is unsupported".into(),
        );
    }
    let mut reader =
        |address, length| Ok(read_ranges(process.user_root(), &[(address, length)])?.remove(0));
    user::modules(&mut reader, process.peb)
}

pub(crate) fn resolve_operands(arguments: &[String]) -> Result<Vec<String>, String> {
    let mut operands = arguments.to_vec();
    let options = TargetOptions::extract(&mut operands)?;
    let symbolic = operands
        .iter()
        .any(|value| value.contains('!') || value.contains('+'));
    if symbolic {
        let selector = options
            .selector
            .as_deref()
            .ok_or("symbolic interception addresses require --process PID|NAME")?;
        let setup = matches!(
            (
                operands.first().map(String::as_str),
                operands.get(1).map(String::as_str)
            ),
            (Some("hook"), Some("install"))
                | (Some("syscall" | "debug-registers" | "cpuid"), Some("set"))
        );
        let root = if setup {
            memory::number(operands.get(2).ok_or("installation requires a CR3")?)?
        } else {
            let token = memory::number(
                operands
                    .get(2)
                    .ok_or("symbolic interception requires a session token")?,
            )?;
            let mut status = interception_packet(&InterceptionRequest {
                operation: INTERCEPT_STATUS,
                ..Default::default()
            })?;
            memory::invoke(&mut status)?;
            if quad(&status, 80) != token || word(&status, 112) != INTERCEPT_ACTIVE {
                return Err(
                    "symbolic interception requires the current active session token".into(),
                );
            }
            quad(&status, 16)
        };
        let (_, process) = options.load(selector, root)?;
        let modules = load_modules(&process)?;
        for operand in &mut operands {
            if operand.contains('!') || operand.contains('+') {
                *operand = format!("{:#x}", user::resolve_address(&modules, operand)?);
            }
        }
    }
    Ok(operands)
}

pub(crate) fn instructions_json(instructions: &[user::Instruction]) -> Value {
    json!(instructions.iter().map(|instruction| json!({
        "address": output::hex(instruction.address), "bytes": hex_bytes(&instruction.bytes),
        "text": instruction.text, "symbol": instruction.symbol,
        "targets": instruction.targets.iter().map(|(address, symbol)| json!({"address": output::hex(*address), "symbol": symbol})).collect::<Vec<_>>()
    })).collect::<Vec<_>>())
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn instructions_at(modules: &[Module], root: u64, address: u64) -> Result<(Value, bool), String> {
    if address >= 0x8000_0000_0000 {
        return Err("instruction address exceeds native user space".into());
    }
    let length = (0x8000_0000_0000 - address).min(64) as usize;
    let results = transfer_present(
        root,
        &[Item {
            address,
            bytes: vec![0; length],
        }],
    )?;
    let result = results
        .first()
        .ok_or("instruction read returned no range")?;
    if result.bytes.is_empty() {
        return Err(format!(
            "instruction read at {address:#x}: {}",
            neo::memory::status_text(result.status)
        ));
    }
    Ok((
        instructions_json(&user::disassemble(modules, address, &result.bytes, 8)),
        result.is_complete(),
    ))
}

fn take_flag(arguments: &mut Vec<String>, name: &str) -> bool {
    if let Some(index) = arguments.iter().position(|argument| argument == name) {
        arguments.remove(index);
        true
    } else {
        false
    }
}

fn take_option(arguments: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    if let Some(index) = arguments.iter().position(|argument| argument == name) {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a value"))?
            .clone();
        arguments.drain(index..index + 2);
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub(crate) fn run(arguments: &[String]) -> Result<i32, String> {
    let mut operands = arguments.to_vec();
    let options = TargetOptions::extract(&mut operands)?;
    let command = operands.first().cloned().unwrap_or_default();
    let resident = take_flag(&mut operands, "--resident");
    let show_exports = take_flag(&mut operands, "--exports");
    let show_sections = take_flag(&mut operands, "--sections");
    let decode = take_flag(&mut operands, "--disasm");
    let pattern = take_option(&mut operands, "--pattern")?
        .map(|text| Pattern::parse(&text))
        .transpose()?;
    let start = take_option(&mut operands, "--start")?;
    let end = take_option(&mut operands, "--end")?;
    let maximum = take_option(&mut operands, "--max-hits")?
        .map(|text| memory::number(&text))
        .transpose()?
        .unwrap_or(1000);
    let output_path = take_option(&mut operands, "--output")?;
    if operands.len() < 3
        || !matches!(command.as_str(), "memmap" | "modules" | "scan" | "disasm")
        || operands
            .iter()
            .skip(1)
            .any(|argument| argument.starts_with('-'))
    {
        return Err("usage: neo memmap|modules|scan|disasm PID|NAME CR3|auto [options]; scan requires --pattern \"48 8B ??\"; disasm requires ADDRESS SIZE".into());
    }
    if (command != "disasm" && operands.len() != 3)
        || (command == "disasm" && operands.len() != 5)
        || resident && command != "memmap"
        || (show_exports || show_sections) && command != "modules"
        || (pattern.is_some() || start.is_some() || end.is_some() || decode) && command != "scan"
        || maximum == 0
        || maximum > 100_000
    {
        return Err("invalid analysis operands or options; max-hits must be 1..100000".into());
    }
    if command == "scan" && pattern.is_none() {
        return Err("scan requires --pattern".into());
    }
    let cr3 = if operands[2] == "auto" {
        0
    } else {
        memory::number(&operands[2])?
    };
    let (symbols, process) = options.load(&operands[1], cr3)?;
    let modules = if command == "memmap" {
        Vec::new()
    } else {
        load_modules(&process)?
    };
    let mut data = json!({"pid": output::hex(process.pid), "name": process.name,
        "user_cr3": output::hex(process.user_root()), "memory_consistency": "live_observational"});
    let mut partial = false;
    match command.as_str() {
        "memmap" => {
            let regions = symbols.memory_map(&process)?;
            let mut pages = Vec::new();
            if resident {
                let mut cursor = 0;
                loop {
                    let batch = enumerate_page_batch(process.user_root(), cursor)?;
                    pages.extend(batch.pages.into_iter().map(|(_, address)| address));
                    cursor = batch.next;
                    if cursor >= batch.limit {
                        break;
                    }
                    if pages.len() > 16 * 1024 * 1024 {
                        return Err(
                            "resident map exceeds its page limit; use a bounded scan".into()
                        );
                    }
                }
            }
            data["end_convention"] = json!("exclusive");
            data["protection_encoding"] =
                json!("MMVAD Protection index; not effective per-page permissions");
            data["commit_semantics"] = json!(
                "null means mapped or partially committed region; not inferred from residency"
            );
            data["regions"] = json!(regions.iter().map(|region| {
                let mut value = json!({"start": output::hex(region.start), "end": output::hex(region.end),
                    "protection": region.protection, "private": region.private, "committed": region.committed});
                if resident {
                    value["resident_pages"] = json!(pages.partition_point(|address| *address < region.end) - pages.partition_point(|address| *address < region.start));
                }
                value
            }).collect::<Vec<_>>());
        }
        "modules" => {
            partial = show_exports && modules.iter().any(|module| module.export_error.is_some());
            data["modules"] = json!(modules.iter().map(|module| {
                let mut value = json!({"base": output::hex(module.base), "size": module.size,
                    "entry_point": output::hex(module.entry_point), "name": module.name, "path": module.path});
                if show_sections { value["sections"] = json!(module.sections.iter().map(|section| json!({"name": section.name,
                    "start": output::hex(section.start), "size": section.size, "characteristics": section.characteristics})).collect::<Vec<_>>()); }
                if show_exports {
                    value["exports"] = json!(module.exports.iter().map(|export| json!({"name": export.name,
                        "ordinal": export.ordinal, "address": export.address.map(output::hex), "forwarder": export.forwarder})).collect::<Vec<_>>());
                    if let Some(error) = &module.export_error {
                        value["export_error"] = json!(error);
                    }
                }
                value
            }).collect::<Vec<_>>());
        }
        "disasm" => {
            let address = user::resolve_address(&modules, &operands[3])?;
            let length = usize::try_from(memory::number(&operands[4])?)
                .map_err(|_| "invalid disassembly size")?;
            if length == 0 || length > 1024 * 1024 {
                return Err("disassembly size must be 1..1048576 bytes".into());
            }
            let mut reader = |address, length| {
                Ok(read_ranges(process.user_root(), &[(address, length)])?.remove(0))
            };
            let bytes = user::read_exact(&mut reader, address, length)?;
            let instructions = user::disassemble(&modules, address, &bytes, length);
            let decoded = instructions
                .iter()
                .map(|instruction| instruction.bytes.len())
                .sum::<usize>();
            partial = decoded != length;
            data["instructions"] = instructions_json(&instructions);
            data["decoded_bytes"] = json!(decoded);
            data["requested_bytes"] = json!(length);
        }
        "scan" => {
            let start = start
                .as_deref()
                .map(|value| user::resolve_address(&modules, value))
                .transpose()?
                .unwrap_or(0);
            let end = end
                .as_deref()
                .map(|value| user::resolve_address(&modules, value))
                .transpose()?
                .unwrap_or(0x8000_0000_0000);
            if start >= end || end > 0x8000_0000_0000 {
                return Err("invalid user scan range".into());
            }
            let mut scanner = PatternScanner::new(pattern.ok_or("scan requires --pattern")?);
            let mut cursor = start & !4095;
            let mut hits = Vec::new();
            let mut skipped = Vec::new();
            let mut scanned = 0u64;
            let mut limited = false;
            'scan: loop {
                let batch = enumerate_page_batch(process.user_root(), cursor)?;
                let pages = batch
                    .pages
                    .into_iter()
                    .filter(|(_, address)| *address < end)
                    .collect::<Vec<_>>();
                // Fifteen full pages plus descriptors fit inside BUFFER_BYTES.
                for pages in pages.chunks((BUFFER_BYTES - HEADER_BYTES) / (4096 + ITEM_BYTES)) {
                    let items = pages
                        .iter()
                        .map(|(_, address)| {
                            let first = (*address).max(start);
                            Item {
                                address: first,
                                bytes: vec![0; ((*address + 4096).min(end) - first) as usize],
                            }
                        })
                        .collect::<Vec<_>>();
                    for result in transfer_present(process.user_root(), &items)? {
                        scanned += result.transferred as u64;
                        for address in scanner.feed(
                            result.address,
                            &result.bytes,
                            maximum as usize + 1 - hits.len(),
                        ) {
                            if hits.len() == maximum as usize {
                                limited = true;
                                break 'scan;
                            }
                            let mut hit = json!({"address": output::hex(address), "symbol": user::symbolize(&modules, address)});
                            if decode {
                                match instructions_at(&modules, process.user_root(), address) {
                                    Ok((instructions, complete)) => {
                                        hit["instructions"] = instructions;
                                        hit["instruction_read_complete"] = json!(complete);
                                    }
                                    Err(error) => hit["analysis_error"] = json!(error),
                                }
                            }
                            hits.push(hit);
                        }
                        if !result.is_complete() {
                            scanner.gap();
                            skipped.push(json!({"address": output::hex(result.address), "status": result.status,
                                "transferred": result.transferred, "requested": result.requested}));
                            if skipped.len() >= 65536 {
                                limited = true;
                                break 'scan;
                            }
                        }
                    }
                }
                cursor = batch.next;
                if cursor >= end || cursor >= batch.limit {
                    break;
                }
            }
            partial = limited || !skipped.is_empty();
            data["hits"] = json!(hits);
            data["skipped"] = json!(skipped);
            data["scanned_bytes"] = json!(output::hex(scanned));
            data["truncated"] = json!(limited);
            data["coverage"] =
                json!("present pages observed through AD_ENUMERATE; excludes nonresident regions");
        }
        _ => return Err("unknown analysis command".into()),
    }
    data["complete"] = json!(!partial);
    if let Some(path) = output_path {
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&data).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("failed to write {path}: {error}"))?;
        data = json!({"output": path, "complete": !partial});
    } else if serde_json::to_vec(&data)
        .map_err(|error| error.to_string())?
        .len()
        > 12 * 1024 * 1024
    {
        return Err("analysis output exceeds the remote capture budget; use --output PATH on the target host".into());
    }
    if output::is_json() {
        if partial {
            output::partial(
                data,
                "ANALYSIS_PARTIAL",
                "analysis is incomplete; inspect the result for missing ranges or metadata",
            )?;
        } else {
            output::success(data)?;
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).map_err(|error| error.to_string())?
        );
    }
    Ok(i32::from(partial))
}
