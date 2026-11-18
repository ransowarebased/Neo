use crate::analysis_cli::{self, TargetOptions};
use crate::{memory, output};
use neo::memory::{InterceptionRequest, interception_packet};
use neo::protocol::memory::*;
use neo::unwind::{self, DynamicTable, UnwindContext};
use neo::user::{self, Module};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const FORMAT: &str = "neo-investigation-v1";

#[derive(Default, Serialize, Deserialize)]
struct Catalog {
    modules: Vec<Module>,
    dynamic: Vec<DynamicTable>,
    dynamic_list: Option<u64>,
    #[serde(default)]
    binary_identities: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modules_initialized: Option<bool>,
}

fn module_identity(reader: &mut impl user::MemoryReader, module: &Module) -> Result<Value, String> {
    let headers = user::read_exact(reader, module.base, (module.size as usize).min(4096))?;
    let number = |bytes: &[u8], offset: usize| -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or("truncated module identity")?
                .try_into()
                .map_err(|_| "invalid module identity word")?,
        ))
    };
    if headers.get(..2) != Some(b"MZ") {
        return Err("module identity is not a PE image".into());
    }
    let pe = number(&headers, 60)? as usize;
    if pe > 1024 * 1024 {
        return Err("PE identity offset exceeds its bound".into());
    }
    let nt = user::read_exact(reader, module.address(pe as u32, 264)?, 264)?;
    if &nt[..4] != b"PE\0\0"
        || nt[24..26] != 0x20bu16.to_le_bytes()
        || number(&nt, 80)? != module.size
    {
        return Err("module identity changed during enumeration".into());
    }
    let mut debug_identity = None;
    if number(&nt, 132)? >= 7 {
        let directory = number(&nt, 136 + 6 * 8)?;
        let length = number(&nt, 140 + 6 * 8)? as usize;
        if length > 128 * 28 || !length.is_multiple_of(28) {
            return Err("module debug directory exceeds its bound".into());
        }
        if length != 0 {
            let debug = user::read_exact(reader, module.address(directory, length)?, length)?;
            for row in debug.as_chunks::<28>().0 {
                if number(row, 12)? != 2 {
                    continue;
                }
                let size = number(row, 16)? as usize;
                if !(24..=4096).contains(&size) {
                    continue;
                }
                let data = user::read_exact(reader, module.address(number(row, 20)?, size)?, size)?;
                if let Ok(identity) = neo::symbols::Identity::parse(&data) {
                    debug_identity = Some(
                        json!({"pdb": identity.name, "guid": identity.guid, "age": identity.age}),
                    );
                    break;
                }
            }
        }
    }
    Ok(
        json!({"name": module.name, "base": output::hex(module.base), "image_size": module.size,
        "timestamp": number(&nt, 8)?, "checksum": number(&nt, 88)?, "debug_identity": debug_identity,
        "headers_sha256": analysis_cli::hex_bytes(&Sha256::digest(&headers)),
        "unwind": {"rva": module.exception_rva, "bytes": module.exception_size},
        "memory_consistency": "collection_start_observational"}),
    )
}

fn binary_identities(process: &neo::symbols::Process, modules: &[Module]) -> Vec<Value> {
    let mut reader = |address, length| {
        Ok(neo::memory::read_ranges(process.user_root(), &[(address, length)])?.remove(0))
    };
    modules
        .iter()
        .take(1024)
        .map(|module| {
            module_identity(&mut reader, module).unwrap_or_else(|error|
        json!({"name": module.name, "base": output::hex(module.base), "identity_error": error}))
        })
        .collect()
}

#[derive(Deserialize, Serialize)]
struct Segment {
    address: String,
    requested: u16,
    status: u32,
    bytes: String,
    #[serde(default)]
    copied: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argument: Option<Value>,
    #[serde(default)]
    pages: Vec<SnapshotPage>,
}

#[derive(Deserialize, Serialize)]
struct SnapshotPage {
    address: String,
    physical: String,
    pte_fingerprint: String,
    requested: u32,
    copied: u32,
    status: u32,
    permissions: u32,
    offset: usize,
    page_size: u64,
    sha256: String,
}

fn field(value: &Value, key: &str) -> Result<u64, String> {
    memory::number(
        value[key]
            .as_str()
            .ok_or_else(|| format!("missing field {key}"))?,
    )
}

fn kind_name(kind: u64) -> &'static str {
    match kind {
        EVENT_CONTEXT => "context",
        EVENT_WATCH => "watch",
        EVENT_EXCEPTION | EVENT_SOFTWARE_EXCEPTION => "exception",
        EVENT_ENTRY => "entry",
        EVENT_RETURN => "return",
        EVENT_ABANDON => "abandon",
        EVENT_UNMATCHED => "unmatched",
        EVENT_INSTRUCTION => "instruction",
        EVENT_ARM => "arm",
        EVENT_AFTER => "after",
        _ => "unknown",
    }
}

pub(crate) fn decode(record: &[u8]) -> Result<Value, String> {
    if record.len() != EVENT_RECORD_BYTES {
        return Err("invalid event record size".into());
    }
    let context = memory::context_json(record);
    let mut offset = EVENT_RECORD_HEADER;
    let mut segments = Vec::new();
    for capacity in [EVENT_CODE_BYTES, EVENT_STACK_BYTES]
        .into_iter()
        .chain([EVENT_REGION_BYTES; EVENT_REGIONS])
    {
        let segment = &record[offset..offset + EVENT_SEGMENT_HEADER + capacity];
        let requested = u16::from_le_bytes([segment[8], segment[9]]);
        let captured = u16::from_le_bytes([segment[10], segment[11]]);
        if captured > requested || usize::from(requested) > capacity {
            return Err("invalid event segment length".into());
        }
        let payload = &segment[EVENT_SEGMENT_HEADER..];
        let mut pages = Vec::new();
        let mut next_offset = 0;
        let mut total = 0;
        for descriptor in segment[64..EVENT_SEGMENT_HEADER]
            .as_chunks::<EVENT_PAGE_BYTES>()
            .0
        {
            let page_requested = word(descriptor, 24);
            if page_requested == 0 {
                continue;
            }
            let page_copied = word(descriptor, 28);
            let page_offset = word(descriptor, 40) as usize;
            if page_offset != next_offset
                || page_copied > page_requested
                || page_offset + page_requested as usize > usize::from(requested)
                || quad(descriptor, 0)
                    != quad(segment, 0)
                        .checked_add(page_offset as u64)
                        .ok_or("snapshot address overflow")?
            {
                return Err("invalid snapshot page range".into());
            }
            next_offset += page_requested as usize;
            total += page_copied;
            pages.push(SnapshotPage {
                address: output::hex(quad(descriptor, 0)),
                physical: output::hex(quad(descriptor, 8)),
                pte_fingerprint: output::hex(quad(descriptor, 16)),
                requested: page_requested,
                copied: page_copied,
                status: word(descriptor, 32),
                permissions: word(descriptor, 36),
                offset: page_offset,
                page_size: u64::from(word(descriptor, 44)),
                sha256: analysis_cli::hex_bytes(&Sha256::digest(
                    &payload[page_offset..page_offset + page_copied as usize],
                )),
            });
        }
        if next_offset != usize::from(requested) || total != u32::from(captured) {
            return Err("snapshot page coverage does not match the segment".into());
        }
        segments.push(Segment {
            address: output::hex(quad(segment, 0)),
            requested,
            status: word(segment, 12),
            bytes: analysis_cli::hex_bytes(&payload[..usize::from(requested)]),
            copied: captured,
            argument: (quad(segment, 56) != 0).then(|| json!({
                "source_kind": if quad(segment, 56) == ARGUMENT_REGISTER { "register" } else { "stack" },
                "source_location": output::hex(quad(segment, 16)), "value": output::hex(quad(segment, 24)),
                "initial_pointer": output::hex(quad(segment, 32)), "effective_address": output::hex(quad(segment, 40)),
                "pointer_depth": quad(segment, 48) & 0xffff,
                "pointer_offset": (quad(segment, 48) >> 48) as u16 as i16,
            })),
            pages,
        });
        offset += segment.len();
    }
    let metadata = &record[CONTEXT_RECORD_BYTES..];
    let kind = quad(metadata, 0);
    let detail = quad(metadata, 24);
    let auxiliary = quad(metadata, 32);
    let address = quad(metadata, 48);
    let mut data = json!({
        "type": "event", "kind": kind_name(kind), "context": context,
        "invocation": output::hex(quad(metadata, 8)), "parent": output::hex(quad(metadata, 16)),
        "source_sequence": output::hex(quad(metadata, 40)), "address": output::hex(address),
        "detail": output::hex(detail), "auxiliary": output::hex(auxiliary),
        "memory_consistency": "captured_at_vm_exit", "segments": segments,
        "capture_status": if segments.iter().any(|segment| segment.status != 0 || segment.copied < segment.requested) { "partial" } else { "complete" },
        "version": quad(metadata, 56),
        "timestamp_clock": "tsc", "permission_scope": "guest_page_tables",
        "target_identity": {"pid": output::hex(quad(metadata, 104)), "creation_time": output::hex(quad(metadata, 112)),
            "process_object": output::hex(quad(metadata, 120)), "validated": quad(metadata, 112) != 0},
        "thread_id": (quad(metadata, 136) == 0 && quad(metadata, 128) != 0).then(|| output::hex(quad(metadata, 128))),
        "thread_id_status": quad(metadata, 136),
        "register_context_available": kind != EVENT_ARM,
        "snapshot_phase": match kind { EVENT_ARM => "arm", EVENT_AFTER => "after_instruction", _ => "hit" },
        "process_atomic": false,
        "consistency_note": "Other threads may continue executing; this is not an atomic snapshot of the whole process.",
    });
    if kind == EVENT_AFTER {
        data["correlation"] = json!({"cpu": data["context"]["cpu"], "hit_sequence": output::hex(auxiliary),
            "instruction_address": output::hex(detail)});
        data["instruction_retired"] = json!(quad(metadata, 96) == 0);
        data["after_status"] = json!(quad(metadata, 96));
        data["after_exit_reason"] = json!(quad(metadata, 88));
        if quad(metadata, 96) != 0 {
            data["snapshot_phase"] = json!("after_attempt");
            data["capture_status"] = json!("partial");
        }
    }
    if quad(metadata, 56) != EVENT_FORMAT_VERSION {
        return Err("unsupported event record version".into());
    }
    if kind == EVENT_INSTRUCTION {
        let call_kind = quad(metadata, 72);
        let source = quad(metadata, 88);
        let register = if call_kind == CALL_REGISTER {
            [
                "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15",
            ]
            .get(source as usize)
            .copied()
        } else {
            None
        };
        data["instruction"] = json!({"timing": "before_instruction", "length": quad(metadata, 64),
            "call_kind": match call_kind { CALL_DIRECT => "direct", CALL_REGISTER => "register", CALL_MEMORY => "memory", _ => "none" },
            "effective_target": output::hex(quad(metadata, 80)), "source_address": (call_kind == CALL_MEMORY).then(|| output::hex(source)),
            "source_register": register, "status": quad(metadata, 96)});
    }
    if kind == EVENT_SOFTWARE_EXCEPTION {
        data["exception"] = json!({"source": "windows_dispatch", "record_available": detail != u64::MAX,
            "code": (detail != u64::MAX).then(|| output::hex(detail)),
            "flags": (detail != u64::MAX).then(|| output::hex(auxiliary)),
            "address": (detail != u64::MAX).then(|| output::hex(address))});
    } else if kind == EVENT_EXCEPTION {
        data["exception"] = json!({"source": "vmx", "vector": detail & 255, "interruption_type": (detail >> 8) & 7,
            "error_code": (detail & (1 << 11) != 0).then_some(auxiliary),
            "fault_address": (detail & 255 == 14).then(|| output::hex(address))});
    }
    Ok(data)
}

pub(crate) struct Snapshot(Vec<(u64, Vec<u8>)>);

impl Snapshot {
    pub(crate) fn parse(event: &Value) -> Result<Self, String> {
        let segments: Vec<Segment> =
            serde_json::from_value(event["segments"].clone()).map_err(|error| error.to_string())?;
        let expected_regions = match event["version"].as_u64() {
            None | Some(1 | 2) => 4,
            Some(EVENT_FORMAT_VERSION) => EVENT_REGIONS,
            _ => return Err("unsupported snapshot version".into()),
        };
        if segments.len() != 2 + expected_regions {
            return Err("invalid snapshot segment count".into());
        }
        let mut regions = Vec::new();
        for (index, segment) in segments.into_iter().enumerate() {
            let capacity = [EVENT_CODE_BYTES, EVENT_STACK_BYTES]
                .get(index)
                .copied()
                .unwrap_or(EVENT_REGION_BYTES);
            let address = memory::number(&segment.address)?;
            if segment.bytes.len() % 2 != 0
                || segment.bytes.len() / 2 > usize::from(segment.requested)
                || usize::from(segment.requested) > capacity
                || address.checked_add(u64::from(segment.requested)).is_none()
            {
                return Err("invalid snapshot byte range".into());
            }
            let bytes = segment
                .bytes
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                        .ok_or_else(|| "invalid snapshot hex data".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if segment.pages.is_empty() {
                regions.push((address, bytes));
            } else {
                let mut next_offset = 0;
                let mut copied = 0;
                if segment.pages.len() > EVENT_SEGMENT_PAGES
                    || bytes.len() != usize::from(segment.requested)
                {
                    return Err("invalid snapshot page count or payload length".into());
                }
                for page in segment.pages {
                    let offset = page.offset;
                    let end = offset
                        .checked_add(page.requested as usize)
                        .ok_or("snapshot page overflow")?;
                    let page_address = memory::number(&page.address)?;
                    if offset != next_offset
                        || end > bytes.len()
                        || page.copied > page.requested
                        || address.checked_add(offset as u64) != Some(page_address)
                    {
                        return Err("invalid snapshot page layout".into());
                    }
                    let captured = bytes[offset..offset + page.copied as usize].to_vec();
                    if analysis_cli::hex_bytes(&Sha256::digest(&captured)) != page.sha256 {
                        return Err("snapshot page hash mismatch".into());
                    }
                    copied += page.copied;
                    next_offset = end;
                    regions.push((page_address, captured));
                }
                if next_offset != bytes.len() || copied != u32::from(segment.copied) {
                    return Err("snapshot page coverage mismatch".into());
                }
            }
        }
        Ok(Self(regions))
    }
}

impl user::MemoryReader for Snapshot {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        while bytes.len() < length {
            let position = address
                .checked_add(bytes.len() as u64)
                .ok_or("snapshot address overflow")?;
            let Some((base, region)) = self
                .0
                .iter()
                .find(|(base, data)| position >= *base && position - *base < data.len() as u64)
            else {
                break;
            };
            let start = (position - base) as usize;
            let count = (length - bytes.len()).min(region.len() - start);
            bytes.extend_from_slice(&region[start..start + count]);
        }
        if length != 0 && bytes.is_empty() {
            return Err(format!(
                "address {address:#x} is outside the captured bytes"
            ));
        }
        Ok(bytes)
    }
}

#[derive(Default)]
pub(crate) struct Analysis {
    disasm: bool,
    unwind: bool,
    frames: usize,
    catalog: Catalog,
}

impl Analysis {
    pub(crate) fn apply(&self, event: &mut Value) -> Result<(), String> {
        if let Some(rip) = event["context"]["rip"]
            .as_str()
            .and_then(|value| memory::number(value).ok())
            && let Some(module) = self
                .catalog
                .modules
                .iter()
                .find(|module| module.contains(rip))
        {
            event["location"] = json!({"module": module.name, "base": output::hex(module.base), "rva": output::hex(rip - module.base),
                "binary": self.catalog.binary_identities.iter().find(|identity| identity["base"] == output::hex(module.base))});
        }
        if !self.disasm && !self.unwind || event["register_context_available"] == false {
            return Ok(());
        }
        let mut snapshot = Snapshot::parse(event)?;
        let context = &event["context"];
        let rip = field(context, "rip")?;
        let rsp = field(context, "rsp")?;
        let cpl = field(context, "cpl")?;
        let mut registers = [0; 16];
        for (index, name) in [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .into_iter()
        .enumerate()
        {
            registers[index] = field(context, name)?;
        }
        if self.disasm {
            event["instructions"] = analysis_cli::instructions_json(&user::disassemble(
                &self.catalog.modules,
                rip,
                &user::MemoryReader::read(&mut snapshot, rip, EVENT_CODE_BYTES).unwrap_or_default(),
                8,
            ));
        }
        if self.unwind {
            if cpl != 3 {
                return Err("captured unwind requires a native user-mode context".into());
            }
            let mut tables = self.catalog.dynamic.clone();
            let mut discovery_error = None;
            if let Some(head) = self.catalog.dynamic_list {
                match unwind::dynamic_tables(&mut snapshot, head) {
                    Ok(discovered) => tables.extend(discovered),
                    Err(error) => discovery_error = Some(error),
                }
            }
            let result = unwind::unwind_with_tables(
                &mut snapshot,
                &self.catalog.modules,
                &tables,
                UnwindContext {
                    rip,
                    rsp,
                    registers,
                },
                self.frames,
                true,
            );
            event["unwind"] = json!({"frames": result.frames.iter().map(|frame| json!({
                "rip": output::hex(frame.rip), "rsp": output::hex(frame.rsp), "symbol": frame.symbol,
                "method": frame.method,
            })).collect::<Vec<_>>(), "stop": result.stop, "complete": result.complete,
                "dynamic_list_error": discovery_error,
                "memory_consistency": "captured_at_vm_exit", "module_catalog": "collection_start",
            });
        }
        Ok(())
    }
}

fn take(
    arguments: &mut Vec<String>,
    option: &str,
    count: usize,
) -> Result<Option<Vec<String>>, String> {
    let Some(index) = arguments.iter().position(|value| value == option) else {
        return Ok(None);
    };
    if arguments.len() - index <= count {
        return Err(format!("{option} requires {count} value(s)"));
    }
    Ok(Some(
        arguments.drain(index..=index + count).skip(1).collect(),
    ))
}

fn value(arguments: &mut Vec<String>, option: &str) -> Result<Option<String>, String> {
    Ok(take(arguments, option, 1)?.and_then(|mut values| values.pop()))
}

fn flag(arguments: &mut Vec<String>, option: &str) -> bool {
    arguments
        .iter()
        .position(|value| value == option)
        .is_some_and(|index| {
            arguments.remove(index);
            true
        })
}

fn numeric(arguments: &mut Vec<String>, option: &str) -> Result<Option<u64>, String> {
    value(arguments, option)?
        .as_deref()
        .map(memory::number)
        .transpose()
}

pub(crate) fn analysis(arguments: &mut Vec<String>) -> Result<Analysis, String> {
    let mut analysis = Analysis {
        disasm: flag(arguments, "--disasm"),
        unwind: flag(arguments, "--unwind"),
        frames: numeric(arguments, "--frames")?
            .unwrap_or(32)
            .try_into()
            .map_err(|_| "invalid frame limit")?,
        ..Analysis::default()
    };
    if !(1..=STACK_MAX_FRAMES).contains(&analysis.frames) {
        return Err("--frames must be 1..64".into());
    }
    analysis.catalog.dynamic_list = numeric(arguments, "--dynamic-list")?;
    while let Some(values) = take(arguments, "--table", 5)? {
        let values = values
            .iter()
            .map(|value| memory::number(value))
            .collect::<Result<Vec<_>, _>>()?;
        let table = DynamicTable {
            base: values[0],
            start: values[1],
            end: values[2],
            address: values[3],
            count: values[4].try_into().map_err(|_| "invalid table count")?,
            kind: 0,
        };
        table.validate()?;
        analysis.catalog.dynamic.push(table);
    }
    Ok(analysis)
}

fn request(request: InterceptionRequest) -> Result<Vec<u8>, String> {
    let mut bytes = interception_packet(&request)?;
    for attempt in 0..5 {
        let result = memory::invoke(&mut bytes);
        if result.is_ok() || word(&bytes, 40) != Error::Busy as u32 || attempt == 4 {
            return result.map(|()| bytes);
        }
        std::thread::sleep(Duration::from_millis(1));
        bytes = interception_packet(&request)?;
    }
    unreachable!()
}

pub(crate) fn available() -> Result<bool, String> {
    let mut info = neo::memory::info_packet()?;
    memory::invoke(&mut info)?;
    Ok(word(&info, 72) & EVENT_V3_CAPABILITY != 0)
}

struct Batch {
    next: u64,
    oldest: u64,
    dropped: u64,
    records: Vec<Value>,
}

fn fetch(token: u64, cpu: u32, cursor: u64) -> Result<Batch, String> {
    let probe = request(InterceptionRequest {
        operation: EVENT_FETCH,
        token,
        cpu,
        cursor,
        ..Default::default()
    })?;
    let oldest = quad(&probe, 96);
    let head = quad(&probe, 104);
    let pending = head.saturating_sub(cursor.max(oldest.saturating_sub(1)));
    if pending == 0 {
        return Ok(Batch {
            next: cursor,
            oldest,
            dropped: quad(&probe, 120),
            records: Vec::new(),
        });
    }
    let bytes = request(InterceptionRequest {
        operation: EVENT_FETCH,
        token,
        cpu,
        cursor,
        count: pending.min(EVENT_FETCH_MAX as u64) as usize,
        ..Default::default()
    })?;
    let batch = neo::memory::decode_event_batch(&bytes)?;
    let records = batch
        .records
        .into_iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Batch {
        next: quad(&bytes, 88),
        oldest: quad(&bytes, 96),
        dropped: quad(&bytes, 120),
        records,
    })
}

pub(crate) fn retained(token: u64, cpu: u32, kind: u64) -> Result<Vec<Value>, String> {
    let mut cursor = 0;
    let mut records = Vec::new();
    for _ in 0..EVENT_RING_RECORDS.div_ceil(EVENT_FETCH_MAX) {
        let batch = fetch(token, cpu, cursor)?;
        let full = batch.records.len() == EVENT_FETCH_MAX;
        cursor = batch.next;
        records.extend(
            batch
                .records
                .into_iter()
                .filter(|event| event["kind"] == kind_name(kind)),
        );
        if !full {
            break;
        }
    }
    Ok(records)
}

pub(crate) fn attach(
    bytes: &[u8],
    request: &InterceptionRequest,
    options: &TargetOptions,
    mut analysis: Analysis,
) -> Result<Value, String> {
    let mut data = memory::observation_json(bytes, request.operation)?;
    let records = data["records"]
        .as_array_mut()
        .ok_or("missing observation records")?;
    let captured = retained(
        request.token,
        request.cpu,
        if request.operation == WATCH_FETCH {
            EVENT_WATCH
        } else {
            EVENT_CONTEXT
        },
    )?;
    let mut process = None;
    let mut catalog_errors = std::collections::HashMap::new();
    for record in records {
        let Some(mut event) = captured
            .iter()
            .find(|event| {
                event["source_sequence"] == record["sequence"]
                    && event["context"]["tsc"] == record["tsc"]
                    && event["context"]["cr3"] == record["cr3"]
            })
            .cloned()
        else {
            record["analysis_error"] =
                json!("event bytes are outside the retained snapshot window");
            continue;
        };
        let root = field(record, "cr3")? & !4095;
        if process.is_none() && options.selector.is_some() {
            if let std::collections::hash_map::Entry::Vacant(entry) = catalog_errors.entry(root) {
                match analysis.load_catalog(options, root) {
                    Ok(resolved) => process = resolved,
                    Err(error) => {
                        entry.insert(error);
                    }
                }
            }
            if let Some(error) = catalog_errors.get(&root) {
                record["analysis_error"] = json!(error);
                continue;
            }
        }
        if process.is_some_and(|(kernel, user)| root != kernel && root != user) {
            record["analysis_error"] =
                json!("captured CR3 does not belong to the selected process");
            continue;
        }
        if let Err(error) = analysis.apply(&mut event) {
            event["analysis_error"] = json!(error);
        }
        if process.is_some() {
            record["symbol"] = json!(user::symbolize(
                &analysis.catalog.modules,
                field(record, "rip")?
            ));
        }
        record["snapshot"] = event;
    }
    data["memory_consistency"] = json!("captured_at_vm_exit");
    Ok(data)
}

impl Analysis {
    fn load_catalog(
        &mut self,
        options: &TargetOptions,
        root: u64,
    ) -> Result<Option<(u64, u64)>, String> {
        let Some(selector) = options.selector.as_deref() else {
            return Ok(None);
        };
        let (_, process) = options.load(selector, root)?;
        if root & !4095 != process.user_root() && root & !4095 != process.kernel_cr3 {
            return Err("captured CR3 does not belong to the selected process".into());
        }
        let loaded = analysis_cli::load_initialized_modules(&process)?;
        self.catalog.modules_initialized = Some(loaded.is_some());
        self.catalog.modules = loaded.unwrap_or_default();
        self.catalog.binary_identities = binary_identities(&process, &self.catalog.modules);
        if self.catalog.dynamic_list.is_none() {
            let mut reader = |address, length| {
                Ok(neo::memory::read_ranges(process.user_root(), &[(address, length)])?.remove(0))
            };
            self.catalog.dynamic_list =
                unwind::dynamic_list_head(&mut reader, &self.catalog.modules).ok();
        }
        Ok(Some((process.kernel_cr3, process.user_root())))
    }

    pub(crate) fn captured_stack(
        mut self,
        token: u64,
        cpu: u32,
        sequence: u64,
        count: usize,
        options: &TargetOptions,
    ) -> Result<i32, String> {
        let cached = request(InterceptionRequest {
            operation: CONTEXT_RECORD_GET,
            token,
            cpu,
            cursor: sequence,
            count: 1,
            ..Default::default()
        })?;
        let context = memory::context_json(&cached[HEADER_BYTES..]);
        let mut event = retained(token, cpu, EVENT_CONTEXT)?
            .into_iter()
            .find(|event| {
                event["source_sequence"] == context["sequence"]
                    && event["context"]["tsc"] == context["tsc"]
                    && event["context"]["cr3"] == context["cr3"]
            })
            .ok_or("context memory is outside the retained snapshot window")?;
        self.frames = count;
        self.load_catalog(options, field(&event["context"], "cr3")?)?;
        self.apply(&mut event)?;
        let incomplete = event["unwind"]["complete"] != true;
        if incomplete && output::is_json() {
            output::partial(
                event,
                "UNWIND_PARTIAL",
                "stack walk stopped at the recorded boundary",
            )?;
        } else {
            report(event)?;
        }
        Ok(i32::from(incomplete))
    }

    pub(crate) fn live_tables(
        &self,
        reader: &mut impl user::MemoryReader,
        modules: &[Module],
    ) -> Result<Vec<DynamicTable>, String> {
        let mut tables = self.catalog.dynamic.clone();
        if let Some(head) = self.catalog.dynamic_list {
            tables.extend(unwind::dynamic_tables(reader, head)?);
        } else if let Ok(head) = unwind::dynamic_list_head(reader, modules)
            && let Ok(discovered) = unwind::dynamic_tables(reader, head)
        {
            tables.extend(discovered);
        }
        Ok(tables)
    }
}

fn active(token: u64, bytes: &[u8]) -> Result<(), String> {
    if quad(bytes, 80) != token || word(bytes, 112) != INTERCEPT_ACTIVE {
        return Err(format!(
            "capture session ended or token changed (cause {})",
            word(bytes, 116)
        ));
    }
    Ok(())
}

fn argument_location(expression: &str, on_stack: bool) -> Result<(u64, i16), String> {
    let expression = expression.trim();
    let expression = if expression.starts_with('[') || expression.ends_with(']') {
        expression
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or("invalid argument address expression")?
    } else {
        expression
    };
    let split = expression.find(['+', '-']);
    let (location, displacement) = split.map_or((expression, None), |index| {
        (&expression[..index], Some(&expression[index..]))
    });
    let location = location.trim();
    let location = if on_stack {
        memory::number(location)?
    } else {
        [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .iter()
        .position(|register| register.eq_ignore_ascii_case(location))
        .ok_or("invalid argument register")? as u64
    };
    let displacement = if let Some(value) = displacement {
        let magnitude = memory::number(value[1..].trim())?;
        let signed = i64::try_from(magnitude).map_err(|_| "argument offset exceeds i16 range")?;
        i16::try_from(if value.starts_with('-') {
            -signed
        } else {
            signed
        })
        .map_err(|_| "argument offset exceeds i16 range")?
    } else {
        0
    };
    Ok((location, displacement))
}

fn setup(arguments: &mut Vec<String>) -> Result<i32, String> {
    let options = TargetOptions::extract(arguments)?;
    let no_lease = flag(arguments, "--no-lease");
    let code_pages = flag(arguments, "--code-pages");
    let mut setup = InterceptionRequest {
        operation: EVENT_SET,
        event_sample: flag(arguments, "--sample"),
        flags: if no_lease { INTERCEPT_NO_LEASE } else { 0 },
        event_exceptions: numeric(arguments, "--exceptions")?.unwrap_or(0),
        event_limit: numeric(arguments, "--max-events")?.unwrap_or(0),
        snapshot_arm: flag(arguments, "--snapshot-arm"),
        snapshot_after: flag(arguments, "--snapshot-after"),
        event_stack_bytes: numeric(arguments, "--stack-bytes")?
            .unwrap_or(0)
            .try_into()
            .map_err(|_| "invalid stack capture size")?,
        alternate_cr3: numeric(arguments, "--alternate-cr3")?.unwrap_or(0),
        lease_ms: numeric(arguments, "--lease-ms")?
            .unwrap_or(0)
            .try_into()
            .map_err(|_| "invalid lease")?,
        ..Default::default()
    };
    let mut regions = Vec::new();
    while let Some(values) = take(arguments, "--region", 2)? {
        regions.push((values[0].clone(), memory::number(&values[1])?));
    }
    for (option, on_stack) in [("--arg-reg", false), ("--arg-stack", true)] {
        while let Some(values) = take(arguments, option, 3)? {
            let (location, pointer_offset) = argument_location(&values[0], on_stack)?;
            setup.event_arguments.push(neo::memory::ArgumentCapture {
                location,
                on_stack,
                pointer_offset,
                copy_bytes: memory::number(&values[1])?
                    .try_into()
                    .map_err(|_| "invalid argument copy size")?,
                pointer_depth: memory::number(&values[2])?
                    .try_into()
                    .map_err(|_| "invalid argument pointer depth")?,
            });
        }
    }
    let mut probes = Vec::new();
    let circular = flag(arguments, "--circular");
    for (option, kind) in [
        ("--entry", EVENT_ENTRY),
        ("--return", EVENT_RETURN),
        ("--exception-dispatch", EVENT_SOFTWARE_EXCEPTION),
        ("--instruction", EVENT_INSTRUCTION),
    ] {
        while let Some(address) = value(arguments, option)? {
            probes.push((address, kind));
        }
    }
    let [cr3, token] = arguments.as_slice() else {
        return Err("usage: neo session set CR3 TOKEN [--sample] [--exceptions MASK] [--region ADDRESS SIZE] [--entry ADDRESS --return ADDRESS]".into());
    };
    setup.cr3 = if cr3 == "auto" {
        0
    } else {
        memory::number(cr3)?
    };
    setup.token = memory::number(token)?;
    let instruction_capture = probes.iter().any(|(_, kind)| *kind == EVENT_INSTRUCTION);
    if !circular && setup.event_limit == 0 && instruction_capture {
        setup.event_limit = 1;
    }
    if instruction_capture {
        if no_lease {
            return Err("instruction capture requires a lease; remove --no-lease".into());
        }
        if options.selector.is_none() {
            return Err("instruction capture requires --process PID|NAME to validate the process execution identity".into());
        }
    }
    if setup.token != 0 {
        let status = request(InterceptionRequest {
            operation: INTERCEPT_STATUS,
            ..Default::default()
        })?;
        active(setup.token, &status)?;
        if setup.alternate_cr3 == 0 {
            setup.alternate_cr3 = quad(&status, 64);
        }
        if !no_lease && setup.lease_ms == 0 {
            setup.lease_ms = word(&status, 132);
            if setup.lease_ms == 0 && !instruction_capture {
                setup.flags |= INTERCEPT_NO_LEASE;
            }
        }
    }
    let mut identities = Vec::new();
    let mut modules_initialized = false;
    let modules = if let Some(selector) = options.selector.as_deref() {
        let (symbols, process) = options.load(selector, setup.cr3)?;
        (setup.event_identity, setup.event_guards) = symbols.capture_identity(&process)?;
        setup.thread_id_offset = symbols
            .thread_id_offset
            .map(|offset| {
                u32::try_from(offset).map_err(|_| "thread identity field offset exceeds its bound")
            })
            .transpose()?
            .unwrap_or(0);
        setup.cr3 = process.user_root();
        let loaded = analysis_cli::load_initialized_modules(&process)?;
        modules_initialized = loaded.is_some();
        let modules = loaded.unwrap_or_default();
        identities = binary_identities(&process, &modules);
        modules
    } else {
        Vec::new()
    };
    let resolve = |address: String| user::resolve_address(&modules, &address);
    for (address, length) in regions {
        setup.event_regions.push((resolve(address)?, length));
    }
    for (address, kind) in probes {
        setup.event_probes.push((resolve(address)?, kind));
    }
    if code_pages {
        let pages: std::collections::BTreeSet<_> = setup
            .event_probes
            .iter()
            .map(|(address, _)| address & !4095)
            .collect();
        for page in pages {
            if !setup.event_regions.contains(&(page, 4096)) {
                setup.event_regions.push((page, 4096));
            }
        }
    }
    let bytes = request(setup)?;
    let mut result = memory::interception_json(&bytes)?;
    result["catalog"] = json!({"modules": modules, "binary_identities": identities,
        "modules_initialized": modules_initialized});
    report(result)
}

fn report(data: Value) -> Result<i32, String> {
    if output::is_json() {
        output::success(data)?;
    } else {
        output::write(&data)?;
    }
    Ok(0)
}

fn write_row(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| error.to_string())?;
    writer.write_all(b"\n").map_err(|error| error.to_string())
}

struct RecordingLease {
    stop: std::sync::mpsc::Sender<()>,
    failures: std::sync::mpsc::Receiver<String>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RecordingLease {
    fn renew(token: u64, lease_ms: u32) -> Result<u32, String> {
        let bytes = request(InterceptionRequest {
            operation: if lease_ms == 0 {
                INTERCEPT_STATUS
            } else {
                INTERCEPT_RENEW
            },
            token,
            ..Default::default()
        })?;
        active(token, &bytes)?;
        Ok(word(&bytes, 132))
    }

    fn start(token: u64, lease_ms: u32) -> Result<Self, String> {
        let mut lease_ms = Self::renew(token, lease_ms)?;
        let (stop, stopped) = std::sync::mpsc::channel();
        let (failure, failures) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("neo-recording-lease".into())
            .spawn(move || {
                loop {
                    let delay = Duration::from_millis(if lease_ms == 0 {
                        1000
                    } else {
                        u64::from(lease_ms / 3).max(1)
                    });
                    if stopped.recv_timeout(delay)
                        != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    {
                        break;
                    }
                    match Self::renew(token, lease_ms) {
                        Ok(duration) => lease_ms = duration,
                        Err(error) => {
                            let _ = failure.send(error);
                            break;
                        }
                    }
                }
            })
            .map_err(|error| format!("cannot start lease renewal: {error}"))?;
        Ok(Self {
            stop,
            failures,
            worker: Some(worker),
        })
    }

    fn check(&self) -> Result<(), String> {
        match self.failures.try_recv() {
            Ok(error) => Err(error),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err("lease renewal stopped".into()),
        }
    }
}

impl Drop for RecordingLease {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn record(mut arguments: Vec<String>, watch: bool) -> Result<i32, String> {
    let mut analysis = analysis(&mut arguments)?;
    let target = TargetOptions::extract(&mut arguments)?;
    let path = value(&mut arguments, "--output")?.ok_or("record requires --output FILE.jsonl")?;
    let seconds = numeric(&mut arguments, "--seconds")?.or(Some(30));
    let interval = numeric(&mut arguments, "--interval-ms")?.unwrap_or(25);
    let cpu = numeric(&mut arguments, "--cpu")?;
    let [token] = arguments.as_slice() else {
        return Err("record requires TOKEN".into());
    };
    let token = memory::number(token)?;
    if seconds.is_some_and(|seconds| !(1..=86_400).contains(&seconds))
        || !(1..=1000).contains(&interval)
        || cpu.is_some_and(|cpu| cpu >= 64)
    {
        return Err("invalid recording duration, interval or CPU".into());
    }
    let status = request(InterceptionRequest {
        operation: INTERCEPT_STATUS,
        ..Default::default()
    })?;
    active(token, &status)?;
    let root = quad(&status, 16);
    let alternate = quad(&status, 64);
    let lease = RecordingLease::start(token, word(&status, 132))?;
    analysis.load_catalog(&target, root)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("{path}: {error}"))?;
    let mut writer = BufWriter::new(file);
    write_row(
        &mut writer,
        &json!({"type": "session", "format": FORMAT, "token": output::hex(token),
        "cr3": output::hex(root), "alternate_cr3": output::hex(alternate), "catalog": analysis.catalog,
        "started_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        "kind": if watch { "watch" } else { "all" }}),
    )?;
    writer.flush().map_err(|error| error.to_string())?;
    let start = Instant::now();
    let mut cursors = [0; 64];
    let mut drops = [0; 64];
    let mut written = 0u64;
    let mut gaps = 0u64;
    let result = (|| -> Result<(), String> {
        loop {
            lease.check()?;
            let final_pass =
                seconds.is_some_and(|seconds| start.elapsed() >= Duration::from_secs(seconds));
            for index in 0..64 {
                if cpu.is_some_and(|cpu| cpu != index as u64) {
                    continue;
                }
                // A bounded drain keeps other CPUs and the lease renewal responsive.
                for _ in 0..EVENT_RING_RECORDS.div_ceil(EVENT_FETCH_MAX) {
                    lease.check()?;
                    let batch = fetch(token, index as u32, cursors[index])?;
                    if batch.oldest > cursors[index].saturating_add(1)
                        || batch.dropped != drops[index]
                    {
                        write_row(
                            &mut writer,
                            &json!({"type": "gap", "cpu": output::hex(index as u64),
                            "after": output::hex(cursors[index]), "oldest": output::hex(batch.oldest),
                            "dropped_total": output::hex(batch.dropped)}),
                        )?;
                        gaps += 1;
                    }
                    drops[index] = batch.dropped;
                    cursors[index] = batch.next;
                    let full = batch.records.len() == EVENT_FETCH_MAX;
                    for mut event in batch.records {
                        if watch && event["kind"] != "watch" {
                            continue;
                        }
                        lease.check()?;
                        if let Err(error) = analysis.apply(&mut event) {
                            event["analysis_error"] = json!(error);
                        }
                        write_row(&mut writer, &event)?;
                        written += 1;
                    }
                    if !full {
                        break;
                    }
                }
            }
            writer.flush().map_err(|error| error.to_string())?;
            if final_pass {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(interval));
        }
    })();
    write_row(
        &mut writer,
        &json!({"type": "end", "events": output::hex(written), "gaps": output::hex(gaps),
        "complete": result.is_ok(), "error": result.as_ref().err()}),
    )?;
    writer.flush().map_err(|error| error.to_string())?;
    result?;
    report(json!({"output": path, "events": output::hex(written), "gaps": output::hex(gaps)}))
}

fn query(mut arguments: Vec<String>, tree: bool) -> Result<i32, String> {
    let mut analysis = analysis(&mut arguments)?;
    let kind = value(&mut arguments, "--kind")?;
    let cpu = numeric(&mut arguments, "--cpu")?;
    let teb = numeric(&mut arguments, "--thread-teb")?;
    let sequence = numeric(&mut arguments, "--sequence")?;
    let invocation = numeric(&mut arguments, "--invocation")?;
    let limit = numeric(&mut arguments, "--limit")?.unwrap_or(u64::MAX);
    let [path] = arguments.as_slice() else {
        return Err("query requires FILE.jsonl".into());
    };
    let file = File::open(Path::new(path)).map_err(|error| format!("{path}: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let header: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
    if header["type"] != "session" || header["format"] != FORMAT {
        return Err("unsupported investigation format".into());
    }
    let catalog: Catalog =
        serde_json::from_value(header["catalog"].clone()).map_err(|error| error.to_string())?;
    if catalog.modules.iter().any(|module| {
        module.base == 0
            || module.size == 0
            || module
                .base
                .checked_add(u64::from(module.size))
                .is_none_or(|end| end > 0x8000_0000_0000)
    }) {
        return Err("invalid module range in investigation catalog".into());
    }
    for table in &catalog.dynamic {
        table.validate()?;
    }
    analysis.catalog.modules = catalog.modules;
    analysis.catalog.binary_identities = catalog.binary_identities;
    if analysis.catalog.dynamic_list.is_none() {
        analysis.catalog.dynamic_list = catalog.dynamic_list;
    }
    if analysis.catalog.dynamic.is_empty() {
        analysis.catalog.dynamic = catalog.dynamic;
    }
    let mut shown = 0;
    let mut calls = std::collections::BTreeMap::new();
    let mut gaps = 0;
    let mut complete = false;
    let mut truncated = false;
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            break;
        }
        let mut event: Value = match serde_json::from_str(&line) {
            Ok(event) => event,
            Err(_) if !line.ends_with('\n') => {
                truncated = true;
                break;
            }
            Err(error) => return Err(format!("invalid investigation row: {error}")),
        };
        match event["type"].as_str() {
            Some("gap") => {
                gaps += 1;
            }
            Some("end") => {
                complete = event["complete"] == true;
            }
            Some("event") => {
                let context = &event["context"];
                if shown >= limit
                    || kind
                        .as_ref()
                        .is_some_and(|kind| event["kind"].as_str() != Some(kind))
                    || cpu.is_some_and(|cpu| field(context, "cpu").ok() != Some(cpu))
                    || teb.is_some_and(|teb| field(context, "thread_teb").ok() != Some(teb))
                    || sequence
                        .is_some_and(|sequence| field(context, "sequence").ok() != Some(sequence))
                    || invocation.is_some_and(|id| {
                        field(&event, "invocation").ok() != Some(id)
                            && field(&event, "parent").ok() != Some(id)
                    })
                {
                    continue;
                }
                if tree {
                    if !matches!(event["kind"].as_str(), Some("entry" | "return" | "abandon")) {
                        continue;
                    }
                    let id = field(&event, "invocation")?;
                    let node = calls.entry(id).or_insert_with(|| json!({
                        "id": event["invocation"], "parent": event["parent"], "address": event["address"],
                        "thread_teb": event["context"]["thread_teb"], "status": "open", "children": [],
                    }));
                    if event["kind"] == "entry" {
                        node["entry"] = event["context"].clone();
                    } else {
                        node["end"] = event["context"].clone();
                        node["status"] = json!(if event["kind"] == "return" {
                            "returned"
                        } else {
                            "abandoned"
                        });
                    }
                } else {
                    if let Err(error) = analysis.apply(&mut event) {
                        event["analysis_error"] = json!(error);
                    }
                    report(event)?;
                }
                shown += 1;
            }
            _ => return Err("invalid investigation row type".into()),
        }
    }
    if tree {
        let relationships = calls
            .iter()
            .map(|(id, node)| Ok((*id, field(node, "parent")?)))
            .collect::<Result<Vec<_>, String>>()?;
        let mut roots = Vec::new();
        for (id, parent) in relationships {
            if let Some(node) = calls.get_mut(&parent).filter(|_| parent < id) {
                node["children"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(output::hex(id)));
            } else {
                roots.push(output::hex(id));
            }
        }
        return report(
            json!({"type": "call_tree", "roots": roots, "calls": calls.into_values().collect::<Vec<_>>(),
            "gaps": output::hex(gaps), "complete": complete, "truncated_tail": truncated}),
        );
    }
    report(
        json!({"type": "query_summary", "events": output::hex(shown), "gaps": output::hex(gaps),
        "complete": complete, "truncated_tail": truncated}),
    )
}

fn visit_events(
    path: &str,
    mut visit: impl FnMut(Value) -> Result<(), String>,
) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("{path}: {error}"))?;
    let mut lines = BufReader::new(file).lines();
    let header: Value = serde_json::from_str(
        &lines
            .next()
            .ok_or("empty investigation")?
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if header["type"] != "session" || header["format"] != FORMAT {
        return Err("unsupported investigation format".into());
    }
    for line in lines {
        let row: Value = serde_json::from_str(&line.map_err(|error| error.to_string())?)
            .map_err(|error| format!("invalid investigation row: {error}"))?;
        if row["type"] == "event" {
            visit(row)?;
        }
    }
    Ok(())
}

fn event_key(value: &str) -> Result<(u64, u64), String> {
    let (cpu, sequence) = value
        .split_once(':')
        .ok_or("event identity must be CPU:SEQUENCE")?;
    let cpu = memory::number(cpu)?;
    let sequence = memory::number(sequence)?;
    if cpu >= 64 || sequence == 0 {
        return Err("invalid event identity".into());
    }
    Ok((cpu, sequence))
}

pub(crate) fn compare_events(before: &Value, after: &Value) -> Result<Value, String> {
    Snapshot::parse(before)?;
    Snapshot::parse(after)?;
    if field(&before["context"], "cr3")? & !4095 != field(&after["context"], "cr3")? & !4095 {
        return Err("snapshot comparison requires the same address space".into());
    }
    if before["target_identity"] != after["target_identity"] {
        return Err("snapshots belong to different process execution identities".into());
    }
    let collect =
        |event: &Value| -> Result<std::collections::BTreeMap<(usize, u64), SnapshotPage>, String> {
            let segments: Vec<Segment> = serde_json::from_value(event["segments"].clone())
                .map_err(|error| error.to_string())?;
            let mut pages = std::collections::BTreeMap::new();
            for (index, segment) in segments.into_iter().enumerate() {
                for page in segment.pages {
                    let address = memory::number(&page.address)? & !4095;
                    if pages.insert((index, address), page).is_some() {
                        return Err("duplicate page in snapshot segment".into());
                    }
                }
            }
            if pages.is_empty() {
                return Err("snapshot has no per-page metadata".into());
            }
            Ok(pages)
        };
    let before_pages = collect(before)?;
    let after_pages = collect(after)?;
    let keys: std::collections::BTreeSet<_> = before_pages
        .keys()
        .chain(after_pages.keys())
        .copied()
        .collect();
    let mut changed = 0;
    let mut pages = Vec::new();
    for (segment, address) in keys {
        let before = before_pages.get(&(segment, address));
        let after = after_pages.get(&(segment, address));
        let state = match (before, after) {
            (None, _) => "added",
            (_, None) => "removed",
            (Some(_), Some(b)) if b.status == Error::Unmapped as u32 && b.copied == 0 => "missing",
            (Some(_), Some(b)) if b.copied == 0 && b.status != 0 => "unreadable",
            (Some(a), Some(b)) if a.physical != b.physical => "remapped",
            (Some(a), Some(b))
                if a.address != b.address || a.requested != b.requested || a.copied != b.copied =>
            {
                "coverage_changed"
            }
            (Some(a), Some(b)) if a.permissions != b.permissions => "permissions_changed",
            (Some(a), Some(b)) if a.pte_fingerprint != b.pte_fingerprint => "remapped",
            (Some(a), Some(b)) if a.sha256 != b.sha256 => "changed",
            (Some(a), Some(b)) if a.status != b.status => "status_changed",
            _ => "unchanged",
        };
        if state != "unchanged" {
            changed += 1;
        }
        pages.push(
            json!({"segment": segment, "address": output::hex(address), "state": state,
            "before": before, "after": after}),
        );
    }
    Ok(
        json!({"type": "snapshot_comparison", "process_atomic": false, "changed_pages": changed, "pages": pages}),
    )
}

fn compare(arguments: &[String]) -> Result<i32, String> {
    let [path, before, after] = arguments else {
        return Err("usage: neo session compare FILE.jsonl CPU:SEQUENCE CPU:SEQUENCE".into());
    };
    let before_key = event_key(before)?;
    let after_key = event_key(after)?;
    let mut before = None;
    let mut after = None;
    visit_events(path, |event| {
        let key = (
            field(&event["context"], "cpu")?,
            field(&event["context"], "sequence")?,
        );
        if key == before_key {
            if before.is_some() {
                return Err("duplicate before event identity".into());
            }
            before = Some(event.clone());
        }
        if key == after_key {
            if after.is_some() {
                return Err("duplicate after event identity".into());
            }
            after = Some(event);
        }
        Ok(())
    })?;
    report(compare_events(
        &before.ok_or("before snapshot not found")?,
        &after.ok_or("after snapshot not found")?,
    )?)
}

pub(crate) fn export(mut arguments: Vec<String>) -> Result<i32, String> {
    let output = value(&mut arguments, "--output")?.ok_or("export requires --output DIRECTORY")?;
    let [path] = arguments.as_slice() else {
        return Err("usage: neo session export FILE.jsonl --output DIRECTORY".into());
    };
    let header: Value = serde_json::from_str(
        &BufReader::new(File::open(path).map_err(|error| error.to_string())?)
            .lines()
            .next()
            .ok_or("empty investigation")?
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let directory = Path::new(&output);
    std::fs::create_dir(directory)
        .map_err(|error| format!("cannot create export directory {output}: {error}"))?;
    let mut metadata = Vec::new();
    visit_events(path, |mut event| {
        Snapshot::parse(&event)?;
        let cpu = field(&event["context"], "cpu")?;
        let sequence = field(&event["context"], "sequence")?;
        let segments: Vec<Segment> =
            serde_json::from_value(event["segments"].clone()).map_err(|error| error.to_string())?;
        for (index, segment) in segments.into_iter().enumerate() {
            let bytes = segment
                .bytes
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    u8::from_str_radix(
                        std::str::from_utf8(pair).map_err(|error| error.to_string())?,
                        16,
                    )
                    .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if segment.pages.is_empty() && !bytes.is_empty() {
                return Err("binary export requires per-page snapshot metadata".into());
            }
            for (page_index, page) in segment.pages.iter().enumerate() {
                let name =
                    format!("cpu{cpu:02}-event{sequence:016x}-segment{index}-page{page_index}.bin");
                let mut binary = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(directory.join(&name))
                    .map_err(|error| error.to_string())?;
                binary
                    .write_all(&bytes[page.offset..page.offset + page.copied as usize])
                    .map_err(|error| error.to_string())?;
                event["segments"][index]["pages"][page_index]["buffer"] = json!(name);
            }
            event["segments"][index]
                .as_object_mut()
                .ok_or("invalid segment object")?
                .remove("bytes");
        }
        metadata.push(event);
        Ok(())
    })?;
    let count = metadata.len();
    let manifest = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("metadata.json"))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(
        manifest,
        &json!({"format": "matrixhv-event-export-v2", "process_atomic": false,
        "hash_algorithm": "sha256", "session": header, "events": metadata}),
    )
    .map_err(|error| error.to_string())?;
    report(json!({"output": output, "events": count, "metadata": "metadata.json"}))
}

pub(crate) fn run(arguments: &[String]) -> Result<i32, String> {
    let watch = arguments[0] == "watch";
    if arguments.len() < 2 {
        return Err("usage: neo session set|clear|record|query".into());
    }
    let mut operands = arguments[2..].to_vec();
    if !watch && arguments[1] == "compare" {
        return compare(&operands);
    }
    if !watch && arguments[1] == "export" {
        return export(operands);
    }
    if !watch && matches!(arguments[1].as_str(), "query" | "tree") {
        return query(operands, arguments[1] == "tree");
    }
    if !available()? {
        return Err("event snapshots require an updated MatrixHV EFI".into());
    }
    match arguments[1].as_str() {
        "set" if !watch => setup(&mut operands),
        "status" if !watch && operands.len() <= 1 => {
            let bytes = request(InterceptionRequest {
                operation: INTERCEPT_STATUS,
                ..Default::default()
            })?;
            if let Some(token) = operands.first()
                && memory::number(token)? != quad(&bytes, 80)
            {
                return Err("capture session token changed".into());
            }
            report(memory::interception_json(&bytes)?)
        }
        "fetch" if !watch && operands.len() == 4 => {
            let bytes = request(InterceptionRequest {
                operation: EVENT_FETCH,
                token: memory::number(&operands[0])?,
                cpu: memory::number(&operands[1])?
                    .try_into()
                    .map_err(|_| "invalid CPU")?,
                cursor: memory::number(&operands[2])?,
                count: memory::number(&operands[3])?
                    .try_into()
                    .map_err(|_| "invalid count")?,
                ..Default::default()
            })?;
            let batch = neo::memory::decode_event_batch(&bytes)?;
            let records = batch
                .records
                .into_iter()
                .map(decode)
                .collect::<Result<Vec<_>, _>>()?;
            report(
                json!({"token": output::hex(batch.token), "next": output::hex(batch.next), "oldest": output::hex(batch.oldest), "head": output::hex(batch.head),
                "dropped": output::hex(batch.dropped), "captured_hits": output::hex(batch.captured_hits), "records": records}),
            )
        }
        "clear" if !watch && operands.len() == 1 => {
            let bytes = request(InterceptionRequest {
                operation: EVENT_CLEAR,
                token: memory::number(&operands[0])?,
                ..Default::default()
            })?;
            report(memory::interception_json(&bytes)?)
        }
        "record" => record(operands, watch),
        _ => Err(
            "usage: neo session set|clear|record|query; neo watch record TOKEN --output FILE.jsonl"
                .into(),
        ),
    }
}

#[cfg(test)]
#[path = "../tests/investigation_tests.rs"]
mod tests;
