//! Cache serialization and deserialization for compiled JIT code.

use std::collections::HashMap;
use std::io::{Read, Write, Cursor};
use std::path::Path;

use crate::cruby::*;
use crate::options::get_option;
use crate::payload::{IseqStatus, get_or_create_iseq_payload};
use crate::reloc::RelocKind;
use crate::state::ZJITState;

/// Magic bytes for the cache file header
const CACHE_MAGIC: &[u8; 4] = b"ZJIT";
/// Cache format version — bump when the format changes
const CACHE_VERSION: u32 = 1;

// Reloc kind tags for serialization
const RELOC_SELF_ISEQ: u8 = 0;
const RELOC_ISEQ_BYTECODE_OPERAND: u8 = 1;
const RELOC_CME: u8 = 2;
const RELOC_CLASS: u8 = 3;
const RELOC_GLOBAL_C_OBJECT: u8 = 4;
const RELOC_CONSTANT: u8 = 5;
const RELOC_CFUNC: u8 = 6;
const RELOC_ISEQ_BODY_OFFSET: u8 = 7;
const RELOC_COUNTER: u8 = 8;
const RELOC_EXIT_TRAMPOLINE: u8 = 9;
const RELOC_EXIT_TRAMPOLINE_WITH_COUNTER: u8 = 10;
const RELOC_FUNCTION_STUB_HIT_TRAMPOLINE: u8 = 11;
const RELOC_JIT_FRAME: u8 = 12;

/// Called when a method with an ISEQ is defined. If the cache has code for this
/// method, install it immediately so it's JIT-compiled from the first call.
/// Returns the code pointer if successful, or null if not cached.
#[unsafe(no_mangle)]
pub extern "C" fn rb_zjit_try_load_cached_code(iseq: IseqPtr) -> *const u8 {
    if !crate::state::zjit_enabled_p() { return std::ptr::null() };
    let Some(cache) = ZJITState::get_cache_index() else { return std::ptr::null() };

    with_vm_lock(src_loc!(), || {
        match try_install_cached_code(iseq, cache) {
            Some(code_ptr) => code_ptr,
            None => std::ptr::null(),
        }
    })
}

/// Dump all compiled ISEQs to the cache file.
/// Called from `at_exit` in zjit.rb when `--zjit-cache=path` is set.
#[unsafe(no_mangle)]
pub extern "C" fn rb_zjit_dump_cache(_ec: EcPtr, _self: VALUE) -> VALUE {
    let Some(cache_path) = get_option!(cache_path).as_ref() else {
        return Qnil;
    };

    if let Err(e) = dump_cache(cache_path) {
        eprintln!("ZJIT: Failed to dump cache to {}: {e}", cache_path.display());
    }
    Qnil
}

/// Return the cache path if --zjit-cache is set, else Qnil.
#[unsafe(no_mangle)]
pub extern "C" fn rb_zjit_get_cache_path_p(_ec: EcPtr, _self: VALUE) -> VALUE {
    // Builtin zjit.rb calls this even if ZJIT is disabled, so OPTIONS may not be set.
    if let Some(opts) = unsafe { crate::options::OPTIONS.as_ref() } {
        if let Some(ref path) = opts.cache_path {
            if let Some(s) = path.to_str() {
                return rust_str_to_ruby(s);
            }
        }
    }
    Qnil
}

// ========== Dump ==========

fn dump_cache(path: &Path) -> std::io::Result<()> {
    let cb = ZJITState::get_code_block();
    let mut entries: Vec<CacheEntryData> = Vec::new();

    for_each_iseq(|iseq| {
        let payload = get_or_create_iseq_payload(iseq);
        for version_ref in payload.versions.iter() {
            let version = unsafe { version_ref.as_ref() };

            let code_ptrs = match &version.status {
                IseqStatus::Compiled(ptrs) => ptrs,
                _ => continue,
            };

            let Some(end_ptr) = version.end_ptr else { continue };
            let start_ptr = code_ptrs.start_ptr;

            // Get ISEQ identity
            let iseq_path = unsafe { rb_iseq_path(iseq) };
            let iseq_label = unsafe { rb_iseq_label(iseq) };
            if iseq_path == Qnil || iseq_label == Qnil { continue; }

            // Copy code bytes
            let start_raw = start_ptr.raw_ptr(cb);
            let end_raw = end_ptr.raw_ptr(cb);
            let code_len = unsafe { end_raw.offset_from(start_raw) };
            if code_len <= 0 { continue; }
            let code_bytes = unsafe { std::slice::from_raw_parts(start_raw, code_len as usize) }.to_vec();

            let start_offset_val = start_ptr.as_offset();
            let jit_entry_offsets: Vec<u32> = code_ptrs.jit_entry_ptrs.iter()
                .map(|ptr| (ptr.as_offset() - start_offset_val) as u32)
                .collect();

            let reloc_entries: Vec<_> = version.reloc_entries.iter()
                .map(|entry| {
                    let rel_offset = (entry.offset.as_offset() - start_offset_val) as u32;
                    (rel_offset, entry.kind)
                })
                .collect();

            // Collect JIT-to-JIT call sites
            let call_sites: Vec<_> = version.outgoing.iter().filter_map(|iseq_call| {
                let callee_iseq = iseq_call.iseq.get();
                if callee_iseq.is_null() { return None; }
                let callee_path_val = unsafe { rb_iseq_path(callee_iseq) };
                let callee_label_val = unsafe { rb_iseq_label(callee_iseq) };
                if callee_path_val == Qnil || callee_label_val == Qnil { return None; }
                let cs_start = iseq_call.start_addr.get()?;
                let cs_end = iseq_call.end_addr.get()?;
                Some(CachedCallSite {
                    callee_path: ruby_str_to_rust_string(callee_path_val),
                    callee_label: ruby_str_to_rust_string(callee_label_val),
                    jit_entry_idx: iseq_call.jit_entry_idx,
                    start_offset: (cs_start.as_offset() - start_offset_val) as u32,
                    end_offset: (cs_end.as_offset() - start_offset_val) as u32,
                })
            }).collect();

            entries.push(CacheEntryData {
                path: ruby_str_to_rust_string(iseq_path),
                label: ruby_str_to_rust_string(iseq_label),
                code_bytes,
                jit_entry_offsets,
                reloc_entries,
                call_sites,
            });
        }
    });

    let mut file = std::fs::File::create(path)?;
    write_cache(&mut file, &entries)
}

struct CacheEntryData {
    path: String,
    label: String,
    code_bytes: Vec<u8>,
    jit_entry_offsets: Vec<u32>,
    reloc_entries: Vec<(u32, RelocKind)>,
    call_sites: Vec<CachedCallSite>,
}

/// A JIT-to-JIT call site within cached code
#[derive(Debug)]
struct CachedCallSite {
    /// Callee identity
    callee_path: String,
    callee_label: String,
    /// Which entry point in the callee
    jit_entry_idx: u16,
    /// The call instruction region (offsets relative to code start)
    start_offset: u32,
    end_offset: u32,
}

/// Builder for a global string table. Deduplicates strings and assigns indices.
struct StringTableBuilder {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl StringTableBuilder {
    fn new() -> Self { Self { strings: Vec::new(), index: HashMap::new() } }

    /// Intern a string, returning its index in the table.
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = self.strings.len() as u32;
        self.index.insert(s.to_string(), idx);
        self.strings.push(s.to_string());
        idx
    }
}

fn write_cache(w: &mut impl Write, entries: &[CacheEntryData]) -> std::io::Result<()> {
    // First pass: build the global string table
    let mut stab = StringTableBuilder::new();
    for entry in entries {
        stab.intern(&entry.path);
        stab.intern(&entry.label);
        for &(_, ref kind) in &entry.reloc_entries {
            match kind {
                RelocKind::CFunc { name } => { stab.intern(name); }
                RelocKind::Class { name } => { stab.intern(name); }
                _ => {}
            }
        }
        for cs in &entry.call_sites {
            stab.intern(&cs.callee_path);
            stab.intern(&cs.callee_label);
        }
    }

    // Header
    w.write_all(CACHE_MAGIC)?;
    w.write_all(&CACHE_VERSION.to_le_bytes())?;
    w.write_all(&target_arch_hash().to_le_bytes())?;

    // String table
    w.write_all(&(stab.strings.len() as u32).to_le_bytes())?;
    for s in &stab.strings {
        write_string(w, s)?;
    }

    // Entries
    w.write_all(&(entries.len() as u32).to_le_bytes())?;
    for entry in entries {
        // Identity (as string table indices)
        w.write_all(&stab.intern(&entry.path).to_le_bytes())?;
        w.write_all(&stab.intern(&entry.label).to_le_bytes())?;

        // Code bytes
        w.write_all(&(entry.code_bytes.len() as u32).to_le_bytes())?;
        w.write_all(&entry.code_bytes)?;

        // JIT entry offsets
        w.write_all(&(entry.jit_entry_offsets.len() as u32).to_le_bytes())?;
        for &offset in &entry.jit_entry_offsets {
            w.write_all(&offset.to_le_bytes())?;
        }

        // Relocation entries
        w.write_all(&(entry.reloc_entries.len() as u32).to_le_bytes())?;
        for &(offset, ref kind) in &entry.reloc_entries {
            w.write_all(&offset.to_le_bytes())?;
            write_reloc_kind(w, kind, &stab)?;
        }

        // Call sites
        w.write_all(&(entry.call_sites.len() as u32).to_le_bytes())?;
        for cs in &entry.call_sites {
            w.write_all(&stab.intern(&cs.callee_path).to_le_bytes())?;
            w.write_all(&stab.intern(&cs.callee_label).to_le_bytes())?;
            w.write_all(&cs.jit_entry_idx.to_le_bytes())?;
            w.write_all(&cs.start_offset.to_le_bytes())?;
            w.write_all(&cs.end_offset.to_le_bytes())?;
        }
    }
    Ok(())
}

fn write_reloc_kind(w: &mut impl Write, kind: &RelocKind, stab: &StringTableBuilder) -> std::io::Result<()> {
    match kind {
        RelocKind::SelfIseq => w.write_all(&[RELOC_SELF_ISEQ]),
        RelocKind::IseqBytecodeOperand => w.write_all(&[RELOC_ISEQ_BYTECODE_OPERAND]),
        RelocKind::CME => w.write_all(&[RELOC_CME]),
        RelocKind::Class { name } => {
            w.write_all(&[RELOC_CLASS])?;
            w.write_all(&stab.index[*name].to_le_bytes())
        }
        RelocKind::GlobalCObject => w.write_all(&[RELOC_GLOBAL_C_OBJECT]),
        RelocKind::Constant => w.write_all(&[RELOC_CONSTANT]),
        RelocKind::CFunc { name } => {
            w.write_all(&[RELOC_CFUNC])?;
            w.write_all(&stab.index[*name].to_le_bytes())
        }
        RelocKind::IseqBodyOffset { byte_offset } => {
            w.write_all(&[RELOC_ISEQ_BODY_OFFSET])?;
            w.write_all(&byte_offset.to_le_bytes())
        }
        RelocKind::Counter { counter_id } => {
            w.write_all(&[RELOC_COUNTER])?;
            w.write_all(&counter_id.to_le_bytes())
        }
        RelocKind::ExitTrampoline => w.write_all(&[RELOC_EXIT_TRAMPOLINE]),
        RelocKind::ExitTrampolineWithCounter => w.write_all(&[RELOC_EXIT_TRAMPOLINE_WITH_COUNTER]),
        RelocKind::FunctionStubHitTrampoline => w.write_all(&[RELOC_FUNCTION_STUB_HIT_TRAMPOLINE]),
        RelocKind::JITFrame { pc_offset, materialize_block_code } => {
            w.write_all(&[RELOC_JIT_FRAME])?;
            w.write_all(&pc_offset.to_le_bytes())?;
            w.write_all(&[*materialize_block_code as u8])
        }
    }
}

// ========== Load ==========

/// A cached ISEQ entry loaded from disk
#[derive(Debug)]
pub struct LoadedCacheEntry {
    pub code_bytes: Vec<u8>,
    pub jit_entry_offsets: Vec<u32>,
    pub reloc_entries: Vec<(u32, RelocKind)>,
    pub call_sites: Vec<CachedCallSite>,
}

/// The in-memory cache index, keyed by (path, label)
pub type CacheIndex = HashMap<(String, String), LoadedCacheEntry>;

/// Load the cache file and return an index. Returns None if the file doesn't exist or is invalid.
pub fn load_cache(path: &Path) -> Option<CacheIndex> {
    let data = std::fs::read(path).ok()?;
    let mut cursor = Cursor::new(data.as_slice());
    read_cache(&mut cursor)
}

fn read_cache(r: &mut Cursor<&[u8]>) -> Option<CacheIndex> {
    // Header
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).ok()?;
    if &magic != CACHE_MAGIC { return None; }

    let version = read_u32(r)?;
    if version != CACHE_VERSION { return None; }

    let arch = read_u32(r)?;
    if arch != target_arch_hash() { return None; }

    // Read global string table
    let string_count = read_u32(r)?;
    let mut strings: Vec<&'static str> = Vec::with_capacity(string_count as usize);
    for _ in 0..string_count {
        let s = read_string(r)?;
        strings.push(Box::leak(s.into_boxed_str()));
    }

    let entry_count = read_u32(r)?;
    let mut index = HashMap::new();

    for _ in 0..entry_count {
        let path_idx = read_u32(r)? as usize;
        let label_idx = read_u32(r)? as usize;
        if path_idx >= strings.len() || label_idx >= strings.len() { return None; }
        let path = strings[path_idx].to_string();
        let label = strings[label_idx].to_string();

        let code_len = read_u32(r)? as usize;
        let mut code_bytes = vec![0u8; code_len];
        r.read_exact(&mut code_bytes).ok()?;

        let jit_entry_count = read_u32(r)?;
        let mut jit_entry_offsets = Vec::with_capacity(jit_entry_count as usize);
        for _ in 0..jit_entry_count {
            jit_entry_offsets.push(read_u32(r)?);
        }

        let reloc_count = read_u32(r)?;
        let mut reloc_entries = Vec::with_capacity(reloc_count as usize);
        for _ in 0..reloc_count {
            let offset = read_u32(r)?;
            let kind = read_reloc_kind(r, &strings)?;
            reloc_entries.push((offset, kind));
        }

        // Call sites
        let call_site_count = read_u32(r)?;
        let mut call_sites = Vec::with_capacity(call_site_count as usize);
        for _ in 0..call_site_count {
            let cp_idx = read_u32(r)? as usize;
            let cl_idx = read_u32(r)? as usize;
            if cp_idx >= strings.len() || cl_idx >= strings.len() { return None; }
            call_sites.push(CachedCallSite {
                callee_path: strings[cp_idx].to_string(),
                callee_label: strings[cl_idx].to_string(),
                jit_entry_idx: read_u16(r)?,
                start_offset: read_u32(r)?,
                end_offset: read_u32(r)?,
            });
        }

        index.insert((path, label), LoadedCacheEntry {
            code_bytes,
            jit_entry_offsets,
            reloc_entries,
            call_sites,
        });
    }

    Some(index)
}

fn read_reloc_kind(r: &mut Cursor<&[u8]>, strings: &[&'static str]) -> Option<RelocKind> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag).ok()?;
    match tag[0] {
        RELOC_SELF_ISEQ => Some(RelocKind::SelfIseq),
        RELOC_ISEQ_BYTECODE_OPERAND => Some(RelocKind::IseqBytecodeOperand),
        RELOC_CME => Some(RelocKind::CME),
        RELOC_CLASS => {
            let idx = read_u32(r)? as usize;
            Some(RelocKind::Class { name: *strings.get(idx)? })
        }
        RELOC_GLOBAL_C_OBJECT => Some(RelocKind::GlobalCObject),
        RELOC_CONSTANT => Some(RelocKind::Constant),
        RELOC_CFUNC => {
            let idx = read_u32(r)? as usize;
            Some(RelocKind::CFunc { name: *strings.get(idx)? })
        }
        RELOC_ISEQ_BODY_OFFSET => {
            let byte_offset = read_u32(r)?;
            Some(RelocKind::IseqBodyOffset { byte_offset })
        }
        RELOC_COUNTER => {
            let counter_id = read_u32(r)?;
            Some(RelocKind::Counter { counter_id })
        }
        RELOC_EXIT_TRAMPOLINE => Some(RelocKind::ExitTrampoline),
        RELOC_EXIT_TRAMPOLINE_WITH_COUNTER => Some(RelocKind::ExitTrampolineWithCounter),
        RELOC_FUNCTION_STUB_HIT_TRAMPOLINE => Some(RelocKind::FunctionStubHitTrampoline),
        RELOC_JIT_FRAME => {
            let pc_offset = read_u32(r)?;
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag).ok()?;
            Some(RelocKind::JITFrame { pc_offset, materialize_block_code: flag[0] != 0 })
        }
        _ => None,
    }
}

// ========== Install ==========

/// Try to install cached code for the given ISEQ. Returns the entry code pointer on success.
pub fn try_install_cached_code(iseq: IseqPtr, cache: &CacheIndex) -> Option<*const u8> {
    let iseq_path_val = unsafe { rb_iseq_path(iseq) };
    let iseq_label_val = unsafe { rb_iseq_label(iseq) };
    if iseq_path_val == Qnil || iseq_label_val == Qnil { return None; }

    let path = ruby_str_to_rust_string(iseq_path_val);
    let label = ruby_str_to_rust_string(iseq_label_val);

    let entry = cache.get(&(path, label))?;

    // Pre-resolve all relocations before writing anything to the code block.
    // If any relocation fails, bail out cleanly.
    let iseq_body = unsafe { get_iseq_body_iseq_encoded(iseq) } as *const u8;
    let mut resolved_relocs: Vec<(u32, u64)> = Vec::with_capacity(entry.reloc_entries.len());
    for &(offset, ref kind) in &entry.reloc_entries {
        let resolved = resolve_reloc(iseq, iseq_body, kind);
        if resolved.is_none() {
            eprintln!("CACHE: failed to resolve reloc at offset {offset}: {kind:?}");
            return None;
        }
        resolved_relocs.push((offset, resolved.unwrap()));
    }

    let cb = ZJITState::get_code_block();

    // Copy code bytes into the code block
    let start_ptr = cb.get_write_ptr();
    for &byte in &entry.code_bytes {
        cb.write_byte(byte);
    }
    if cb.has_dropped_bytes() { return None; }

    let start_raw = start_ptr.raw_ptr(cb) as *mut u8;

    // Patch all resolved relocations
    for &(offset, value) in &resolved_relocs {
        let patch_addr = unsafe { start_raw.add(offset as usize) } as *mut u64;
        unsafe { patch_addr.write_unaligned(value); }
    }

    // Compute entry pointers
    let jit_entry_ptrs: Vec<_> = entry.jit_entry_offsets.iter()
        .map(|&off| start_ptr.add_bytes(off as usize))
        .collect();

    // Register with GC: walk reloc entries to find GC values and register their offsets
    let mut gc_offsets = Vec::new();
    for &(offset, ref kind) in &entry.reloc_entries {
        if is_gc_reloc(kind) {
            gc_offsets.push(start_ptr.add_bytes(offset as usize));
        }
    }

    // Create an IseqVersion and install it
    let mut version = crate::payload::IseqVersion::new(iseq);
    let code_ptrs = crate::payload::IseqCodePtrs { start_ptr, jit_entry_ptrs: jit_entry_ptrs.clone() };
    unsafe { version.as_mut() }.status = IseqStatus::Compiled(code_ptrs);
    unsafe { version.as_mut() }.end_ptr = Some(cb.get_write_ptr());

    // Register GC offsets
    crate::gc::append_gc_offsets(iseq, version, &gc_offsets);

    // Add to payload
    let payload = get_or_create_iseq_payload(iseq);
    payload.versions.push(version);

    // Patch JIT-to-JIT call sites.
    #[allow(clippy::needless_range_loop)]
    // Patch JIT-to-JIT call sites.
    // For self-recursive calls, we can resolve immediately using our own entry points.
    // For cross-method calls, we'd need the callee to be loaded already (TODO).
    // TODO: temporarily disabled while debugging relocation issues
    let self_path_val = unsafe { rb_iseq_path(iseq) };
    let self_label_val = unsafe { rb_iseq_label(iseq) };
    let self_path = ruby_str_to_rust_string(self_path_val);
    let self_label = ruby_str_to_rust_string(self_label_val);
    for cs in &entry.call_sites {
        let callee_entry_ptr = if cs.callee_path == self_path && cs.callee_label == self_label  {
            // Self-recursive call — use our own entry points
            let idx = cs.jit_entry_idx as usize;
            if idx < jit_entry_ptrs.len() {
                Some(jit_entry_ptrs[idx])
            } else {
                None
            }
        } else {
            // Cross-method call — check if callee is already loaded
            let callee_key = (cs.callee_path.clone(), cs.callee_label.clone());
            // TODO: look up callee in loaded ISEQs
            None
        };

        if let Some(callee_ptr) = callee_entry_ptr {
            // Regenerate the call site with the new callee address
            let cs_start = start_ptr.add_bytes(cs.start_offset as usize);
            let cs_end = start_ptr.add_bytes(cs.end_offset as usize);
            let callee_addr = callee_ptr.raw_ptr(cb);
            cb.with_write_ptr(cs_start, |cb| {
                let mut asm = crate::backend::lir::Assembler::new();
                asm.new_block_without_id("cache_relink");
                asm.ccall_into(crate::backend::lir::C_RET_OPND, callee_addr, vec![]);
                asm.compile(cb).expect("relink should fit in existing space");
                assert_eq!(cs_end, cb.get_write_ptr(), "relinked call site must be same size");
            });
        }
    }

    // Mark executable and invalidate icache for the loaded code region
    cb.mark_all_executable();
    let end_ptr = cb.get_write_ptr();
    unsafe { rb_jit_icache_invalidate(start_ptr.raw_ptr(cb) as _, end_ptr.raw_ptr(cb) as _) };

    // Install jit_entry on the ISEQ body
    let start_raw_ptr = start_ptr.raw_ptr(cb);
    Some(start_raw_ptr)
}

/// Resolve a relocation to a 64-bit value to patch into the code
fn resolve_reloc(iseq: IseqPtr, iseq_body: *const u8, kind: &RelocKind) -> Option<u64> {
    match kind {
        RelocKind::SelfIseq => Some(VALUE::from(iseq).as_u64()),
        RelocKind::IseqBodyOffset { byte_offset } => {
            Some(unsafe { iseq_body.add(*byte_offset as usize) } as u64)
        }
        RelocKind::CFunc { name } => resolve_cfunc(name).map(|p| p as u64),
        RelocKind::JITFrame { pc_offset, materialize_block_code } => {
            let pc = unsafe { iseq_body.add(*pc_offset as usize) } as *const VALUE;
            let jit_frame = crate::payload::JITFrame::new_iseq(pc, iseq, *materialize_block_code);
            Some(jit_frame as u64)
        }
        RelocKind::Class { name } => {
            // Skip anonymous classes
            if name.starts_with("#<") { return None; }
            let cstr = std::ffi::CString::new(*name).ok()?;
            unsafe extern "C" { fn rb_path2class(path: *const std::ffi::c_char) -> VALUE; }
            let class_val = unsafe { rb_path2class(cstr.as_ptr()) };
            if class_val == Qnil { return None; }
            Some(class_val.as_u64())
        }
        // TODO: resolve other reloc kinds (CME, GlobalCObject, Constant, etc.)
        _ => {
            None // Can't resolve — fall back to normal compilation
        }
    }
}

/// Check if a reloc kind represents a GC-managed VALUE that needs marking
fn is_gc_reloc(kind: &RelocKind) -> bool {
    matches!(kind, RelocKind::SelfIseq | RelocKind::IseqBytecodeOperand |
        RelocKind::CME | RelocKind::Class { .. } | RelocKind::GlobalCObject | RelocKind::Constant)
}

// Extern declarations for all C functions referenced by JIT code via asm_ccall!
// These are used by resolve_cfunc to map function names to addresses at load time.
unsafe extern "C" {
    fn rb_vm_send();
    fn rb_vm_sendforward();
    fn rb_vm_opt_send_without_block();
    fn rb_vm_invokesuper();
    fn rb_vm_invokesuperforward();
    fn rb_vm_invokeblock();
    fn rb_vm_objtostring();
    fn rb_vm_method_cfunc_is();
    fn rb_vm_splat_array();
    fn rb_vm_bh_to_procval();
    fn rb_vm_check_match();
    fn rb_vm_defined();
    fn rb_vm_env_write();
    fn rb_vm_get_ev_const();
    fn rb_vm_get_special_object();
    fn rb_vm_yield_with_cfunc();
    fn rb_vm_getinstancevariable();
    fn rb_vm_setinstancevariable();
    fn rb_vm_getclassvariable();
    fn rb_vm_setclassvariable();
    fn rb_vm_opt_getconstant_path();
    fn rb_ivar_get();
    fn rb_ivar_set();
    fn rb_gvar_get();
    fn rb_gvar_set();
    fn rb_obj_as_string_result();
    fn rb_obj_is_kind_of();
    fn rb_obj_alloc();
    fn rb_str_intern();
    fn rb_str_buf_append();
    fn rb_str_concat_literals();
    fn rb_str_setbyte();
    fn rb_jit_str_concat_codepoint();
    fn rb_yarv_str_eql_internal();
    fn rb_ec_str_resurrect();
    fn rb_fix_aref();
    fn rb_jit_fix_div_fix();
    fn rb_jit_fix_mod_fix();
    fn rb_ary_resurrect();
    fn rb_ary_push();
    fn rb_ary_pop();
    fn rb_ary_clear();
    fn rb_ary_concat();
    fn rb_ary_tmp_new_from_values();
    fn rb_ec_ary_new_from_values();
    fn rb_hash_resurrect();
    fn rb_hash_new_with_size();
    fn rb_hash_bulk_insert();
    fn rb_hash_aref();
    fn rb_hash_aset();
    fn rb_range_new();
    fn rb_backref_get();
    fn rb_reg_nth_match();
    fn rb_reg_last_match();
    fn rb_reg_match_last();
    fn rb_reg_match_pre();
    fn rb_reg_match_post();
    fn rb_reg_new_ary();
    fn rb_class_allocate_instance();
    fn rb_gc_writebarrier();
    fn rb_zjit_defined_ivar();
    fn rb_zjit_record_exit_stack();
}

/// Resolve a C function pointer by name.
fn resolve_cfunc(name: &str) -> Option<*const u8> {
    macro_rules! match_cfunc {
        ($name:expr, $( $func:ident ),+ $(,)?) => {
            match $name {
                $( stringify!($func) => Some($func as *const u8), )+
                _ => None,
            }
        }
    }

    let result = match_cfunc!(name,
        rb_vm_send, rb_vm_sendforward, rb_vm_opt_send_without_block,
        rb_vm_invokesuper, rb_vm_invokesuperforward, rb_vm_invokeblock,
        rb_vm_objtostring, rb_vm_method_cfunc_is, rb_vm_splat_array,
        rb_vm_bh_to_procval, rb_vm_check_match, rb_vm_defined,
        rb_vm_env_write, rb_vm_get_ev_const, rb_vm_get_special_object,
        rb_vm_yield_with_cfunc,
        rb_vm_getinstancevariable, rb_vm_setinstancevariable,
        rb_vm_getclassvariable, rb_vm_setclassvariable,
        rb_vm_opt_getconstant_path,
        rb_ivar_get, rb_ivar_set, rb_gvar_get, rb_gvar_set,
        rb_obj_as_string_result, rb_obj_is_kind_of, rb_obj_alloc,
        rb_str_intern, rb_str_buf_append, rb_str_concat_literals,
        rb_str_setbyte, rb_jit_str_concat_codepoint, rb_yarv_str_eql_internal,
        rb_ec_str_resurrect, rb_fix_aref, rb_jit_fix_div_fix, rb_jit_fix_mod_fix,
        rb_ary_resurrect, rb_ary_push, rb_ary_pop, rb_ary_clear, rb_ary_concat,
        rb_ary_tmp_new_from_values, rb_ec_ary_new_from_values,
        rb_hash_resurrect, rb_hash_new_with_size, rb_hash_bulk_insert,
        rb_hash_aref, rb_hash_aset,
        rb_range_new, rb_backref_get, rb_reg_nth_match,
        rb_reg_last_match, rb_reg_match_last, rb_reg_match_pre, rb_reg_match_post,
        rb_reg_new_ary, rb_class_allocate_instance, rb_gc_writebarrier,
        rb_zjit_defined_ivar, rb_zjit_record_exit_stack,
    );

    if result.is_none() {
        // Handle Rust aliases and internal functions
        use crate::codegen::exit_recompile;
        return match name {
            "exit_recompile" => Some(exit_recompile as *const u8),
            // Rust aliases for C functions (pub use X as Y in cruby.rs)
            "rb_fix_mod_fix" => Some(rb_jit_fix_mod_fix as *const u8),
            "rb_fix_div_fix" => Some(rb_jit_fix_div_fix as *const u8),
            _ => {
                eprintln!("ZJIT cache: unknown C function: {name}");
                None
            }
        };
    }
    result
}

// ========== Helpers ==========

fn write_string(w: &mut impl Write, s: &str) -> std::io::Result<()> {
    w.write_all(&(s.len() as u32).to_le_bytes())?;
    w.write_all(s.as_bytes())
}

fn read_string(r: &mut Cursor<&[u8]>) -> Option<String> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

fn read_u16(r: &mut Cursor<&[u8]>) -> Option<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).ok()?;
    Some(u16::from_le_bytes(buf))
}

fn read_u32(r: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).ok()?;
    Some(u32::from_le_bytes(buf))
}

fn target_arch_hash() -> u32 {
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" }
        else if cfg!(target_arch = "x86_64") { "x86_64" }
        else { "unknown" };
    let mut hash: u32 = 0;
    for b in arch.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    hash
}
