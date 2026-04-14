# ZJIT Code Cache — Serialize and Reload Compiled JIT Code

## Context

ZJIT bakes raw pointers into generated machine code (C function pointers, Ruby VALUE objects, counters, ISEQ pointers, etc.). These are meaningless across process restarts. To avoid recompilation on every boot, we need to:

1. **Dump** compiled code + metadata at process exit
2. **Load** the cache at boot, index it
3. **Install** cached code at JIT trigger time, resolving relocations to live pointers

Step 1 (relocation plumbing for GC VALUEs) is already implemented. This plan covers the remaining work to get end-to-end dump/load working.

## Design Decisions

- **Dump trigger**: `at_exit` hook, activated by `--zjit-cache=path`
- **Load trigger**: At JIT compilation entry point (`rb_zjit_iseq_gen_entry_point`) — check cache before compiling
- **Failure mode**: If any relocation can't be resolved, discard and fall back to normal JIT
- **C function pointers**: Static lookup table (compile-time `match` mapping name → fn ptr)
- **ISEQ identity**: `(file_path, method_label)` tuple

## What Gets Serialized Per Compiled ISEQ

| State | Serialize? | Approach |
|-------|-----------|----------|
| Machine code bytes | Yes | Copy from CodeBlock (need to record `end_ptr` on IseqVersion) |
| Relocation entries | Yes | Expand to cover all pointer types (GC VALUEs, C funcs, ICs, counters, trampolines, JITFrames) |
| Invariant assumptions | Yes | Serialize `(kind, symbolic_key, patch_offset, exit_offset)`, re-register on load |
| JIT-to-JIT call stubs | Yes | Serialize `(callee_identity, entry_idx, stub_offsets)`, relink on load; if callee not yet loaded, register as pending |
| JITFrame metadata | Yes | Serialize `(pc_offset_from_iseq_body, materialize_block_code)`, reconstruct at load (ISEQ is always self) |
| Exit trampolines | Relocation only | Relink to freshly generated trampolines via reloc entries |
| Side exit data | Free | Part of code blob; PCs and VALUEs covered by existing relocs |
| Profile data | No (v1) | Re-profile from scratch if invalidated |

## Implementation Plan

### Phase 0: Add assertions to validate serialization assumptions

Before building serialization, add debug assertions to confirm assumptions we'll rely on:

**In `split_patch_point` (`zjit/src/codegen.rs:1031`):**
```rust
Invariant::NoEPEscape(iseq) => {
    debug_assert_eq!(iseq, unsafe { version.as_ref() }.iseq,
        "NoEPEscape invariant should always reference the self ISEQ");
    track_no_ep_escape_assumption(iseq, code_ptr, side_exit_ptr, version);
}
```

**In `gen_save_pc_for_gc` (`zjit/src/codegen.rs:2795`):**
```rust
debug_assert_eq!(state.iseq, jit.iseq,
    "JITFrame should always reference the self ISEQ");
```

Run the full test suite (`make -C build-arm zjit-test` + `make -C build-arm btest RUN_OPTS="--zjit"`) to confirm.

### Phase 1: Complete relocation tagging

Currently only GC VALUEs are tagged via `emit_load_gc_value`. We need to tag ALL embedded pointers.

**New `RelocKind` variants:**

```rust
pub enum RelocKind {
    // Existing (GC VALUE pointers):
    SelfIseq,
    IseqBytecodeOperand,
    CME,
    Class,
    GlobalCObject,
    Constant,

    // New (non-GC pointers embedded via const_ptr/UImm):
    /// C function pointer, resolved by name at load time
    CFunc { name: &'static str },
    /// Pointer into ISEQ bytecode body (IC, IVC, ICVARC, cd, pc)
    IseqBodyOffset { byte_offset: u32 },
    /// ZJIT stats counter, resolved by counter ID
    Counter { counter_id: u32 },
    /// Global exit trampoline
    ExitTrampoline,
    /// Global exit trampoline with counter
    ExitTrampolineWithCounter,
    /// Global function stub hit trampoline
    FunctionStubHitTrampoline,
    /// JITFrame pointer — reconstruct from (pc_offset, materialize_block_code)
    JITFrame { pc_offset: u32, materialize_block_code: bool },
}
```

**Tagging mechanism for non-GC pointers:** Use the same `value_relocs: HashMap<u64, RelocKind>` side-table keyed by pointer-as-u64. Extend backend emit to check the map for `UImm` operands (not just `Value` operands in `emit_load_gc_value`).

**Key codegen sites to tag:**
- `asm_ccall!` macro: extend to auto-tag function pointer as `CFunc { name: stringify!($fn_name) }`
- `Opnd::const_ptr(ic)` / `Opnd::const_ptr(cd)` / `Opnd::const_ptr(pc)`: tag as `IseqBodyOffset`
- `gen_incr_counter_ptr`: tag as `Counter`
- `Opnd::const_ptr(jit_frame)` in `gen_save_pc_for_gc` / `gen_push_frame`: tag as `JITFrame`
- Trampoline references: tag as `ExitTrampoline` / `FunctionStubHitTrampoline`

**Files**: `zjit/src/reloc.rs`, `zjit/src/codegen.rs`, `zjit/src/backend/lir.rs` (asm_ccall! macro), `zjit/src/backend/arm64/mod.rs`, `zjit/src/backend/x86_64/mod.rs`

### Phase 2: Record invariant assumptions for serialization

Currently invariants are registered via `pos_marker` callbacks in `split_patch_point` and stored only in the `Invariants` struct (not on `IseqVersion`). We need to also record them on `IseqVersion` for serialization.

**Add to `IseqVersion` (`zjit/src/payload.rs`):**
```rust
pub invariant_deps: Vec<SerializedInvariant>,
```

**Define `SerializedInvariant` (`zjit/src/reloc.rs` or new file):**
```rust
pub struct SerializedInvariant {
    pub kind: InvariantKind,
    pub patch_point_offset: u32,  // relative to code start
    pub side_exit_offset: u32,    // relative to code start
}

pub enum InvariantKind {
    BOPRedefined { klass: RedefinitionFlag, bop: ruby_basic_operators },
    MethodRedefined { class_name: String, method_id: ID },
    StableConstantNames { names: Vec<String> },
    NoTracePoint,
    NoEPEscape,  // always self ISEQ
    SingleRactorMode,
    NoSingletonClass { class_name: String },
    RootBoxOnly,
}
```

**In `split_patch_point`**: alongside registering with `Invariants`, also push a `SerializedInvariant` to the version's list.

**Files**: `zjit/src/reloc.rs`, `zjit/src/payload.rs`, `zjit/src/codegen.rs`

### Phase 3: Record JIT-to-JIT call sites for serialization

**Add to `IseqVersion` (`zjit/src/payload.rs`):**
```rust
pub call_sites: Vec<SerializedCallSite>,
```

```rust
pub struct SerializedCallSite {
    pub callee_path: String,
    pub callee_label: String,
    pub jit_entry_idx: u16,
    pub stub_start_offset: u32,  // relative to code start
    pub stub_end_offset: u32,
}
```

**In `gen_iseq_call`**: record each call site on the version.

**At load time**: for each call site, check if callee is already loaded. If yes, patch stub to call callee directly. If no, register as pending. When a callee loads, iterate pending callers and patch their stubs.

**Files**: `zjit/src/payload.rs`, `zjit/src/codegen.rs`, `zjit/src/cache.rs`

### Phase 4: Record code end pointer

Currently `IseqCodePtrs` stores `start_ptr` but not end. We need the end to know how many bytes to copy.

**Add `end_ptr: CodePtr` to `IseqVersion`**. Set it after `asm.compile()` returns using `cb.get_write_ptr()`.

**Files**: `zjit/src/payload.rs`, `zjit/src/codegen.rs`

### Phase 5: Cache file format and dump logic

**CLI option**: `--zjit-cache=path` in `zjit/src/options.rs`, stored as `pub cache_path: Option<PathBuf>`

**File format** (simple binary):
```
Header:
  magic: [u8; 4] = b"ZJIT"
  version: u32 = 1
  arch: u32 = hash of target triple
  entry_count: u32

Per-entry:
  identity: (path_len: u32, path_bytes, label_len: u32, label_bytes)
  code: (code_len: u32, code_bytes, start_offset: u32, jit_entry_count: u32, jit_entry_offsets: [u32])
  relocations: (count: u32, entries: [offset: u32, kind_tag: u8, kind_data: variable])
  invariants: (count: u32, entries: [kind_tag: u8, kind_data: variable, patch_offset: u32, exit_offset: u32])
  call_sites: (count: u32, entries: [callee_path, callee_label, entry_idx: u16, stub_start: u32, stub_end: u32])
```

**Dump flow** (`zjit/src/cache.rs` — new):
1. Called from `at_exit` in `zjit.rb` when `--zjit-cache` is set
2. Walk all ISEQs with compiled `IseqVersion`s
3. For each: read identity, copy code bytes (start_ptr..end_ptr), serialize reloc_entries + invariant_deps + call_sites
4. Write to cache file

**Files**: `zjit/src/cache.rs` (new), `zjit/src/lib.rs`, `zjit/src/options.rs`, `zjit.rb`

### Phase 6: Load and install logic

**Boot-time loading** (`cache.rs`):
1. In `ZJITState::init`: if `--zjit-cache` is set and file exists, read it
2. Parse header, validate arch
3. Build `HashMap<(String, String), CacheEntry>` keyed by `(path, label)`
4. Store on `ZJITState`

**Install at JIT trigger** (modify `rb_zjit_iseq_gen_entry_point` in `codegen.rs`):
1. Before compiling, check cache for `(path, label)`
2. Cache hit:
   a. Copy code bytes into CodeBlock
   b. Resolve each relocation entry:
      - `SelfIseq` → current ISEQ pointer
      - `IseqBytecodeOperand` → re-read from ISEQ bytecode
      - `CME` → re-lookup via class + method
      - `Class` → re-lookup by class path
      - `CFunc { name }` → static lookup table
      - `IseqBodyOffset { offset }` → ISEQ body pointer + offset
      - `Counter { id }` → `counter_ptr(counter)`
      - `ExitTrampoline` → `ZJITState::get_exit_trampoline()`
      - `FunctionStubHitTrampoline` → `ZJITState::get_function_stub_hit_trampoline()`
      - `JITFrame { pc_offset, materialize }` → allocate new JITFrame with resolved pointers
   c. Patch each pointer into the code
   d. Re-register invariant assumptions with the `Invariants` struct
   e. Create JIT-to-JIT stubs (point to trampoline; patch if callee already loaded)
   f. Register GC offsets
   g. Mark code executable, install on ISEQ
3. Any relocation fails → discard, fall through to normal compilation

**Pending callee linking**: Store a `HashMap<(String, String), Vec<PendingCallSite>>` on ZJITState. When a method loads from cache, check if anyone is waiting for it and patch their stubs.

**C function lookup table** (`cache.rs`):
```rust
fn resolve_cfunc(name: &str) -> Option<*const u8> {
    match name {
        "rb_vm_getinstancevariable" => Some(rb_vm_getinstancevariable as *const u8),
        // ... all functions used in asm_ccall!
        _ => None,
    }
}
```

**Files**: `zjit/src/cache.rs`, `zjit/src/codegen.rs`, `zjit/src/state.rs`

### Phase 7: Wire up at_exit hook

**`zjit.rb`**: Add `at_exit { dump_cache }` when cache path is set (parallel to existing stats at_exit)

**`zjit/src/cache.rs`**: Expose `rb_zjit_dump_cache` as `extern "C"` callable from Ruby builtin

**Files**: `zjit.rb`, `zjit/src/cache.rs`, `zjit/src/options.rs`

## Files to modify

| File | Change |
|------|--------|
| `zjit/src/reloc.rs` | Add CFunc, IseqBodyOffset, Counter, trampoline, JITFrame variants; add SerializedInvariant types |
| `zjit/src/cache.rs` | **NEW** — dump/load/install logic, C func lookup table, pending callee linking |
| `zjit/src/lib.rs` | Add `mod cache` |
| `zjit/src/options.rs` | Add `--zjit-cache=path` |
| `zjit/src/state.rs` | Store loaded cache index + pending callee map on ZJITState |
| `zjit/src/payload.rs` | Add `end_ptr`, `invariant_deps`, `call_sites` to IseqVersion |
| `zjit/src/codegen.rs` | Check cache before compiling; tag all const_ptr/ccall sites; record invariants + call sites; add assertions |
| `zjit/src/backend/lir.rs` | Extend asm_ccall! to auto-tag CFunc; check reloc map for UImm in emit |
| `zjit/src/backend/arm64/mod.rs` | Check reloc map for UImm operands during emission |
| `zjit/src/backend/x86_64/mod.rs` | Same |
| `zjit.rb` | Add at_exit dump_cache hook |

## Verification

1. `make -j -C build-arm miniruby` compiles
2. `make -C build-arm zjit-test` — existing tests pass
3. `make -C build-arm btest RUN_OPTS="--zjit"` — bootstrap tests pass
4. Phase 0 assertions hold across full test suite
5. Manual test: `./miniruby --zjit --zjit-cache=/tmp/zjit.cache -e "def foo; 1 + 1; end; 100.times { foo }"` dumps a cache file
6. Second run loads from cache, skips compilation, method works correctly
7. Cross-method test: method A calls method B, both cached, stubs get relinked
