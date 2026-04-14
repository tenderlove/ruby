use crate::hir::Invariant;
use crate::virtualmem::CodePtr;

/// What a relocated pointer represents, so it can be re-resolved at load time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    // === GC VALUE pointers (go through emit_load_gc_value) ===

    /// The ISEQ this compiled code belongs to (jit.iseq passed to VM helpers)
    SelfIseq,
    /// A VALUE read from ISEQ bytecode operands (frozen strings, block ISEQs)
    IseqBytecodeOperand,
    /// A callable method entry for a guard
    CME,
    /// A class object for a type guard, with the class name for resolution at load time.
    /// The name is set during serialization; during compilation it starts as empty and
    /// gets filled in at dump time from the VALUE in the code bytes.
    Class { name: &'static str },
    /// A well-known global C object (rb_cArray, rb_mRubyVMFrozenCore, etc.)
    GlobalCObject,
    /// A resolved constant cache value
    Constant,

    // === Non-GC pointers (embedded via const_ptr/UImm) ===

    /// C function pointer, resolved by name at load time
    CFunc { name: &'static str },
    /// Pointer into ISEQ bytecode body (IC, IVC, ICVARC, cd, pc).
    /// byte_offset is relative to the start of the ISEQ body's encoded instructions.
    IseqBodyOffset { byte_offset: u32 },
    /// ZJIT stats counter, resolved by counter ID at load time
    Counter { counter_id: u32 },
    /// Global exit trampoline (ZJITState::get_exit_trampoline)
    ExitTrampoline,
    /// Global exit trampoline with counter (ZJITState::get_exit_trampoline_with_counter)
    ExitTrampolineWithCounter,
    /// Global function stub hit trampoline (ZJITState::get_function_stub_hit_trampoline)
    FunctionStubHitTrampoline,
    /// JITFrame pointer — reconstruct at load time from pc_offset + materialize_block_code.
    /// The ISEQ is always self (verified by assertion in gen_prepare_non_leaf_call).
    JITFrame { pc_offset: u32, materialize_block_code: bool },
}

/// One relocation record: where in the generated code a pointer lives, and what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocEntry {
    pub offset: CodePtr,
    pub kind: RelocKind,
}

/// An invariant assumption that compiled code depends on, recorded for serialization.
/// At load time, these are re-registered with the Invariants struct so that invalidation
/// still works for cached code.
#[derive(Clone, Copy, Debug)]
pub struct InvariantDep {
    /// The invariant assumption (contains live pointers — converted to symbolic form at dump time)
    pub invariant: Invariant,
    /// Offset of the patch point within the compiled code (relative to code start)
    pub patch_point_offset: CodePtr,
    /// Offset of the side exit within the compiled code (relative to code start)
    pub side_exit_offset: CodePtr,
}
