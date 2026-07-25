# ``Iris``

A pure-Swift ARM64/ARM64E disassembler with a semantic layer validated against LLVM.

## Overview

iris turns ARM64 machine code into something you can reason about. Hand it a 4-byte word or a whole code section and it returns a structured, semantic record of every instruction: the mnemonic with aliases canonically resolved, the operands, and the meaning itself — which registers are read and written, how condition flags move, whether it branches and how, how memory is touched and with what ordering. On top of the records it produces canonical textual assembly.

```swift
import Iris

let instruction = decode(0xD65F03C0)
print(instruction.text)            // "ret"
print(instruction.isReturn)        // true
```

Three properties define the library:

- **The semantic layer is built in.** Register read/write sets, branch classification, memory behavior, and flag effects — the layer every analysis tool otherwise rebuilds — come bit-exact and independent of alias presentation.
- **Zero imports.** Pure Swift, not even Foundation, so it runs anywhere Swift compiles.
- **Every claim is proven.** Each decoded instruction is held to parity with `llvm-mc` over hundreds of millions of rows from real shipped code, plus exhaustive encoding sweeps. The parity harness lives in the same repository and re-earns the claim on every change.

Coverage runs from the base ISA through NEON and floating point, crypto, pointer authentication, MTE, Apple's AMX coprocessor, and the scalable tiers — SVE/SVE2 and SME/SME2 decode in full, with no flag to set.

iris is a disassembler: ARM64 only, decode only, one direction. The walls are documented in <doc:ScopeAndGuarantees>.

Start with <doc:DecodeYourFirstInstruction>, then meet the semantics in <doc:TheSemanticLayer>. Tool builders decoding real binaries should read <doc:DisassemblingWithYourOwnLoader> and <doc:DataInCode>.

## Topics

### Getting started

- <doc:DecodeYourFirstInstruction>
- <doc:TheSemanticLayer>
- <doc:DisassemblingWithYourOwnLoader>
- <doc:DataInCode>
- <doc:ScopeAndGuarantees>

### The command-line tool

- <doc:JSONOutput>

### Essentials

- ``decode(_:at:features:)``
- ``Instruction``
- ``InstructionStream``
- ``Features``

### Packed storage and the performance tiers

- ``InstructionRecord``
- ``InstructionStream/Session``
- ``BorrowedInstruction``

### The semantic layer

- ``RegisterSet``
- ``RegisterRef``
- ``BranchClass``
- ``MemoryAccess``
- ``MemoryOrdering``
- ``FlagEffect``
- ``Category``
- ``Mnemonic``

### The scalable layer (SVE / SME)

- ``ScalableRegisterSet``
- ``ScalableEffect``
- ``ScalableVectorRef``
- ``ScalableVectorGroup``
- ``ScalablePredicateRef``
- ``PredicateQualifier``
- ``SVEPredicatePattern``
- ``ScalableMemoryOperand``
- ``ZATileMask``
- ``ZATileSliceOperand``
- ``ZAArrayVectorOperand``

### Operands

- ``Operand``
- ``MemoryOperand``
- ``MemoryBase``
- ``VectorRegisterRef``
- ``VectorArrangement``
- ``VectorView``
- ``ScalarSize``
- ``RegisterRole``
- ``RegisterWidth``
- ``ConditionCode``
- ``ShiftKind``
- ``ExtendKind``
- ``Writeback``
- ``FloatImmediateKind``
- ``AdvSIMDImmediateKind``

### System operands

- ``PSTATEField``
- ``BarrierOption``
- ``PrefetchOperation``
- ``SystemOp``
- ``SystemRegisterEncoding``
- ``AMXField``

### Loader seams and diagnostics

- ``DataInCodeSpan``
- ``Diagnostic``

### Text comparison and decoder utilities

- ``normalizeDisassembly(_:)``
- ``canonicalElementArrangement(for:)``
- ``decodeAdvSIMDModifiedImmediate(cmode:op:abcdefgh:)``
- ``signExtend9(_:)``
