# ``Iris``

A pure-Swift ARM64/ARM64E disassembler with a semantic layer validated against LLVM.

## Overview

Hand iris a 4-byte word or a whole code section and it returns a structured record of every instruction: the mnemonic with aliases canonically resolved, the operands, and the semantics — registers read and written, how condition flags move, whether it branches and how, how memory is touched and with what ordering. Canonical assembly text renders on top.

```swift
import Iris

let instruction = decode(0xD65F03C0)
print(instruction.text)            // "ret"
print(instruction.isReturn)        // true
```

The semantic layer is built in, bit-exact and independent of alias presentation. The library imports nothing, not even Foundation. Every decoded instruction is held to parity with `llvm-mc` over hundreds of millions of rows from real shipped code plus exhaustive encoding sweeps, by a harness in the same repository that re-runs on every change.

Coverage runs from the base ISA through NEON and floating point, crypto, pointer authentication, MTE, Apple's AMX coprocessor, and the scalable tiers. SVE/SVE2 and SME/SME2 decode in full.

Start with <doc:DecodeYourFirstInstruction>, then <doc:TheSemanticLayer>. Tool builders decoding real binaries want <doc:DisassemblingWithYourOwnLoader> and <doc:DataInCode>. <doc:ScopeAndGuarantees> states what holds.

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

### Rendering text

- ``DisassemblyListing``
- ``TextBytes``
- ``Instruction/appendText(to:)``

### Text comparison and decoder utilities

- ``normalizeDisassembly(_:)``
- ``canonicalElementArrangement(for:)``
- ``decodeAdvSIMDModifiedImmediate(cmode:op:abcdefgh:)``
- ``signExtend9(_:)``
