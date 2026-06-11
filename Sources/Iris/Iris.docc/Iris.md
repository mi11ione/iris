# ``Iris``

A pure-Swift ARM64/ARM64E disassembler with a semantic layer validated against LLVM.

## Overview

Iris turns ARM64 machine code into something you can reason about. Hand it a
4-byte instruction word or a whole code section and it returns a
structured, semantic record of every instruction. You get the mnemonic with
aliases canonically resolved, the operands, and the meaning itself: which
registers are read and written, how condition flags are affected, whether it
branches and how, how memory is touched and with what ordering. On top of
the records it produces canonical textual assembly.

```swift
import Iris

let instruction = decode(0xD65F03C0)
print(instruction.text)            // "ret"
print(instruction.isReturn)        // true
```

Three properties define the library. The semantic layer is built in: the
register read/write sets, branch classification, memory behavior, and flag
effects that every analysis tool otherwise has to rebuild come bit-exact
and independent of alias presentation. The library is pure Swift with zero
imports, not even Foundation, so it runs anywhere Swift compiles. And every
claim is proven: each decoded instruction is held to parity with LLVM's
`llvm-mc` over hundreds of millions of rows from real shipped code plus exhaustive encoding
sweeps, with the parity harness living in the same repository and
re-earning the claim on every change.

Iris is a disassembler: ARM64 only, decode only, one direction. The walls
are documented in <doc:ScopeAndGuarantees>.

Start with <doc:DecodeYourFirstInstruction>, then meet the semantics in
<doc:TheSemanticLayer>. Tool builders decoding real binaries should read
<doc:DisassemblingWithYourOwnLoader> and <doc:DataInCode>.

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
