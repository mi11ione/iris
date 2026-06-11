# The semantic layer

What every instruction tells you beyond its text: register dataflow, control
flow, memory behavior, and flag effects, all bit-exact, alias-independent,
and precisely scoped.

## Overview

Most disassemblers hand you a string. The string is where analysis problems
*start*: which registers did `cmp w0, #0` actually read? Does `casal` write
memory, and with what ordering? Is `cbz` a branch you can resolve? Iris
answers these as typed fields on every ``Instruction``, computed during
decode and validated against external ground truth.

## Register dataflow

``Instruction/semanticReads`` and ``Instruction/semanticWrites`` are
``RegisterSet`` bitmasks of the architectural registers an instruction
semantically reads and writes, **independent of alias presentation**. The
alias `cmp w0, w1` is architecturally `subs wzr, w0, w1`: it reads two
registers and writes none. The zero register is not state, writes to it are
discarded, and Iris never records it:

```swift
let cmp = decode(0x6B01001F)                 // cmp w0, w1
print(cmp.semanticReads.map(\.name))         // ["x0", "x1"]
print(cmp.semanticWrites.isEmpty)            // true
print(cmp.writesFlags)                       // true
```

Register sets iterate as ``RegisterRef`` values at architectural width
(`x0…x30`, `sp`, `v0…v31`). The set deliberately erases the W/X display
width, which is an operand-level fact. Bit 31 always means SP, never the
zero register. The usual set algebra is available: union, intersection,
subtraction, subset and disjointness tests.

```swift
let stp = decode(0xA9BF7BFD)                 // stp x29, x30, [sp, #-16]!
print(stp.semanticReads.map(\.name))         // ["x29", "x30", "sp"]
print(stp.semanticWrites.map(\.name))        // ["sp"]  (pre-index writeback)
```

## Control flow

``Instruction/branchClass`` classifies every control-flow transfer:
`direct`, `conditional`, `call`, `return`, `indirect`, or `exception`. For
direct transfers, ``Instruction/branchTarget`` is the absolute resolved
target, `address + offset` modulo 2^64, so callers never do label
arithmetic. Indirect branches (`br`, `blr`, `ret`) and exception generators
(`svc`, `brk`) resolve to `nil`: their targets are register values or
vectored, and Iris does not guess.

```swift
let cbz = decode(0xB4000048, at: 0x1_0000)   // cbz x8, #8
print(cbz.branchClass)                       // conditional
print(cbz.branchTarget == 0x1_0008)          // true

let blr = decode(0xD63F0100)                 // blr x8
print(blr.isCall)                            // true
print(blr.branchTarget == nil)               // true (indirect, resolves to nil)
```

Address *formation* is separate from branching:
``Instruction/pcRelativeTarget`` resolves ADR, ADRP (page math included),
and PC-literal loads to the absolute data address they reference.

```swift
let adrp = decode(0x90000008, at: 0x1_0000_4A2C)  // adrp x8, #0
print(adrp.pcRelativeTarget == 0x1_0000_4000)     // true (page-aligned)
```

## Memory behavior

``Instruction/memoryAccess`` classifies the access (`load`, `store`,
`atomic` read-modify-write, `exclusiveLoad`/`exclusiveStore` monitor halves,
`prefetch`), and ``Instruction/memoryOrdering`` carries acquire/release
bits. The composable predicates are deliberately precise:
``Instruction/readsMemory`` is true for loads, atomics, and exclusive loads.
A prefetch is *not* a read (it is an architectural hint that may access
nothing).

```swift
let casal = decode(0xC8E0FC01)               // casal x0, x1, [x0]
print(casal.isAtomic)                        // true
print(casal.readsMemory && casal.writesMemory)            // true (RMW)
print(casal.memoryOrdering == [.acquire, .release])       // true
```

## Flag effects

``Instruction/flagEffect`` records which of N, Z, C, V the instruction reads
and writes, per flag. The booleans ``Instruction/readsFlags`` and
``Instruction/writesFlags`` are conveniences over it. Note the precision:
`adc` reads C but executes unconditionally, so it is *not*
``Instruction/isConditional``. That predicate covers instructions whose
architectural effect depends on a condition code or an encoded test
(`b.cond`, `cbz`, `csel`, `ccmp`).

```swift
let adc = decode(0x9A020020)                 // adc x0, x1, x2
print(adc.readsFlags)                        // true  (consumes C)
print(adc.isConditional)                     // false (always executes)

let csel = decode(0x9A821020)                // csel x0, x1, x2, ne
print(csel.isConditional)                    // true
```

## Extension involvement

``Instruction/usesPointerAuthentication`` covers the fixed PAC mnemonic set
(`pacia`/`autia` families, authenticated branches and returns, `ldraa`), and
``Instruction/category`` attributes every record to its encoding family,
including `pointerAuthentication`, `memoryTagging`, `crypto`, and `amx`,
which makes extension censuses one loop:

```swift
let words: [UInt32] = [0xD503233F, 0x9AC23020, 0xD65F03C0]
var pacSites = 0
for word in words where decode(word, features: .arm64e).usesPointerAuthentication {
    pacSites += 1
}
print(pacSites)                              // 2 (paciasp and pacga)
```

Every predicate's exact definition, including what it deliberately does
*not* claim, is documented on the predicate itself. Where classifications
are richer than a boolean, the typed field is the truth and the predicate is
the convenience.
