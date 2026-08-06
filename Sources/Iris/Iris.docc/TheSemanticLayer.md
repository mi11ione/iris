# The semantic layer

What every instruction tells you beyond its text: register dataflow, control flow, memory behavior and flag effects, as typed fields computed during decode.

## Register dataflow

``Instruction/semanticReads`` and ``Instruction/semanticWrites`` are ``RegisterSet`` bitmasks of the registers an instruction semantically touches, independent of alias presentation. `cmp w0, w1` is architecturally `subs wzr, w0, w1`: two reads, no writes. The zero register is not state, so iris never records it.

```swift
let cmp = decode(0x6B01001F)                 // cmp w0, w1
print(cmp.semanticReads.map(\.name))         // ["x0", "x1"]
print(cmp.semanticWrites.isEmpty)            // true
print(cmp.writesFlags)                       // true
```

Sets iterate as ``RegisterRef`` values at architectural width (`x0…x30`, `sp`, `v0…v31`), erasing the W/X display width, which is an operand-level fact. Bit 31 always means SP. The usual algebra is available: union, intersection, subtraction, subset and disjointness.

```swift
let stp = decode(0xA9BF7BFD)                 // stp x29, x30, [sp, #-16]!
print(stp.semanticReads.map(\.name))         // ["x29", "x30", "sp"]
print(stp.semanticWrites.map(\.name))        // ["sp"]  (pre-index writeback)
```

## Control flow

``Instruction/branchClass`` classifies every transfer: `direct`, `conditional`, `call`, `return`, `indirect`, `exception`. For direct transfers ``Instruction/branchTarget`` is the absolute resolved target, so callers never do label arithmetic. Indirect branches and exception generators resolve to `nil`, since their targets are register values or vectored.

```swift
let cbz = decode(0xB4000048, at: 0x1_0000)   // cbz x8, #8
print(cbz.branchClass)                       // conditional
print(cbz.branchTarget == 0x1_0008)          // true

let blr = decode(0xD63F0100)                 // blr x8
print(blr.isCall)                            // true
print(blr.branchTarget == nil)               // true
```

Address formation is separate: ``Instruction/pcRelativeTarget`` resolves ADR, ADRP (page math included) and PC-literal loads to the absolute data address.

```swift
let adrp = decode(0x90000008, at: 0x1_0000_4A2C)  // adrp x8, #0
print(adrp.pcRelativeTarget == 0x1_0000_4000)     // true
```

## Memory behavior

``Instruction/memoryAccess`` classifies the access (`load`, `store`, `atomic`, `exclusiveLoad`/`exclusiveStore`, `prefetch`) and ``Instruction/memoryOrdering`` carries the acquire/release bits. ``Instruction/readsMemory`` is true for loads, atomics and exclusive loads; a prefetch is not a read, being a hint that may access nothing.

```swift
let casal = decode(0xC8E0FC01)               // casal x0, x1, [x0]
print(casal.isAtomic)                        // true
print(casal.readsMemory && casal.writesMemory)            // true
print(casal.memoryOrdering == [.acquire, .release])       // true
```

## Flag effects

``Instruction/flagEffect`` records which of N, Z, C, V an instruction reads and writes, per flag. `adc` reads C but executes unconditionally, so it is not ``Instruction/isConditional``; that predicate covers instructions whose effect depends on a condition code or an encoded test.

```swift
let adc = decode(0x9A020020)                 // adc x0, x1, x2
print(adc.readsFlags)                        // true  (consumes C)
print(adc.isConditional)                     // false (always executes)

let csel = decode(0x9A821020)                // csel x0, x1, x2, ne
print(csel.isConditional)                    // true
```

## Scalable state (SVE / SME)

Predicate registers, the first-fault register, the `ZA` tile array and `ZT0` live in ``Instruction/scalableReads`` and ``Instruction/scalableWrites``. The `Zn` vectors stay in the ordinary register sets, as their `v` aliases.

```swift
let subr = decode(0x04C303E1)                // subr z1.d, p0/m, z1.d, z31.d
print(subr.semanticReads.map(\.name))        // ["v1", "v31"]
print(subr.scalableReads.isEmpty)            // false (p0 governs it)
```

``Instruction/scalableEffect`` carries what neither set can say: whether a write is partial (a predicated SVE write or a `ZA` tile-slice write leaves inactive lanes alone, so a dataflow pass must not treat it as a kill), the relationship to streaming mode and `ZA`-enable, and a scalable load's fault class.

```swift
let fmopa = decode(0x8080FC00)               // fmopa za0.s, p7/m, p7/m, z0.s, z0.s
print(fmopa.scalableWrites.isEmpty)          // false
print(fmopa.category)                        // sme
```

## Extension involvement

``Instruction/usesPointerAuthentication`` covers the fixed PAC mnemonic set, and ``Instruction/category`` attributes every record to its encoding family, so an extension census is one loop.

```swift
let words: [UInt32] = [0xD503233F, 0x9AC23020, 0xD65F03C0]
var pacSites = 0
for word in words where decode(word, features: .arm64e).usesPointerAuthentication {
    pacSites += 1
}
print(pacSites)                              // 2 (paciasp and pacga)
```

Each predicate documents what it does not claim. Where a classification is richer than a boolean, the typed field is the truth and the predicate is the convenience.
