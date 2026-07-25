// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the contiguous scalar-base LD1 loads (`sve_mem_cld_si` /
/// `sve_mem_cld_ss`) at 0xA4/0xA5: the `[Xn]` / `[Xn, #imm, mul vl]` immediate
/// and `[Xn, Xm{, lsl #k}]` register-offset addressing across the sign/size
/// dtype table, including the SVE2p1 128-bit `{Zt.q}` forms. The container
/// element (the `.<T>` on Zt) can be wider than the accessed element (a byte
/// load into a doubleword lane), and the register-offset `lsl` scale is the
/// accessed element size, so `ld1b` never carries an `lsl` while `ld1d` does.
@Suite("SVE memory / contiguous LD1 scalar-base loads")
struct SVEContiguousLoadDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xA400_A000, .ld1b, "ld1b { z0.b }, p0/z, [x0]"),
        (0xA401_A000, .ld1b, "ld1b { z0.b }, p0/z, [x0, #1, mul vl]"),
        (0xA400_4000, .ld1b, "ld1b { z0.b }, p0/z, [x0, x0]"), // byte access → no lsl
        (0xA460_4000, .ld1b, "ld1b { z0.d }, p0/z, [x0, x0]"), // container .d, byte access
        (0xA4A0_4000, .ld1h, "ld1h { z0.h }, p0/z, [x0, x0, lsl #1]"),
        (0xA480_4000, .ld1sw, "ld1sw { z0.d }, p0/z, [x0, x0, lsl #2]"),
        (0xA5E0_4000, .ld1d, "ld1d { z0.d }, p0/z, [x0, x0, lsl #3]"),
        (0xA5C0_4000, .ld1sb, "ld1sb { z0.h }, p0/z, [x0, x0]"),
        (0xA520_4000, .ld1sh, "ld1sh { z0.s }, p0/z, [x0, x0, lsl #1]"),
        (0xA540_4000, .ld1w, "ld1w { z0.s }, p0/z, [x0, x0, lsl #2]"),
        // SVE2p1 128-bit quadword container.
        (0xA510_2000, .ld1w, "ld1w { z0.q }, p0/z, [x0]"),
        (0xA500_8000, .ld1w, "ld1w { z0.q }, p0/z, [x0, x0, lsl #2]"),
        (0xA590_2000, .ld1d, "ld1d { z0.q }, p0/z, [x0]"),
    ]

    @Test func everyContiguousLoadFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .load)
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func aLoadReadsTheBaseAndWritesTheSingleVector() {
        let d = decode(0x8402_5023) // ld1b { z3.s }, p4/z, [x1, z2.s, uxtw] — distinct fields
        #expect(canonicalIndices(d.semanticReads) == [1, 34]) // X1 base + Z2 index
        #expect(canonicalIndices(d.semanticWrites) == [35]) // Z3 destination
        #expect(d.scalableReads.containsPredicate(4)) // Pg
    }

    @Test func aSingleVectorLoadRendersABracedList() {
        // Single-vector SVE loads render `{ Zt.<T> }`, never a bare `Zt`.
        #expect(text(0xA400_A000).contains("{ z0.b }"))
    }
}

/// Validates the first-fault (`LDFF1`) and non-fault (`LDNF1`) contiguous loads.
/// Both suppress a faulting access into the first-fault register rather than
/// taking it, so both read+write FFR and set the fault flag that disambiguates
/// them (`firstFaulting` vs `nonFaulting`); the base kind stays `.load`. LDFF1
/// keeps the `[Xn, Xm]` register form (with the `Rm=31` all-inactive `[Xn]`
/// special case), while LDNF1 is immediate-only.
@Suite("SVE memory / first-fault and non-fault loads")
struct SVEFaultLoadDecodeTests {
    @Test func firstFaultLoadsTouchFFRAndCarryTheFlag() {
        let d = decode(0xA400_6000) // ldff1b { z0.b }, p0/z, [x0, x0]
        #expect(d.mnemonic == .ldff1b)
        #expect(text(0xA400_6000) == "ldff1b { z0.b }, p0/z, [x0, x0]")
        #expect(d.memoryAccess == .load)
        #expect(d.scalableEffect.contains(.firstFaulting))
        #expect(!d.scalableEffect.contains(.nonFaulting))
        #expect(d.scalableReads.containsFFR)
        #expect(d.scalableWrites.containsFFR)
    }

    @Test func firstFaultWithRegister31RendersTheBaseOnlyForm() {
        // Rm=31: plain LD1 rejects `[Xn, xzr]`, but LDFF1 renders `[Xn]`.
        #expect(text(0xA41F_6000) == "ldff1b { z0.b }, p0/z, [x0]")
        #expect(decode(0xA41F_6000).mnemonic == .ldff1b)
    }

    @Test func nonFaultLoadsTouchFFRAndCarryTheOtherFlag() {
        let d = decode(0xA410_A000) // ldnf1b { z0.b }, p0/z, [x0]
        #expect(d.mnemonic == .ldnf1b)
        #expect(text(0xA410_A000) == "ldnf1b { z0.b }, p0/z, [x0]")
        #expect(d.scalableEffect.contains(.nonFaulting))
        #expect(!d.scalableEffect.contains(.firstFaulting))
        #expect(d.scalableReads.containsFFR)
        #expect(d.scalableWrites.containsFFR)
    }

    private static let faultForms: [(UInt32, Mnemonic, String)] = [
        (0xA4A0_6000, .ldff1h, "ldff1h { z0.h }, p0/z, [x0, x0, lsl #1]"),
        (0xA480_6000, .ldff1sw, "ldff1sw { z0.d }, p0/z, [x0, x0, lsl #2]"),
        (0xA5E0_6000, .ldff1d, "ldff1d { z0.d }, p0/z, [x0, x0, lsl #3]"),
        (0xA4B0_A000, .ldnf1h, "ldnf1h { z0.h }, p0/z, [x0]"),
        (0xA490_A000, .ldnf1sw, "ldnf1sw { z0.d }, p0/z, [x0]"),
        (0xA5F0_A000, .ldnf1d, "ldnf1d { z0.d }, p0/z, [x0]"),
    ]

    @Test func everyFaultFormDecodes() {
        for (encoding, mnemonic, expected) in Self.faultForms {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }
}

/// Validates the contiguous non-temporal loads and stores (`LDNT1`/`STNT1`) —
/// low-locality hints that carry the `nonTemporal` flag and do NOT touch FFR.
@Suite("SVE memory / contiguous non-temporal load and store")
struct SVEContiguousNonTemporalDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xA400_C000, .ldnt1b, "ldnt1b { z0.b }, p0/z, [x0, x0]"),
        (0xA400_E000, .ldnt1b, "ldnt1b { z0.b }, p0/z, [x0]"),
        (0xA401_E000, .ldnt1b, "ldnt1b { z0.b }, p0/z, [x0, #1, mul vl]"),
        (0xA480_C000, .ldnt1h, "ldnt1h { z0.h }, p0/z, [x0, x0, lsl #1]"),
        (0xA500_E000, .ldnt1w, "ldnt1w { z0.s }, p0/z, [x0]"),
        (0xA580_E000, .ldnt1d, "ldnt1d { z0.d }, p0/z, [x0]"),
        (0xE410_E000, .stnt1b, "stnt1b { z0.b }, p0, [x0]"),
        (0xE490_E000, .stnt1h, "stnt1h { z0.h }, p0, [x0]"),
        (0xE510_E000, .stnt1w, "stnt1w { z0.s }, p0, [x0]"),
        (0xE590_E000, .stnt1d, "stnt1d { z0.d }, p0, [x0]"),
    ]

    @Test func everyNonTemporalFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect.contains(.nonTemporal))
            #expect(!d.scalableReads.containsFFR, "non-temporal loads/stores never touch FFR")
        }
    }
}

/// Validates the load-and-replicate quadword (`LD1RQ`) and octoword (`LD1RO`,
/// F64MM) forms — the immediate is scaled by the replicate width (16 / 32
/// bytes) and the register-offset shift is the element size.
@Suite("SVE memory / load-and-replicate quadword and octoword")
struct SVEReplicateQuadDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xA400_2000, .ld1rqb, "ld1rqb { z0.b }, p0/z, [x0]"),
        (0xA400_0000, .ld1rqb, "ld1rqb { z0.b }, p0/z, [x0, x0]"),
        (0xA401_2000, .ld1rqb, "ld1rqb { z0.b }, p0/z, [x0, #16]"), // scaled by 16
        (0xA480_0000, .ld1rqh, "ld1rqh { z0.h }, p0/z, [x0, x0, lsl #1]"),
        (0xA500_2000, .ld1rqw, "ld1rqw { z0.s }, p0/z, [x0]"),
        (0xA580_2000, .ld1rqd, "ld1rqd { z0.d }, p0/z, [x0]"),
        (0xA421_2000, .ld1rob, "ld1rob { z0.b }, p0/z, [x0, #32]"), // scaled by 32
        (0xA4A0_0000, .ld1roh, "ld1roh { z0.h }, p0/z, [x0, x0, lsl #1]"),
        (0xA520_2000, .ld1row, "ld1row { z0.s }, p0/z, [x0]"),
        (0xA5A0_2000, .ld1rod, "ld1rod { z0.d }, p0/z, [x0]"),
    ]

    @Test func everyReplicateFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(decode(encoding).memoryAccess == .load)
        }
    }
}

/// Validates the structured interleaving loads and stores (LD2-4 / ST2-4, plus
/// the SVE2p1 quadword LD2Q-4Q / ST2Q-4Q). The register group is the load-bearing
/// operand: a pair renders `{ z0.b, z1.b }`, three or more render the compact
/// range `{ z0.b - z2.b }`, and the whole group is written (load) or read
/// (store). The immediate is scaled by the vector count.
@Suite("SVE memory / structured interleaving load and store")
struct SVEStructuredMemDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xA420_E000, .ld2b, "ld2b { z0.b, z1.b }, p0/z, [x0]"),
        (0xA421_E000, .ld2b, "ld2b { z0.b, z1.b }, p0/z, [x0, #2, mul vl]"), // ×2 scale
        (0xA440_E000, .ld3b, "ld3b { z0.b - z2.b }, p0/z, [x0]"),
        (0xA460_E000, .ld4b, "ld4b { z0.b - z3.b }, p0/z, [x0]"),
        (0xA520_E000, .ld2w, "ld2w { z0.s, z1.s }, p0/z, [x0]"),
        (0xA490_E000, .ld2q, "ld2q { z0.q, z1.q }, p0/z, [x0]"),
        (0xA510_E000, .ld3q, "ld3q { z0.q - z2.q }, p0/z, [x0]"),
        (0xE430_E000, .st2b, "st2b { z0.b, z1.b }, p0, [x0]"),
        (0xE450_E000, .st3b, "st3b { z0.b - z2.b }, p0, [x0]"),
        (0xE470_E000, .st4b, "st4b { z0.b - z3.b }, p0, [x0]"),
        (0xE440_0000, .st2q, "st2q { z0.q, z1.q }, p0, [x0]"),
        (0xE4C0_0000, .st4q, "st4q { z0.q - z3.q }, p0, [x0]"),
    ]

    @Test func everyStructuredFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func aStructuredLoadWritesTheWholeGroup() {
        let d = decode(0xA423_D022) // ld2b { z2.b, z3.b }, p4/z, [x1, x3]
        #expect(text(0xA423_D022) == "ld2b { z2.b, z3.b }, p4/z, [x1, x3]")
        #expect(canonicalIndices(d.semanticWrites) == [34, 35]) // Z2, Z3
        #expect(canonicalIndices(d.semanticReads) == [1, 3]) // base + scalar index
    }

    @Test func aStructuredStoreReadsTheWholeGroupAndWritesNothing() {
        let d = decode(0xE430_E000) // st2b { z0.b, z1.b }, p0, [x0]
        #expect(canonicalIndices(d.semanticWrites) == [])
        #expect(canonicalIndices(d.semanticReads) == [0, 32, 33]) // base + Z0 + Z1
    }
}

/// Validates the contiguous scalar-base stores (`ST1`), including the SVE2p1
/// 128-bit `{Zt.q}` forms, and confirms a store reads its data + address and
/// writes no register.
@Suite("SVE memory / contiguous ST1 stores")
struct SVEContiguousStoreDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xE400_E000, .st1b, "st1b { z0.b }, p0, [x0]"),
        (0xE401_E000, .st1b, "st1b { z0.b }, p0, [x0, #1, mul vl]"),
        (0xE400_4000, .st1b, "st1b { z0.b }, p0, [x0, x0]"),
        (0xE4A0_4000, .st1h, "st1h { z0.h }, p0, [x0, x0, lsl #1]"),
        (0xE540_4000, .st1w, "st1w { z0.s }, p0, [x0, x0, lsl #2]"),
        (0xE5E0_4000, .st1d, "st1d { z0.d }, p0, [x0, x0, lsl #3]"),
        (0xE500_E000, .st1w, "st1w { z0.q }, p0, [x0]"), // 128-bit container
        (0xE5C0_E000, .st1d, "st1d { z0.q }, p0, [x0]"),
    ]

    @Test func everyContiguousStoreFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .store)
        }
    }

    @Test func aStoreReadsItsDataAndAddressAndWritesNothing() {
        let d = decode(0xE402_5023) // st1b { z3.b }, p4, [x1, x2]
        #expect(text(0xE402_5023) == "st1b { z3.b }, p4, [x1, x2]")
        #expect(canonicalIndices(d.semanticReads) == [1, 2, 35]) // base + scalar index + data
        #expect(canonicalIndices(d.semanticWrites) == [])
    }
}

/// Validates the LDR/STR register fill/spill forms — the whole-register move of
/// a `Z` or `P` register to/from memory with a 9-bit `mul vl` displacement. The
/// data register renders with no element suffix (`z0`, `p0`); LDR writes the
/// register, STR reads it, and the `P` form rides the scalable register file
/// while the `Z` form rides the shared SIMD bit.
@Suite("SVE memory / LDR and STR register fill and spill")
struct SVEFillSpillDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x8580_0000, .ldr, "ldr p0, [x0]"),
        (0x8580_0400, .ldr, "ldr p0, [x0, #1, mul vl]"),
        (0x8580_4000, .ldr, "ldr z0, [x0]"),
        (0x8580_4400, .ldr, "ldr z0, [x0, #1, mul vl]"),
        (0xE580_0000, .str, "str p0, [x0]"),
        (0xE580_4000, .str, "str z0, [x0]"),
    ]

    @Test func everyFillSpillFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func fillWritesTheVectorAndSpillReadsIt() {
        let ldr = decode(0x8580_5461) // ldr z1, [x3, #5, mul vl]
        #expect(text(0x8580_5461) == "ldr z1, [x3, #5, mul vl]")
        #expect(ldr.memoryAccess == .load)
        #expect(canonicalIndices(ldr.semanticReads) == [3]) // base only
        #expect(canonicalIndices(ldr.semanticWrites) == [33]) // Z1 filled

        let str = decode(0xE580_5461) // str z1, [x3, #5, mul vl]
        #expect(str.memoryAccess == .store)
        #expect(canonicalIndices(str.semanticReads) == [3, 33]) // base + Z1 data
        #expect(canonicalIndices(str.semanticWrites) == [])
    }

    @Test func thePredicateFillRidesTheScalableRegisterFile() {
        let ldr = decode(0x8580_0000) // ldr p0, [x0]
        #expect(ldr.scalableWrites.containsPredicate(0))
        #expect(canonicalIndices(ldr.semanticWrites) == []) // not on the SIMD bit
        let str = decode(0xE580_0000) // str p0, [x0]
        #expect(str.scalableReads.containsPredicate(0))
    }
}

/// Validates that reserved memory encodings — an out-of-range structured vector
/// count, a reserved store dtype — decode to a well-formed UNDEFINED.
@Suite("SVE memory / reserved contiguous holes")
struct SVEContiguousHoleDecodeTests {
    @Test func reservedContiguousEncodingsAreUndefined() {
        for encoding: UInt32 in [
            0xE400_0000, // store structured with nregs=0
            0xA4C0_8000, // contiguous-load reserved marker
            0xA400_8000, // contiguous-load reserved marker
        ] {
            let d = decode(encoding)
            #expect(d.mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
            #expect(d.category == .sve)
            #expect(d.operands.isEmpty)
        }
    }
}
