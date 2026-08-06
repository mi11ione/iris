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

/// Validates the 32-bit-index gather loads.
@Suite("SVE memory / 32-bit gather loads")
struct SVE32BitGatherDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x8400_4000, .ld1b, "ld1b { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8440_4000, .ld1b, "ld1b { z0.s }, p0/z, [x0, z0.s, sxtw]"),
        (0x8420_C000, .ld1b, "ld1b { z0.s }, p0/z, [z0.s]"),
        (0x8421_C000, .ld1b, "ld1b { z0.s }, p0/z, [z0.s, #1]"),
        (0x84A0_4000, .ld1h, "ld1h { z0.s }, p0/z, [x0, z0.s, uxtw #1]"),
        (0x8400_0000, .ld1sb, "ld1sb { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8480_0000, .ld1sh, "ld1sh { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8500_4000, .ld1w, "ld1w { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8520_4000, .ld1w, "ld1w { z0.s }, p0/z, [x0, z0.s, uxtw #2]"),
        (0x8520_C000, .ld1w, "ld1w { z0.s }, p0/z, [z0.s]"),
    ]

    @Test func every32BitGatherFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .load)
        }
    }

    @Test func aVectorBaseGatherReadsOnlyTheIndexVector() {
        let d = decode(0x8420_D043)
        #expect(text(0x8420_D043) == "ld1b { z3.s }, p4/z, [z2.s]")
        #expect(canonicalIndices(d.semanticReads) == [34])
        #expect(canonicalIndices(d.semanticWrites) == [35])
    }
}

/// Validates the 64-bit-index gather loads (0xC4/0xC5).
@Suite("SVE memory / 64-bit gather loads")
struct SVE64BitGatherDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0xC400_4000, .ld1b, "ld1b { z0.d }, p0/z, [x0, z0.d, uxtw]"),
        (0xC440_C000, .ld1b, "ld1b { z0.d }, p0/z, [x0, z0.d]"),
        (0xC420_C000, .ld1b, "ld1b { z0.d }, p0/z, [z0.d]"),
        (0xC4E0_C000, .ld1h, "ld1h { z0.d }, p0/z, [x0, z0.d, lsl #1]"),
        (0xC4A0_4000, .ld1h, "ld1h { z0.d }, p0/z, [x0, z0.d, uxtw #1]"),
        (0xC5C0_C000, .ld1d, "ld1d { z0.d }, p0/z, [x0, z0.d]"),
        (0xC5E0_C000, .ld1d, "ld1d { z0.d }, p0/z, [x0, z0.d, lsl #3]"),
        (0xC500_0000, .ld1sw, "ld1sw { z0.d }, p0/z, [x0, z0.d, uxtw]"),
    ]

    @Test func every64BitGatherFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func quadwordGatherUsesAVectorBaseWithAScalarIndex() {
        let d = decode(0xC400_A000)
        #expect(d.mnemonic == .ld1q)
        #expect(text(0xC400_A000) == "ld1q { z0.q }, p0/z, [z0.d, x0]")
        #expect(text(0xC41F_A000) == "ld1q { z0.q }, p0/z, [z0.d]")
    }
}

/// Validates the first-fault gather loads.
@Suite("SVE memory / first-fault gather loads")
struct SVEGatherFirstFaultDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x8400_6000, .ldff1b, "ldff1b { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8400_2000, .ldff1sb, "ldff1sb { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0x8500_6000, .ldff1w, "ldff1w { z0.s }, p0/z, [x0, z0.s, uxtw]"),
        (0xC400_6000, .ldff1b, "ldff1b { z0.d }, p0/z, [x0, z0.d, uxtw]"),
        (0xC580_6000, .ldff1d, "ldff1d { z0.d }, p0/z, [x0, z0.d, uxtw]"),
        (0xC500_2000, .ldff1sw, "ldff1sw { z0.d }, p0/z, [x0, z0.d, uxtw]"),
    ]

    @Test func everyGatherFirstFaultFormTouchesFFR() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect.contains(.firstFaulting))
            #expect(d.scalableReads.containsFFR)
            #expect(d.scalableWrites.containsFFR)
        }
    }
}

/// Validates the vector-base non-temporal gather (`gldnt`, `LDNT1*` with a
/// `Zn.<T>` base).
@Suite("SVE memory / vector-base non-temporal gather")
struct SVEGatherNonTemporalDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x8400_A000, .ldnt1b, "ldnt1b { z0.s }, p0/z, [z0.s, x0]"),
        (0x841F_A000, .ldnt1b, "ldnt1b { z0.s }, p0/z, [z0.s]"),
        (0x8400_8000, .ldnt1sb, "ldnt1sb { z0.s }, p0/z, [z0.s, x0]"),
        (0x8500_A000, .ldnt1w, "ldnt1w { z0.s }, p0/z, [z0.s, x0]"),
        (0xC400_C000, .ldnt1b, "ldnt1b { z0.d }, p0/z, [z0.d, x0]"),
        (0xC580_C000, .ldnt1d, "ldnt1d { z0.d }, p0/z, [z0.d, x0]"),
        (0xC500_8000, .ldnt1sw, "ldnt1sw { z0.d }, p0/z, [z0.d, x0]"),
    ]

    @Test func everyGatherNonTemporalFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect.contains(.nonTemporal))
            #expect(!d.scalableReads.containsFFR)
        }
    }
}

/// Validates the scatter stores (0xE4/0xE5).
@Suite("SVE memory / scatter stores")
struct SVEScatterDecodeTests {
    private static let scatterSV: [(UInt32, Mnemonic, String)] = [
        (0xE400_8000, .st1b, "st1b { z0.d }, p0, [x0, z0.d, uxtw]"),
        (0xE400_A000, .st1b, "st1b { z0.d }, p0, [x0, z0.d]"),
        (0xE400_C000, .st1b, "st1b { z0.d }, p0, [x0, z0.d, sxtw]"),
        (0xE4A0_A000, .st1h, "st1h { z0.d }, p0, [x0, z0.d, lsl #1]"),
        (0xE500_8000, .st1w, "st1w { z0.d }, p0, [x0, z0.d, uxtw]"),
        (0xE520_A000, .st1w, "st1w { z0.d }, p0, [x0, z0.d, lsl #2]"),
        (0xE580_8000, .st1d, "st1d { z0.d }, p0, [x0, z0.d, uxtw]"),
    ]

    @Test func everyScatterScalarBaseFormDecodes() {
        for (encoding, mnemonic, expected) in Self.scatterSV {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .store)
        }
    }

    private static let scatterVI: [(UInt32, Mnemonic, String)] = [
        (0xE440_A000, .st1b, "st1b { z0.d }, p0, [z0.d]"),
        (0xE441_A000, .st1b, "st1b { z0.d }, p0, [z0.d, #1]"),
        (0xE541_A000, .st1w, "st1w { z0.d }, p0, [z0.d, #4]"),
    ]

    @Test func everyScatterVectorBaseFormDecodes() {
        for (encoding, mnemonic, expected) in Self.scatterVI {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func aScatterReadsBaseIndexAndData() {
        let d = decode(0xE502_9023)
        #expect(text(0xE502_9023) == "st1w { z3.d }, p4, [x1, z2.d, uxtw]")
        #expect(canonicalIndices(d.semanticReads) == [1, 34, 35])
        #expect(canonicalIndices(d.semanticWrites) == [])
    }

    @Test func quadwordScatterUsesAVectorBase() {
        #expect(decode(0xE420_2000).mnemonic == .st1q)
        #expect(text(0xE420_2000) == "st1q { z0.q }, p0, [z0.d, x0]")
        #expect(text(0xE43F_2000) == "st1q { z0.q }, p0, [z0.d]")
    }

    @Test func scatterNonTemporalCarriesTheFlag() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0xE400_2000, .stnt1b, "stnt1b { z0.d }, p0, [z0.d, x0]"),
            (0xE440_2000, .stnt1b, "stnt1b { z0.s }, p0, [z0.s, x0]"),
            (0xE500_2000, .stnt1w, "stnt1w { z0.d }, p0, [z0.d, x0]"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect.contains(.nonTemporal))
        }
    }
}

/// Validates the SVE prefetch family across all four addressing shapes.
@Suite("SVE memory / prefetch addressing forms")
struct SVEPrefetchDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x85C0_0000, .prfb, "prfb pldl1keep, p0, [x0]"),
        (0x85C1_0000, .prfb, "prfb pldl1keep, p0, [x0, #1, mul vl]"),
        (0x8500_C000, .prfw, "prfw pldl1keep, p0, [x0, x0, lsl #2]"),
        (0x8420_0000, .prfb, "prfb pldl1keep, p0, [x0, z0.s, uxtw]"),
        (0x8420_2000, .prfh, "prfh pldl1keep, p0, [x0, z0.s, uxtw #1]"),
        (0x8400_E000, .prfb, "prfb pldl1keep, p0, [z0.s]"),
        (0x8501_E000, .prfw, "prfw pldl1keep, p0, [z0.s, #4]"),
        (0xC420_0000, .prfb, "prfb pldl1keep, p0, [x0, z0.d, uxtw]"),
        (0xC460_A000, .prfh, "prfh pldl1keep, p0, [x0, z0.d, lsl #1]"),
        (0xC580_E000, .prfd, "prfd pldl1keep, p0, [z0.d]"),
    ]

    @Test func everyPrefetchFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .prefetch)
            #expect(d.semanticWrites == .empty)
        }
    }

    @Test func aGatherPrefetchReadsTheBaseAndIndex() {
        let d = decode(0xC420_0000)
        #expect(canonicalIndices(d.semanticReads) == [0, 32])
        #expect(d.scalableReads.containsPredicate(0))
    }

    @Test func aPrefetchWithHighBit4IsUndefined() {
        #expect(decode(0x85C0_0010).mnemonic == .undefined)
    }
}

/// Validates the load-and-replicate LD1R forms co-located in the gather region
/// (`sve_mem_ld_dup`).
@Suite("SVE memory / load-and-replicate single element")
struct SVEReplicateSingleDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x8440_8000, .ld1rb, "ld1rb { z0.b }, p0/z, [x0]"),
        (0x8440_E000, .ld1rb, "ld1rb { z0.d }, p0/z, [x0]"),
        (0x8441_8000, .ld1rb, "ld1rb { z0.b }, p0/z, [x0, #1]"),
        (0x84C0_A000, .ld1rh, "ld1rh { z0.h }, p0/z, [x0]"),
        (0x84C0_8000, .ld1rsw, "ld1rsw { z0.d }, p0/z, [x0]"),
        (0x8540_C000, .ld1rw, "ld1rw { z0.s }, p0/z, [x0]"),
        (0x85C0_E000, .ld1rd, "ld1rd { z0.d }, p0/z, [x0]"),
        (0x85C0_8000, .ld1rsb, "ld1rsb { z0.d }, p0/z, [x0]"),
        (0x8540_8000, .ld1rsh, "ld1rsh { z0.d }, p0/z, [x0]"),
    ]

    @Test func everyReplicateSingleFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.memoryAccess == .load)
        }
    }
}
