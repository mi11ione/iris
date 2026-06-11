// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates BranchClass — 7 mutually-exclusive control-flow classes
/// from `none` through `exception`, raw values 0..6 stable.
@Suite("BranchClass / raw values and exhaustive cases")
struct BranchClassTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(BranchClass.none.rawValue == 0)
        #expect(BranchClass.direct.rawValue == 1)
        #expect(BranchClass.indirect.rawValue == 2)
        #expect(BranchClass.conditional.rawValue == 3)
        #expect(BranchClass.call.rawValue == 4)
        #expect(BranchClass.return.rawValue == 5)
        #expect(BranchClass.exception.rawValue == 6)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 6 {
            let cls = BranchClass(rawValue: raw)
            #expect(cls != nil)
            #expect(cls?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(BranchClass(rawValue: 7) == nil)
        #expect(BranchClass(rawValue: 255) == nil)
    }
}

/// Validates MemoryAccess — 7 mutually-exclusive memory-effect
/// classes; `.atomic` is RMW (both load and store atomically).
@Suite("MemoryAccess / raw values and exhaustive cases")
struct MemoryAccessTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(MemoryAccess.none.rawValue == 0)
        #expect(MemoryAccess.load.rawValue == 1)
        #expect(MemoryAccess.store.rawValue == 2)
        #expect(MemoryAccess.atomic.rawValue == 3)
        #expect(MemoryAccess.exclusiveLoad.rawValue == 4)
        #expect(MemoryAccess.exclusiveStore.rawValue == 5)
        #expect(MemoryAccess.prefetch.rawValue == 6)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 6 {
            #expect(MemoryAccess(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(MemoryAccess(rawValue: 7) == nil)
    }
}

/// Validates MemoryOrdering — two-bit OptionSet for acquire / release
/// memory-ordering bits; covers empty, single bits, and union.
@Suite("MemoryOrdering / option-set bits")
struct MemoryOrderingTests {
    @Test func emptyHasZeroRaw() {
        #expect(MemoryOrdering().rawValue == 0)
    }

    @Test func acquireRawIsOne() {
        #expect(MemoryOrdering.acquire.rawValue == 1)
    }

    @Test func releaseRawIsTwo() {
        #expect(MemoryOrdering.release.rawValue == 2)
    }

    @Test func acquireReleaseUnion() {
        let both: MemoryOrdering = [.acquire, .release]
        #expect(both.rawValue == 3)
        #expect(both.contains(.acquire))
        #expect(both.contains(.release))
    }

    @Test func acquireDoesNotContainRelease() {
        #expect(!MemoryOrdering.acquire.contains(.release))
        #expect(!MemoryOrdering.release.contains(.acquire))
    }

    @Test func customRawValueRoundTrips() {
        let v = MemoryOrdering(rawValue: 0b11)
        #expect(v == [.acquire, .release])
    }

    @Test func descriptionRendersBracketedNames() {
        #expect(MemoryOrdering().description == "[]")
        #expect(MemoryOrdering.acquire.description == "[acquire]")
        #expect(MemoryOrdering.release.description == "[release]")
        #expect(([.acquire, .release] as MemoryOrdering).description == "[acquire, release]")
        #expect("\(MemoryOrdering.acquire)" == "[acquire]")
    }
}

/// Validates FlagEffect — a packed NZCV read/write bitmask (writes in bits
/// 0-3, reads in bits 4-7). Raw values + bit composition stable.
@Suite("FlagEffect / raw values and bit composition")
struct FlagEffectTests {
    @Test func noneRawIsZero() {
        #expect(FlagEffect.none.rawValue == 0)
    }

    @Test func nzcvIsTheFourWriteBits() {
        #expect(FlagEffect.nzcv.rawValue == 0b0000_1111)
    }

    @Test func readsNZCVIsTheFourReadBits() {
        #expect(FlagEffect.readsNZCV.rawValue == 0b1111_0000)
    }

    @Test func writeAndReadHalvesSeparateCleanly() {
        let rw: FlagEffect = [.nzcv, .readsC]
        #expect(rw.writtenFlags == .nzcv)
        #expect(rw.readFlags == [.readsC])
        #expect(rw.rawValue == 0b0100_1111)
    }

    @Test func rawValueRoundTrip() {
        #expect(FlagEffect(rawValue: 0) == FlagEffect.none)
        #expect(FlagEffect(rawValue: 0b0000_1111) == FlagEffect.nzcv)
        #expect(FlagEffect(rawValue: 0b1111_0000) == FlagEffect.readsNZCV)
    }
}

/// Validates Category — 12 cases covering the decoder sentinels plus
/// the per-family encoding attributions; raw values stable.
@Suite("Category / raw values and exhaustive cases")
struct CategoryTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(Iris.Category.undefined.rawValue == 0)
        #expect(Iris.Category.dataInCodeMarker.rawValue == 1)
        #expect(Iris.Category.truncatedTail.rawValue == 2)
        #expect(Iris.Category.dataProcessingImmediate.rawValue == 3)
        #expect(Iris.Category.branchesExceptionSystem.rawValue == 4)
        #expect(Iris.Category.dataProcessingRegister.rawValue == 5)
        #expect(Iris.Category.loadsAndStores.rawValue == 6)
        #expect(Iris.Category.simdAndFP.rawValue == 7)
        #expect(Iris.Category.pointerAuthentication.rawValue == 8)
        #expect(Iris.Category.crypto.rawValue == 9)
        #expect(Iris.Category.amx.rawValue == 10)
        #expect(Iris.Category.memoryTagging.rawValue == 11)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 11 {
            #expect(Iris.Category(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(Iris.Category(rawValue: 12) == nil)
    }
}

/// Validates ShiftKind — four register-shift kinds (LSL/LSR/ASR/ROR) plus
/// MSL (modified shift left, AdvSIMD modified-immediate only).
@Suite("ShiftKind / raw values and exhaustive cases")
struct ShiftKindTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(ShiftKind.lsl.rawValue == 0)
        #expect(ShiftKind.lsr.rawValue == 1)
        #expect(ShiftKind.asr.rawValue == 2)
        #expect(ShiftKind.ror.rawValue == 3)
        #expect(ShiftKind.msl.rawValue == 4)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 4 {
            #expect(ShiftKind(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(ShiftKind(rawValue: 5) == nil)
    }
}

/// Validates ExtendKind — none + 8 UXT/SXT extensions + the
/// degenerate LSL form used in some indexed addressing encodings.
@Suite("ExtendKind / raw values and exhaustive cases")
struct ExtendKindTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(ExtendKind.none.rawValue == 0)
        #expect(ExtendKind.uxtb.rawValue == 1)
        #expect(ExtendKind.uxth.rawValue == 2)
        #expect(ExtendKind.uxtw.rawValue == 3)
        #expect(ExtendKind.uxtx.rawValue == 4)
        #expect(ExtendKind.sxtb.rawValue == 5)
        #expect(ExtendKind.sxth.rawValue == 6)
        #expect(ExtendKind.sxtw.rawValue == 7)
        #expect(ExtendKind.sxtx.rawValue == 8)
        #expect(ExtendKind.lsl.rawValue == 9)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 9 {
            #expect(ExtendKind(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(ExtendKind(rawValue: 10) == nil)
    }
}

/// Validates Writeback — `.none`, `.preIndex`, `.postIndex` for the
/// three forms of base-register update on indexed load/store.
@Suite("Writeback / raw values and exhaustive cases")
struct WritebackTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(Writeback.none.rawValue == 0)
        #expect(Writeback.preIndex.rawValue == 1)
        #expect(Writeback.postIndex.rawValue == 2)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 2 {
            #expect(Writeback(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(Writeback(rawValue: 3) == nil)
    }
}

/// Validates ConditionCode — 16 raw values matching the 4-bit `cond`
/// field, including the distinct `.al` (always) and `.nv` (never) codes.
@Suite("ConditionCode / raw values and exhaustive cases")
struct ConditionCodeTests {
    @Test func everyCaseHasStableRawValue() {
        let expected: [(ConditionCode, UInt8)] = [
            (.eq, 0), (.ne, 1), (.cs, 2), (.cc, 3),
            (.mi, 4), (.pl, 5), (.vs, 6), (.vc, 7),
            (.hi, 8), (.ls, 9), (.ge, 10), (.lt, 11),
            (.gt, 12), (.le, 13), (.al, 14), (.nv, 15),
        ]
        for (cc, raw) in expected {
            #expect(cc.rawValue == raw)
        }
    }

    @Test func rawValueRoundTripCoversAllSixteen() {
        for raw: UInt8 in 0 ... 15 {
            #expect(ConditionCode(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(ConditionCode(rawValue: 16) == nil)
    }

    @Test func alAndNvAreDistinct() {
        #expect(ConditionCode.al != ConditionCode.nv)
    }
}

/// Validates FloatImmediateKind — half / single / double widths.
@Suite("FloatImmediateKind / raw values and exhaustive cases")
struct FloatImmediateKindTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(FloatImmediateKind.half.rawValue == 0)
        #expect(FloatImmediateKind.single.rawValue == 1)
        #expect(FloatImmediateKind.double.rawValue == 2)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 2 {
            #expect(FloatImmediateKind(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(FloatImmediateKind(rawValue: 3) == nil)
    }
}
