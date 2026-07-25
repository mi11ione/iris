// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ScalableEffect — the per-instruction flags that carry the
/// SVE/SME properties which are not register reads or writes. The bit
/// positions are pinned: the flags ride on every ``InstructionRecord`` as a
/// one-byte field that Piece 4 reads directly, so a renumbering would
/// silently re-interpret every record. Bits 0-3 are the 2s.1 flags, bits 4-6
/// the 2s.5 SVE-load fault/temporal flags, and bit 7 stays reserved.
@Suite("ScalableEffect / flag bit positions and defaults")
struct ScalableEffectFlagTests {
    @Test func noneIsTheEmptySet() {
        #expect(ScalableEffect.none.rawValue == 0)
        #expect(ScalableEffect.none.isEmpty)
        #expect(ScalableEffect() == .none)
    }

    @Test func everyFlagHasItsPinnedBitPosition() {
        #expect(ScalableEffect.partialWrite.rawValue == 1 << 0)
        #expect(ScalableEffect.readsStreamingMode.rawValue == 1 << 1)
        #expect(ScalableEffect.writesStreamingMode.rawValue == 1 << 2)
        #expect(ScalableEffect.writesZAEnable.rawValue == 1 << 3)
        #expect(ScalableEffect.firstFaulting.rawValue == 1 << 4)
        #expect(ScalableEffect.nonFaulting.rawValue == 1 << 5)
        #expect(ScalableEffect.nonTemporal.rawValue == 1 << 6)
    }

    @Test func theSevenFlagsAreDistinct() {
        let flags: [ScalableEffect] = [
            .partialWrite, .readsStreamingMode, .writesStreamingMode, .writesZAEnable,
            .firstFaulting, .nonFaulting, .nonTemporal,
        ]
        #expect(Set(flags.map(\.rawValue)).count == flags.count)
    }

    @Test func theSevenFlagsFillBitsZeroThroughSixLeavingBitSevenReserved() {
        // 2s.1 owns bits 0-3; 2s.5's fault/temporal markers own bits 4-6. Bit 7
        // is the one remaining reserved slot for a later streaming-legality flag.
        let all: ScalableEffect = [
            .partialWrite, .readsStreamingMode, .writesStreamingMode, .writesZAEnable,
            .firstFaulting, .nonFaulting, .nonTemporal,
        ]
        #expect(all.rawValue == 0b0111_1111)
        #expect(all.rawValue & 0b1000_0000 == 0)
    }

    @Test func theFaultAndTemporalFlagsAreMutuallyExclusiveInPractice() {
        // A given load is first-fault, non-fault, non-temporal, or none — the
        // decoder sets at most one, but the type permits querying each.
        let firstFault = ScalableEffect.firstFaulting
        #expect(firstFault.contains(.firstFaulting))
        #expect(!firstFault.contains(.nonFaulting))
        #expect(!firstFault.contains(.nonTemporal))
        #expect(!firstFault.contains(.partialWrite))
    }

    @Test func rawValueInitRoundTrips() {
        for raw: UInt8 in [0, 1, 0b0111_1111, 0xFF] {
            #expect(ScalableEffect(rawValue: raw).rawValue == raw)
        }
    }

    @Test func theReservedHighBitSurvivesRoundTrip() {
        // Bit 7 is the only reserved slot; a raw value there is preserved, not
        // masked away — the type is a plain OptionSet over the byte.
        let reserved = ScalableEffect(rawValue: 1 << 7)
        #expect(reserved.rawValue == 0b1000_0000)
        #expect(!reserved.contains(.partialWrite))
        #expect(!reserved.contains(.nonTemporal))
    }
}

/// Validates ScalableEffect's OptionSet algebra — the composition a decoder
/// performs when classifying an instruction (a predicated ZA-slice write is
/// both a partial write and streaming-mode dependent) and the queries Piece 4
/// performs on the result.
@Suite("ScalableEffect / OptionSet composition and queries")
struct ScalableEffectCompositionTests {
    @Test func emptyEffectContainsNoFlag() {
        let none = ScalableEffect.none
        #expect(!none.contains(.partialWrite))
        #expect(!none.contains(.readsStreamingMode))
        #expect(!none.contains(.writesStreamingMode))
        #expect(!none.contains(.writesZAEnable))
    }

    @Test func arrayLiteralComposesFlags() {
        let effect: ScalableEffect = [.partialWrite, .readsStreamingMode]
        #expect(effect.contains(.partialWrite))
        #expect(effect.contains(.readsStreamingMode))
        #expect(!effect.contains(.writesStreamingMode))
        #expect(!effect.contains(.writesZAEnable))
        #expect(effect.rawValue == 0b011)
    }

    @Test func unionAccumulatesFlags() {
        let merged = ScalableEffect.partialWrite.union(.writesZAEnable)
        #expect(merged.contains(.partialWrite))
        #expect(merged.contains(.writesZAEnable))
        #expect(merged.rawValue == 0b1001)
    }

    @Test func insertAddsAFlagInPlace() {
        var effect = ScalableEffect.none
        effect.insert(.writesStreamingMode)
        #expect(effect.contains(.writesStreamingMode))
        #expect(effect == .writesStreamingMode)
    }

    @Test func removeClearsAFlag() {
        var effect: ScalableEffect = [.partialWrite, .writesZAEnable]
        effect.remove(.partialWrite)
        #expect(!effect.contains(.partialWrite))
        #expect(effect.contains(.writesZAEnable))
    }

    @Test func intersectionFindsSharedFlags() {
        let a: ScalableEffect = [.partialWrite, .readsStreamingMode]
        let b: ScalableEffect = [.readsStreamingMode, .writesZAEnable]
        #expect(a.intersection(b) == .readsStreamingMode)
    }

    @Test func streamingTransitionIsDistinctFromStreamingDependence() {
        // The channel deliberately separates "my semantics depend on
        // PSTATE.SM" from "I change PSTATE.SM" — a single boolean would
        // conflate them and Piece 4 could not find the mode boundaries.
        let dependent = ScalableEffect.readsStreamingMode
        let transition = ScalableEffect.writesStreamingMode
        #expect(dependent != transition)
        #expect(!dependent.contains(.writesStreamingMode))
        #expect(!transition.contains(.readsStreamingMode))
    }

    @Test func smstartZAEffectSetsBothTransitionFlags() {
        // SMSTART (no field qualifier) enters streaming mode AND enables ZA;
        // the SME decoder sets both bits on that record.
        let smstart: ScalableEffect = [.writesStreamingMode, .writesZAEnable]
        #expect(smstart.contains(.writesStreamingMode))
        #expect(smstart.contains(.writesZAEnable))
        #expect(!smstart.contains(.partialWrite))
    }

    @Test func equalEffectsHashEqual() {
        let a: ScalableEffect = [.partialWrite, .writesZAEnable]
        let b = ScalableEffect(rawValue: 0b1001)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Pins ScalableEffect's layout — one byte, matching FlagEffect's shape. The
/// field is the last byte of ``InstructionRecord``'s 57 meaningful bytes, so
/// a wider effect set would move the record's pinned size.
@Suite("ScalableEffect / memory-layout invariant")
struct ScalableEffectLayoutTests {
    @Test func sizeIsExactlyOneByte() {
        #expect(MemoryLayout<ScalableEffect>.size == 1)
    }
}
