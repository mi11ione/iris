// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `ScalableEffect`, the per-instruction flags carrying the SVE/SME
/// properties that are not register reads or writes.
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
        let all: ScalableEffect = [
            .partialWrite, .readsStreamingMode, .writesStreamingMode, .writesZAEnable,
            .firstFaulting, .nonFaulting, .nonTemporal,
        ]
        #expect(all.rawValue == 0b0111_1111)
        #expect(all.rawValue & 0b1000_0000 == 0)
    }

    @Test func theFaultAndTemporalFlagsAreMutuallyExclusiveInPractice() {
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
        let reserved = ScalableEffect(rawValue: 1 << 7)
        #expect(reserved.rawValue == 0b1000_0000)
        #expect(!reserved.contains(.partialWrite))
        #expect(!reserved.contains(.nonTemporal))
    }
}

/// Validates ScalableEffect's OptionSet algebra.
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
        let dependent = ScalableEffect.readsStreamingMode
        let transition = ScalableEffect.writesStreamingMode
        #expect(dependent != transition)
        #expect(!dependent.contains(.writesStreamingMode))
        #expect(!transition.contains(.readsStreamingMode))
    }

    @Test func smstartZAEffectSetsBothTransitionFlags() {
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

/// Pins ScalableEffect's layout.
@Suite("ScalableEffect / memory-layout invariant")
struct ScalableEffectLayoutTests {
    @Test func sizeIsExactlyOneByte() {
        #expect(MemoryLayout<ScalableEffect>.size == 1)
    }
}
