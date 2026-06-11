// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates BarrierOption — the architectural memory-barrier options
/// for DSB/DMB/ISB, including the rejected reserved encodings.
@Suite("BarrierOption / architectural option bits")
struct BarrierOptionRawTests {
    @Test func everyNamedCaseHasStableRawValue() {
        #expect(BarrierOption.oshld.rawValue == 0b0001)
        #expect(BarrierOption.oshst.rawValue == 0b0010)
        #expect(BarrierOption.osh.rawValue == 0b0011)
        #expect(BarrierOption.nshld.rawValue == 0b0101)
        #expect(BarrierOption.nshst.rawValue == 0b0110)
        #expect(BarrierOption.nsh.rawValue == 0b0111)
        #expect(BarrierOption.ishld.rawValue == 0b1001)
        #expect(BarrierOption.ishst.rawValue == 0b1010)
        #expect(BarrierOption.ish.rawValue == 0b1011)
        #expect(BarrierOption.ld.rawValue == 0b1101)
        #expect(BarrierOption.st.rawValue == 0b1110)
        #expect(BarrierOption.sy.rawValue == 0b1111)
    }

    @Test func rawValueRoundTripForEveryNamedCase() {
        let valid: [UInt8] = [0b0001, 0b0010, 0b0011, 0b0101, 0b0110, 0b0111,
                              0b1001, 0b1010, 0b1011, 0b1101, 0b1110, 0b1111]
        for raw in valid {
            #expect(BarrierOption(rawValue: raw)?.rawValue == raw)
        }
    }
}

/// Validates BarrierOption.init?(rawOptionBits:) including the four
/// architecturally-reserved nibble values that return nil.
@Suite("BarrierOption / init from raw option bits")
struct BarrierOptionInitTests {
    @Test func everyNamedNibbleConstructsCorrectly() {
        let valid: [(UInt8, BarrierOption)] = [
            (0b0001, .oshld), (0b0010, .oshst), (0b0011, .osh),
            (0b0101, .nshld), (0b0110, .nshst), (0b0111, .nsh),
            (0b1001, .ishld), (0b1010, .ishst), (0b1011, .ish),
            (0b1101, .ld), (0b1110, .st), (0b1111, .sy),
        ]
        for (raw, expected) in valid {
            #expect(BarrierOption(rawOptionBits: raw) == expected)
        }
    }

    @Test func reservedNibblesReturnNil() {
        let reserved: [UInt8] = [0b0000, 0b0100, 0b1000, 0b1100]
        for raw in reserved {
            #expect(BarrierOption(rawOptionBits: raw) == nil)
        }
    }

    @Test func highBitsAreMaskedAway() {
        // 0xF1 truncates to 0b0001 == .oshld; high nibble must be ignored.
        #expect(BarrierOption(rawOptionBits: 0xF1) == .oshld)
        #expect(BarrierOption(rawOptionBits: 0xFF) == .sy)
    }
}
