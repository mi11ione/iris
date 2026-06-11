// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Pins the 36 Mnemonic raw-value constants the DPI family owns,
/// in the reserved 256..1023 slab `Mnemonic.allocations` declares. The
/// allocation requires uniqueness + range-membership; both are checked
/// here at constant time.
@Suite("DPI / Mnemonic constants 256..299")
struct DPIMnemonicConstantsTests {
    /// The family's allocation table — base mnemonics + alias mnemonics with their locked raw values.
    private static let allDPIMnemonics: [(Mnemonic, UInt16, String)] = [
        (.add, 256, "add"), (.adds, 257, "adds"), (.sub, 258, "sub"), (.subs, 259, "subs"),
        (.and, 260, "and"), (.orr, 261, "orr"), (.eor, 262, "eor"), (.ands, 263, "ands"),
        (.movn, 264, "movn"), (.movz, 265, "movz"), (.movk, 266, "movk"),
        (.adr, 267, "adr"), (.adrp, 268, "adrp"),
        (.bfm, 269, "bfm"), (.sbfm, 270, "sbfm"), (.ubfm, 271, "ubfm"),
        (.extr, 272, "extr"),
        (.cmp, 280, "cmp"), (.cmn, 281, "cmn"), (.tst, 282, "tst"), (.mov, 283, "mov"),
        (.bfi, 284, "bfi"), (.bfxil, 285, "bfxil"), (.bfc, 286, "bfc"),
        (.sbfiz, 287, "sbfiz"), (.sbfx, 288, "sbfx"),
        (.ubfiz, 289, "ubfiz"), (.ubfx, 290, "ubfx"),
        (.lsl, 291, "lsl"), (.lsr, 292, "lsr"), (.asr, 293, "asr"), (.ror, 294, "ror"),
        (.sxtb, 295, "sxtb"), (.sxth, 296, "sxth"), (.sxtw, 297, "sxtw"),
        (.uxtb, 298, "uxtb"), (.uxth, 299, "uxth"),
    ]

    @Test func everyMnemonicHasItsLockedRawValue() {
        for (mnemonic, expected, name) in Self.allDPIMnemonics {
            #expect(mnemonic.rawValue == expected, "Mnemonic.\(name) raw value drifted")
        }
    }

    @Test func everyMnemonicFallsInTheReservedRange() {
        let dpiSlab: ClosedRange<UInt16> = 256 ... 1023
        for (mnemonic, _, name) in Self.allDPIMnemonics {
            #expect(dpiSlab.contains(mnemonic.rawValue), "Mnemonic.\(name) outside the DPI slab")
        }
    }

    @Test func rawValuesAreUnique() {
        var seen: [UInt16: String] = [:]
        for (mnemonic, _, name) in Self.allDPIMnemonics {
            let prior = seen.updateValue(name, forKey: mnemonic.rawValue)
            #expect(
                prior == nil,
                "Mnemonic.\(name) collides with .\(prior ?? "<none>") at raw value \(mnemonic.rawValue)",
            )
        }
    }

    @Test func rangeAllocationStillNamesTheSlab() {
        let dpiEntry = Mnemonic.allocations.first { $0.label == "Data Processing — Immediate" }
        #expect(dpiEntry?.range == 256 ... 1023)
    }
}
