// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Pins the 58 Mnemonic raw-value constants the DPR family owns, in
/// the reserved 4096..6143 slab `Mnemonic.allocations` declares. Verifies
/// uniqueness + range-membership; also pins the 16 mnemonics DPR reuses
/// from DPI at their existing raw values so a refactor that moves them
/// is caught.
@Suite("DPR / Mnemonic constants 4096..4153")
struct DPRMnemonicConstantsTests {
    /// The family's allocation table: every DPR-declared mnemonic at
    /// its locked raw value. Each row is `(constant, expected, name)`.
    private static let allDPRMnemonics: [(Mnemonic, UInt16, String)] = [
        (.bic, 4096, "bic"), (.orn, 4097, "orn"), (.eon, 4098, "eon"), (.bics, 4099, "bics"),
        (.mvn, 4100, "mvn"),
        (.adc, 4101, "adc"), (.adcs, 4102, "adcs"), (.sbc, 4103, "sbc"), (.sbcs, 4104, "sbcs"),
        (.ngc, 4105, "ngc"), (.ngcs, 4106, "ngcs"),
        (.neg, 4107, "neg"), (.negs, 4108, "negs"),
        (.ccmn, 4109, "ccmn"), (.ccmp, 4110, "ccmp"),
        (.csel, 4111, "csel"), (.csinc, 4112, "csinc"), (.csinv, 4113, "csinv"), (.csneg, 4114, "csneg"),
        (.cset, 4115, "cset"), (.csetm, 4116, "csetm"),
        (.cinc, 4117, "cinc"), (.cinv, 4118, "cinv"), (.cneg, 4119, "cneg"),
        (.madd, 4120, "madd"), (.msub, 4121, "msub"),
        (.smaddl, 4122, "smaddl"), (.smsubl, 4123, "smsubl"),
        (.umaddl, 4124, "umaddl"), (.umsubl, 4125, "umsubl"),
        (.smulh, 4126, "smulh"), (.umulh, 4127, "umulh"),
        (.mul, 4128, "mul"), (.mneg, 4129, "mneg"),
        (.smull, 4130, "smull"), (.smnegl, 4131, "smnegl"),
        (.umull, 4132, "umull"), (.umnegl, 4133, "umnegl"),
        (.udiv, 4134, "udiv"), (.sdiv, 4135, "sdiv"),
        (.lslv, 4136, "lslv"), (.lsrv, 4137, "lsrv"),
        (.asrv, 4138, "asrv"), (.rorv, 4139, "rorv"),
        (.clz, 4140, "clz"), (.cls, 4141, "cls"),
        (.rbit, 4142, "rbit"),
        (.rev, 4143, "rev"), (.rev16, 4144, "rev16"), (.rev32, 4145, "rev32"),
        (.crc32b, 4146, "crc32b"), (.crc32h, 4147, "crc32h"),
        (.crc32w, 4148, "crc32w"), (.crc32x, 4149, "crc32x"),
        (.crc32cb, 4150, "crc32cb"), (.crc32ch, 4151, "crc32ch"),
        (.crc32cw, 4152, "crc32cw"), (.crc32cx, 4153, "crc32cx"),
    ]

    /// DPI-owned mnemonics that the DPR family reuses. Pinned so a DPI
    /// refactor that drops them is caught at the DPR surface.
    private static let reusedDPIMnemonics: [(Mnemonic, UInt16, String)] = [
        (.add, 256, "add"), (.adds, 257, "adds"), (.sub, 258, "sub"), (.subs, 259, "subs"),
        (.and, 260, "and"), (.orr, 261, "orr"), (.eor, 262, "eor"), (.ands, 263, "ands"),
        (.cmp, 280, "cmp"), (.cmn, 281, "cmn"), (.tst, 282, "tst"), (.mov, 283, "mov"),
        (.lsl, 291, "lsl"), (.lsr, 292, "lsr"), (.asr, 293, "asr"), (.ror, 294, "ror"),
    ]

    @Test func everyNewMnemonicHasItsLockedRawValue() {
        for (mnemonic, expected, name) in Self.allDPRMnemonics {
            #expect(mnemonic.rawValue == expected, "Mnemonic.\(name) raw value drifted")
        }
    }

    @Test func everyNewMnemonicFallsInTheReservedRange() {
        let dprSlab: ClosedRange<UInt16> = 4096 ... 6143
        for (mnemonic, _, name) in Self.allDPRMnemonics {
            #expect(dprSlab.contains(mnemonic.rawValue), "Mnemonic.\(name) outside the DPR slab")
        }
    }

    @Test func newMnemonicRawValuesAreUnique() {
        var seen: [UInt16: String] = [:]
        for (mnemonic, _, name) in Self.allDPRMnemonics {
            let prior = seen.updateValue(name, forKey: mnemonic.rawValue)
            #expect(
                prior == nil,
                "Mnemonic.\(name) collides with .\(prior ?? "<none>") at raw value \(mnemonic.rawValue)",
            )
        }
    }

    @Test func reusedMnemonicsStillResolveToTheirDPIValues() {
        for (mnemonic, expected, name) in Self.reusedDPIMnemonics {
            #expect(mnemonic.rawValue == expected, "Mnemonic.\(name) (reused from DPI) raw value drifted")
        }
    }

    @Test func rangeAllocationStillNamesTheSlab() {
        let dprEntry = Mnemonic.allocations.first { $0.label == "Data Processing — Register" }
        #expect(dprEntry?.range == 4096 ... 6143)
    }

    @Test func allocationCountMatchesTheCommittedTable() {
        #expect(Self.allDPRMnemonics.count == 58, "the DPR allocation commits to 58 new mnemonics")
    }
}
