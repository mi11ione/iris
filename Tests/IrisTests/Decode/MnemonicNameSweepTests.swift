// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Sweeps `Mnemonic.name` over every allocated family range and proves the
/// tables are total.
@Suite("Mnemonic / name-table population sweeps")
struct MnemonicNameSweepTests {
    private static let expectedNamedCounts: [String: Int] = [
        "Sentinels & UDF": 4,
        "Data Processing — Immediate": 37,
        "Branches, Exception, System": 121,
        "Loads & Stores": 507,
        "Data Processing — Register": 66,
        "SIMD & Floating-Point": 373,
        "Crypto + Apple Extensions": 101,
        "SVE / SVE2 tier": 418,
        "SME / SME2 tier": 68,
    ]

    @Test func everyAllocatedRangeResolvesRealNamesAndExactFallbacks() {
        for allocation in Mnemonic.allocations {
            var named = 0
            for raw in allocation.range {
                let name = Mnemonic(rawValue: raw).name
                #expect(!name.isEmpty, "raw \(raw) produced an empty name")
                #expect(name == name.lowercased(), "raw \(raw): name \"\(name)\" is not lowercase")
                if name == "?\(raw)" {
                    continue
                }
                #expect(!name.hasPrefix("?"),
                        "raw \(raw): malformed fallback \"\(name)\" (must be ?<raw> exactly)")
                named += 1
            }
            #expect(named == Self.expectedNamedCounts[allocation.label],
                    "\(allocation.label): named population drifted to \(named)")
        }
    }

    @Test func rawValuesBeyondEveryAllocationUseTheFallback() {
        for raw: UInt16 in [40960, 50000, 65534, 65535] {
            let m = Mnemonic(rawValue: raw)
            #expect(m.name == "?\(raw)")
            #expect(m.description == "?\(raw)")
        }
    }

    @Test func sentinelRangeNamesItsFourConstantsOnly() {
        #expect(Mnemonic.undefined.name == "undefined")
        #expect(Mnemonic.dataMarker.name == "data")
        #expect(Mnemonic.truncatedTail.name == "truncated")
        #expect(Mnemonic.udf.name == "udf")
        for raw: UInt16 in 4 ... 255 {
            #expect(Mnemonic(rawValue: raw).name == "?\(raw)")
        }
    }

    @Test func compositeEncodingsCarryTheirManualSpellings() {
        #expect(Mnemonic.bCond.name == "b.cond")
        #expect(Mnemonic.bcCond.name == "bc.cond")
        #expect(Mnemonic.msrImm.name == "msr")
        #expect(Mnemonic.amxUnknownOp.name == "amx-unknown")
    }
}
