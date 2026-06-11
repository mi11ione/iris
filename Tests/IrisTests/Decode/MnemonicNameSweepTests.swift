// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Sweeps `Mnemonic.name` over every raw value of every allocated family
/// range and proves the name tables are total and well-formed: every
/// declared constant resolves to a real lowercase name (never the
/// `?<raw>` fallback), every unallocated gap resolves to exactly
/// `?<raw>`, the per-family named-constant populations are pinned, and
/// raw values beyond all allocations fall to the fallback.
@Suite("Mnemonic / name-table population sweeps")
struct MnemonicNameSweepTests {
    /// Named (non-fallback) population per allocation label, mirroring
    /// the per-family `static let` declarations one-for-one.
    private static let expectedNamedCounts: [String: Int] = [
        "Sentinels & UDF": 4,
        "Data Processing — Immediate": 37,
        "Branches, Exception, System": 104,
        "Loads & Stores": 492,
        "Data Processing — Register": 66,
        "SIMD & Floating-Point": 313,
        "Crypto + Apple Extensions": 89,
    ]

    @Test func everyAllocatedRangeResolvesRealNamesAndExactFallbacks() {
        for allocation in Mnemonic.allocations {
            var named = 0
            for raw in allocation.range {
                let name = Mnemonic(rawValue: raw).name
                #expect(!name.isEmpty, "raw \(raw) produced an empty name")
                #expect(name == name.lowercased(), "raw \(raw): name \"\(name)\" is not lowercase")
                if name == "?\(raw)" {
                    continue // unallocated gap — exact fallback form
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
        for raw: UInt16 in [16384, 30000, 65534, 65535] {
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
