// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the composite that multiplexes the three families sharing
/// `op0=0b0000`: Apple's AMX coprocessor (an implementation-defined squat on
/// reserved space), architectural SME (bit31=1), and the genuine reserved
/// holes. UDF also lives at `op0=0` but is intercepted by the dispatcher before
/// family lookup. Getting this wrong is not a rendering bug — it would silently
/// attribute one vendor's instructions to another architecture.
@Suite("Op0ZeroDecoder / composite routing of the op0=0 tier")
struct Op0ZeroDecoderRoutingTests {
    @Test func amxEncodingsRouteToTheAMXDecoder() {
        // The AMX magic pattern (0x00201000 / mask 0xFFFFFC00) with every
        // documented opcode.
        for opcode: UInt32 in 0 ..< 23 {
            let encoding = 0x0020_1000 | (opcode << 5)
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.category == .amx, "AMX opcode \(opcode) misrouted")
        }
    }

    @Test func smeEncodingsRouteToTheSMEDecoder() {
        // bit31=1 within op0=0 is the SME region. The scalable tier is complete,
        // so the routing claim is that each bits[31:29] group reaches the SME
        // decoder and lands in the SME category — proven here with a genuine
        // architectural hole per group (an in-region word that decodes to a
        // well-formed UNDEFINED rather than a real instruction).
        let holes: [(UInt32, String)] = [
            (0x8000_0004, "100|0|0 — SME2 outer-product hole"),
            (0xA000_8002, "101|0|0 — SME2 multi-vector memory hole"),
            (0xC00C_1000, "110|0|0 — SME2 ZERO-array hole"),
            (0xE000_0010, "111|0|0 — SME core ZA-load hole"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.category == .sme, "\(label) misrouted")
            #expect(draft.mnemonic == .undefined, "\(label)")
        }
    }

    @Test func smeCoreEncodingsRouteThroughToARealRecord() {
        // The composite must reach 2s.6's decoder too, not just its UNDEFINED
        // arm — a routing break would look like a silently unimplemented tier.
        let core: [(UInt32, Mnemonic, String)] = [
            (0x8080_0000, .fmopa, "outer product"),
            (0xC000_0000, .mov, "MOVA insert"),
            (0xC008_0011, .zero, "ZERO"),
            (0xE01F_0000, .ld1b, "LD1B tile slice"),
            (0xE100_0000, .ldr, "LDR ZA"),
        ]
        for (encoding, mnemonic, label) in core {
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.category == .sme, "\(label)")
            #expect(draft.mnemonic == mnemonic, "\(label)")
            #expect(draft.encoding == encoding, "\(label)")
        }
    }

    @Test func genuineHolesRouteToUndefined() {
        // op0=0, bit31=0, not the AMX magic pattern, not UDF — the reserved
        // space that remains unallocated even under maximal SME/SVE features.
        let holes: [UInt32] = [
            0x0020_1400, // adjacent to AMX but outside its mask
            0x0020_0000, // op0=0, bits[31:16] != 0, not AMX
            0x0100_0000,
            0x01FF_FFFF,
            0x0020_1800,
        ]
        for encoding in holes {
            let draft = Iris.decode(encoding, at: 0, features: .scalable)
            #expect(draft.category == .undefined, "hole 0x\(String(encoding, radix: 16)) misrouted")
            #expect(draft.mnemonic == .undefined)
            #expect(draft.encoding == encoding)
            #expect(draft.operands.isEmpty)
        }
    }

    @Test func theThreeRoutesAreMutuallyExclusive() {
        // AMX and SME both live at op0=0; they must never both claim a word.
        // AMX is bit31=0 by construction, SME is bit31=1 — and a word can only
        // come back in one category, so the split is visible on the record.
        for opcode: UInt32 in 0 ..< 23 {
            let amxWord = 0x0020_1000 | (opcode << 5)
            #expect(Iris.decode(amxWord, features: .scalable).category == .amx)
        }
        for topBits: UInt32 in 0b100 ... 0b111 {
            let smeWord = topBits << 29
            #expect(Iris.decode(smeWord, features: .scalable).category == .sme)
        }
        // …and UDF, the fourth resident, keeps its own category.
        #expect(Iris.decode(0x0000_1234, features: .scalable).category == .branchesExceptionSystem)
    }
}

/// Validates that the whole of `op0=0` is accounted for. The tier is
/// architecturally SME, with AMX squatting a masked window and UDF carved out
/// below it, so every word in the tier must come back attributed to one of the
/// four outcomes — never unclaimed, never attributed to two families.
@Suite("Op0ZeroDecoder / the tier is fully accounted for")
struct Op0ZeroDecoderRegistrationTests {
    @Test func everyOutcomeInTheTierIsReachable() {
        let representatives: [(UInt32, Category, String)] = [
            (0x0000_1234, .branchesExceptionSystem, "UDF"),
            (0x0020_1000, .amx, "Apple AMX"),
            (0x8080_0000, .sme, "architectural SME"),
            (0x0020_1400, .undefined, "reserved hole"),
        ]
        var seen: Set<Category> = []
        for (encoding, category, label) in representatives {
            let actual = Iris.decode(encoding, features: .scalable).category
            #expect(actual == category, "\(label) attributed to \(actual)")
            seen.insert(actual)
        }
        #expect(seen.count == representatives.count, "the four outcomes must be distinct")
    }
}
