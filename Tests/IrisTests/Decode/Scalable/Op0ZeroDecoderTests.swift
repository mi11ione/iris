// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the composite multiplexing the three families sharing `op0=0`.
@Suite("Op0ZeroDecoder / composite routing of the op0=0 tier")
struct Op0ZeroDecoderRoutingTests {
    @Test func amxEncodingsRouteToTheAMXDecoder() {
        for opcode: UInt32 in 0 ..< 23 {
            let encoding = 0x0020_1000 | (opcode << 5)
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.category == .amx, "AMX opcode \(opcode) misrouted")
        }
    }

    @Test func smeEncodingsRouteToTheSMEDecoder() {
        let holes: [(UInt32, String)] = [
            (0x8000_0004, "100|0|0 — SME2 outer-product hole"),
            (0xA000_8002, "101|0|0 — SME2 multi-vector memory hole"),
            (0xC00C_1000, "110|0|0 — SME2 ZERO-array hole"),
            (0xE000_0010, "111|0|0 — SME core ZA-load hole"),
        ]
        for (encoding, label) in holes {
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.category == .sme, "\(label) misrouted")
            #expect(draft.mnemonic == .undefined, "\(label)")
        }
    }

    @Test func smeCoreEncodingsRouteThroughToARealRecord() {
        let core: [(UInt32, Mnemonic, String)] = [
            (0x8080_0000, .fmopa, "outer product"),
            (0xC000_0000, .mov, "MOVA insert"),
            (0xC008_0011, .zero, "ZERO"),
            (0xE01F_0000, .ld1b, "LD1B tile slice"),
            (0xE100_0000, .ldr, "LDR ZA"),
        ]
        for (encoding, mnemonic, label) in core {
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.category == .sme, "\(label)")
            #expect(draft.mnemonic == mnemonic, "\(label)")
            #expect(draft.encoding == encoding, "\(label)")
        }
    }

    @Test func genuineHolesRouteToUndefined() {
        let holes: [UInt32] = [
            0x0020_1400,
            0x0020_0000,
            0x0100_0000,
            0x01FF_FFFF,
            0x0020_1800,
        ]
        for encoding in holes {
            let draft = Iris.decode(encoding, at: 0)
            #expect(draft.category == .undefined, "hole 0x\(String(encoding, radix: 16)) misrouted")
            #expect(draft.mnemonic == .undefined)
            #expect(draft.encoding == encoding)
            #expect(draft.operands.isEmpty)
        }
    }

    @Test func theThreeRoutesAreMutuallyExclusive() {
        for opcode: UInt32 in 0 ..< 23 {
            let amxWord = 0x0020_1000 | (opcode << 5)
            #expect(Iris.decode(amxWord).category == .amx)
        }
        for topBits: UInt32 in 0b100 ... 0b111 {
            let smeWord = topBits << 29
            #expect(Iris.decode(smeWord).category == .sme)
        }
        #expect(Iris.decode(0x0000_1234).category == .branchesExceptionSystem)
    }
}

/// Validates that the whole of `op0=0` is accounted for.
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
            let actual = Iris.decode(encoding).category
            #expect(actual == category, "\(label) attributed to \(actual)")
            seen.insert(actual)
        }
        #expect(seen.count == representatives.count, "the four outcomes must be distinct")
    }
}
