// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import Testing

private func canonical(_ enc: UInt32) -> String {
    let draft = decode(enc, at: 0)
    return draft.text
}

/// Golden-corpus parity: every row of the harvested BES synthetic TSV decodes
/// and canonicalizes to its recorded llvm-mc text.
@Suite("BES / Adequacy — golden synthetic corpus parity")
struct BESGoldenCorpusParityTests {
    @Test func canonicalizesEverySyntheticRow() throws {
        let path = decodeCorpusTSVPath(family: "bes")
        let contents = try String(contentsOfFile: path, encoding: .utf8)
        var checked = 0
        for raw in contents.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw).trimmingCharacters(in: .newlines)
            if line.isEmpty { continue }
            if line.hasPrefix("#") { continue }
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            let enc = try #require(UInt32(parts[0], radix: 16))
            let expected = normalizeDisassembly(parts.dropFirst().joined(separator: " "))
            let d = decode(enc, at: 0)
            #expect(expected.isEmpty ? d.isUndefined : d.text == expected,
                    "golden mismatch for 0x\(String(enc, radix: 16)): \(d.text) != \(expected)")
            checked &+= 1
        }
        #expect(checked > 1000, "expected >1000 corpus rows, got \(checked)")
    }
}

/// Exhaustive imm7 → mnemonic and operand shape for HINT, every imm7 ∈
/// 0...127.
@Suite("BES / Adequacy — HINT 0..127 exact mapping")
struct BESHintExactMappingTests {
    private static let expected: [(UInt8, Mnemonic, [Operand])] = [
        (0, .nop, []), (1, .yield, []), (2, .wfe, []), (3, .wfi, []),
        (4, .sev, []), (5, .sevl, []), (6, .dgh, []), (7, .xpaclri, []),
        (8, .pacia1716, []),
        (10, .pacib1716, []),
        (12, .autia1716, []),
        (14, .autib1716, []),
        (16, .esb, []), (17, .psb, []), (18, .tsb, []),
        (19, .gcsbDsync, []),
        (20, .csdb, []),
        (22, .clrbhb, []),
        (24, .paciaz, []), (25, .paciasp, []),
        (26, .pacibz, []), (27, .pacibsp, []),
        (28, .autiaz, []), (29, .autiasp, []),
        (30, .autibz, []), (31, .autibsp, []),
        (32, .bti, [.unsignedImmediate(value: 0, width: 2)]),
        (34, .bti, [.unsignedImmediate(value: 1, width: 2)]),
        (36, .bti, [.unsignedImmediate(value: 2, width: 2)]),
        (38, .bti, [.unsignedImmediate(value: 3, width: 2)]),
        (39, .pacm, []),
        (40, .chkfeat, []),
        (48, .stshh, [.unsignedImmediate(value: 0, width: 3)]),
        (49, .stshh, [.unsignedImmediate(value: 1, width: 3)]),
        (50, .shuh, [.unsignedImmediate(value: 0, width: 3)]),
        (51, .shuh, [.unsignedImmediate(value: 1, width: 3)]),
        (52, .stcph, []),
        (53, .stshh, [.unsignedImmediate(value: 5, width: 3)]),
        (54, .stshh, [.unsignedImmediate(value: 6, width: 3)]),
        (55, .stshh, [.unsignedImmediate(value: 7, width: 3)]),
    ]

    private static let reservedImm7: Set<UInt8> = {
        var set: Set<UInt8> = []
        let named = Set(expected.map(\.0))
        for i: UInt8 in 0 ..< 128 where !named.contains(i) {
            set.insert(i)
        }
        return set
    }()

    private func enc(_ imm7: UInt8) -> UInt32 {
        UInt32(0xD503_201F) | (UInt32(imm7) << 5)
    }

    @Test func everyNamedSlotHasExactMnemonicAndOperand() {
        for (imm7, expectedMnemonic, expectedOperands) in Self.expected {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic == expectedMnemonic, "HINT \(imm7)")
            #expect(Array(d.operands) == expectedOperands, "HINT \(imm7) operands")
        }
    }

    @Test func everyReservedSlotEmitsHintWithExactImmediate() {
        for imm7 in Self.reservedImm7.sorted() {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic == .hint, "HINT \(imm7) expected .hint sentinel")
            #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(imm7), width: 7)],
                    "HINT \(imm7) operand")
        }
    }
}

/// Encoding-backed SYS alias parity.
@Suite("BES / Adequacy — SYS alias encoding parity")
struct BESSysAliasParityTests {
    @Test func everySysAliasInTableRoundTrips() {
        let cases: [(UInt8, UInt8, UInt8, UInt8, Bool, String)] = [
            (0, 7, 1, 0, false, "ic ialluis"),
            (0, 7, 5, 0, false, "ic iallu"),
            (3, 7, 5, 1, true, "ic ivau"),
            (3, 7, 4, 1, true, "dc zva"),
            (0, 7, 6, 1, true, "dc ivac"),
            (0, 7, 6, 2, true, "dc isw"),
            (3, 7, 10, 1, true, "dc cvac"),
            (0, 7, 10, 2, true, "dc csw"),
            (3, 7, 11, 1, true, "dc cvau"),
            (3, 7, 14, 1, true, "dc civac"),
            (3, 7, 12, 1, true, "dc cvap"),
            (0, 7, 14, 2, true, "dc cisw"),
            (0, 7, 8, 0, true, "at s1e1r"),
            (0, 7, 8, 1, true, "at s1e1w"),
            (0, 7, 8, 2, true, "at s1e0r"),
            (0, 7, 8, 3, true, "at s1e0w"),
            (0, 8, 3, 0, false, "tlbi vmalle1is"),
            (0, 8, 3, 1, true, "tlbi vae1is"),
            (0, 8, 7, 0, false, "tlbi vmalle1"),
            (0, 8, 7, 1, true, "tlbi vae1"),
            (0, 8, 3, 2, true, "tlbi aside1is"),
            (0, 8, 7, 2, true, "tlbi aside1"),
            (4, 8, 3, 4, false, "tlbi alle1is"),
            (4, 8, 7, 4, false, "tlbi alle1"),
            (0, 8, 3, 5, true, "tlbi vale1is"),
            (0, 8, 7, 5, true, "tlbi vale1"),
        ]
        for (op1, CRn, CRm, op2, needsReg, expectedName) in cases {
            let Rt: UInt8 = needsReg ? 5 : 0x1F
            var enc: UInt32 = 0
            enc |= UInt32(0b11_0101_0100) << 22
            enc |= UInt32(0b01) << 19
            enc |= UInt32(op1) << 16
            enc |= UInt32(CRn) << 12
            enc |= UInt32(CRm) << 8
            enc |= UInt32(op2) << 5
            enc |= UInt32(Rt)
            let actual = canonical(enc)
            let expected = needsReg ? "\(expectedName), x\(Rt)" : expectedName
            #expect(actual == expected, "SYS alias \(expectedName)")
        }
    }
}

/// Exhaustive (op_high3, LL) matrix for exceptions.
@Suite("BES / Adequacy — exception (op_high3, LL) matrix")
struct BESExceptionMatrixTests {
    private static let validTuples: [(UInt8, UInt8, Mnemonic)] = [
        (0b000, 0b01, .svc),
        (0b000, 0b10, .hvc),
        (0b000, 0b11, .smc),
        (0b001, 0b00, .brk),
        (0b010, 0b00, .hlt),
        (0b101, 0b01, .dcps1),
        (0b101, 0b10, .dcps2),
        (0b101, 0b11, .dcps3),
        (0b111, 0b00, .tenter),
    ]

    private func enc(op_high3: UInt8, LL: UInt8, imm16: UInt16 = 0) -> UInt32 {
        var e: UInt32 = 0
        e |= UInt32(0xD4) << 24
        e |= UInt32(op_high3 & 0x7) << 21
        e |= UInt32(imm16) << 5
        e |= UInt32(LL & 0x3)
        return e
    }

    @Test func everyValidTupleProducesExactMnemonic() {
        for (op3, LL, expected) in Self.validTuples {
            let d = decode(enc(op_high3: op3, LL: LL), at: 0)
            #expect(d.mnemonic == expected, "(\(op3), \(LL))")
            #expect(d.branchClass == .exception)
        }
    }

    @Test func everyOtherTupleIsUndefined() {
        let valid = Set(Self.validTuples.map { UInt32($0.0) * 4 + UInt32($0.1) })
        for op3: UInt8 in 0 ... 7 {
            for LL: UInt8 in 0 ... 3 {
                let key = UInt32(op3) * 4 + UInt32(LL)
                if valid.contains(key) { continue }
                let d = decode(enc(op_high3: op3, LL: LL), at: 0)
                #expect(d.mnemonic == .undefined,
                        "(\(op3), \(LL)) expected .undefined")
                #expect(d.encoding == enc(op_high3: op3, LL: LL),
                        "raw encoding preserved")
            }
        }
    }
}

/// Sweeps every reserved branch-register discriminator, otherwise-valid
/// fields, asserting `.undefined`.
@Suite("BES / Adequacy — branch-register reserved opcodes")
struct BESBranchRegReservedOpcTests {
    @Test func regularReservedOpcReturnsUndefined() {
        let valid: Set<UInt8> = [0b0000, 0b0001, 0b0010, 0b0100, 0b0101]
        for opc: UInt8 in 0 ... 7 {
            if valid.contains(opc) { continue }
            let enc: UInt32 = (0x6B << 25) | (UInt32(opc) << 21) | (0x1F << 16)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .undefined, "regular opc \(opc) reserved")
        }
    }

    @Test func authTwoOperandReservedOpcReturnsUndefined() {
        for opcLow3: UInt8 in 2 ... 7 {
            let opcHighBit: UInt32 = 0x8
            let enc: UInt32 = (0x6B << 25)
                | ((opcHighBit | UInt32(opcLow3)) << 21)
                | (0x1F << 16)
                | (0b00001 << 11)
                | (16 << 5)
                | 17
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .undefined, "auth-two opcLow3 \(opcLow3) reserved")
        }
    }

    @Test func authZeroAndReturnReservedOpcReturnsUndefined() {
        for opcLow3: UInt8 in [0b011, 0b101, 0b110, 0b111] {
            let enc: UInt32 = (0x6B << 25)
                | (UInt32(opcLow3) << 21)
                | (0x1F << 16)
                | (0b00001 << 11)
                | (0x1F << 5)
                | 0x1F
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .undefined, "auth-zero opcLow3 \(opcLow3) reserved")
        }
    }
}

/// Exhaustive DSB nXS CRm coverage.
@Suite("BES / Adequacy — DSB nXS CRm matrix")
struct BESDsbNxsMatrixTests {
    @Test func nxsAtOp2OneAcceptsOnlyDocumentedCRm() {
        let valid: Set<UInt8> = [2, 6, 10, 14]
        let expectedTexts: [UInt8: String] = [
            2: "dsb oshnxs",
            6: "dsb nshnxs",
            10: "dsb ishnxs",
            14: "dsb synxs",
        ]
        for crm: UInt8 in 0 ..< 16 {
            let enc = UInt32(0xD503_303F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            if valid.contains(crm) {
                #expect(d.mnemonic == .dsb, "CRm \(crm) expected .dsb (nXS)")
                #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(crm) | 0x10, width: 5)],
                        "CRm \(crm) operand")
                #expect(canonical(enc) == expectedTexts[crm]!, "CRm \(crm) canonical")
            } else {
                #expect(d.mnemonic == .msr, "CRm \(crm) expected .msr")
            }
        }
    }
}

/// Strengthens CLREX (every CRm), WFET (every Rt) and odd BTI slots on exact
/// immediate, Rt operand and semantic reads.
@Suite("BES / Adequacy — strengthened loop assertions")
struct BESStrengthenedLoopTests {
    @Test func clrexEveryCRmHasExactOperand() {
        for crm: UInt8 in 0 ..< 16 {
            let enc = UInt32(0xD503_305F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .clrex, "CRm \(crm)")
            if crm == 0xF {
                #expect(d.operands.isEmpty, "CRm 15 should have no operand")
                #expect(canonical(enc) == "clrex")
            } else {
                #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(crm), width: 4)],
                        "CRm \(crm) operand")
                #expect(canonical(enc) == "clrex #\(crm)")
            }
        }
    }

    @Test func wfetEveryRtCarriesExactRegister() {
        for rt: UInt8 in 0 ..< 32 {
            let enc = UInt32(0xD503_1000) | UInt32(rt)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .wfet, "Rt \(rt)")
            let expectedRef: RegisterRef = (rt == 31) ? .xzr() : .x(rt)
            #expect(Array(d.operands) == [.register(expectedRef)], "Rt \(rt) operand")
            #expect(d.semanticReads.contains(expectedRef), "Rt \(rt) reads")
        }
    }

    @Test func wfitEveryRtCarriesExactRegister() {
        for rt: UInt8 in 0 ..< 32 {
            let enc = UInt32(0xD503_1020) | UInt32(rt)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .wfit, "Rt \(rt)")
            let expectedRef: RegisterRef = (rt == 31) ? .xzr() : .x(rt)
            #expect(Array(d.operands) == [.register(expectedRef)], "Rt \(rt) operand")
        }
    }

    @Test func btiOddSlotsCarryExactGenericImmediate() {
        for imm7: UInt8 in [33, 35, 37, 41] {
            let enc = UInt32(0xD503_201F) | (UInt32(imm7) << 5)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .hint, "imm7 \(imm7)")
            #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(imm7), width: 7)],
                    "imm7 \(imm7) operand")
            #expect(canonical(enc) == "hint #\(imm7)", "imm7 \(imm7) canonical")
        }
    }
}
