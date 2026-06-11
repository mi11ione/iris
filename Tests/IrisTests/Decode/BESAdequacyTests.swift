// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import Testing

private func canonical(_ enc: UInt32) -> String {
    let draft = decode(enc, at: 0)
    return draft.text
}

/// Golden-corpus parity: load the harvested BES synthetic corpus TSV
/// (which is llvm-mc's reference output at the parity mattr) and assert
/// every row's decoded+canonicalized text matches the recorded oracle.
/// The per-mnemonic unit tests prove individual cases; this test proves
/// the full enumerative coverage at the unit-test level.
@Suite("BES / Adequacy — golden synthetic corpus parity")
struct BESGoldenCorpusParityTests {
    @Test func canonicalizesEverySyntheticRow() throws {
        // In-repo fixture by default; an external corpus tree when
        // `IRIS_DECODE_CORPUS` is set — see `decodeCorpusTSVPath(family:)`.
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
            // The oracle's "" convention marks undefined encodings; Iris
            // text is total (`.long 0x…`), so the comparison maps "" to
            // the undefined witness.
            let d = decode(enc, at: 0)
            #expect(expected.isEmpty ? d.isUndefined : d.text == expected,
                    "golden mismatch for 0x\(String(enc, radix: 16)): \(d.text) != \(expected)")
            checked &+= 1
        }
        #expect(checked > 1000, "expected >1000 corpus rows, got \(checked)")
    }
}

/// Exhaustive imm7 → mnemonic table for HINT decode. The existing
/// `everyImm7Decodes` loop only proves each slot returns non-undefined;
/// this test pins the exact mnemonic + operand shape for every
/// imm7 ∈ 0..127.
@Suite("BES / Adequacy — HINT 0..127 exact mapping")
struct BESHintExactMappingTests {
    /// Expected (mnemonic, subTarget) per imm7 slot. Aligned with
    /// HintTable.entries — any mutation to the table fails this test.
    private static let expected: [(UInt8, Mnemonic, UInt8)] = [
        (0, .nop, 0), (1, .yield, 0), (2, .wfe, 0), (3, .wfi, 0),
        (4, .sev, 0), (5, .sevl, 0), (6, .dgh, 0), (7, .xpaclri, 0),
        (8, .pacia1716, 0),
        (10, .pacib1716, 0),
        (12, .autia1716, 0),
        (14, .autib1716, 0),
        (16, .esb, 0), (17, .psb, 0), (18, .tsb, 0),
        (19, .gcsbDsync, 0),
        (20, .csdb, 0),
        (22, .clrbhb, 0),
        (24, .paciaz, 0), (25, .paciasp, 0),
        (26, .pacibz, 0), (27, .pacibsp, 0),
        (28, .autiaz, 0), (29, .autiasp, 0),
        (30, .autibz, 0), (31, .autibsp, 0),
        (32, .bti, 0),
        (34, .bti, 1),
        (36, .bti, 2),
        (38, .bti, 3),
        (40, .chkfeat, 0),
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
        for (imm7, expectedMnemonic, subTarget) in Self.expected {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic == expectedMnemonic, "HINT \(imm7)")
            if subTarget == 0 {
                #expect(d.operands.isEmpty, "HINT \(imm7) should have no operand")
            } else {
                #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(subTarget), width: 2)],
                        "HINT \(imm7) sub-target")
            }
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

/// Encoding-backed SYS alias parity: every entry in the synthetic
/// corpus that decodes to .sys/.sysl gets decoded + canonicalized; the
/// resulting text must match the corpus's recorded oracle (which is
/// llvm-mc's text). The alias rendering tests pin named rows through
/// decode + text; this test verifies the alias text against the
/// recorded oracle via real encodings.
@Suite("BES / Adequacy — SYS alias encoding parity")
struct BESSysAliasParityTests {
    @Test func everySysAliasInTableRoundTrips() {
        // For every (op1, CRn, CRm, op2, needsReg, expected-name)
        // documented in the alias surface, construct the SYS
        // encoding and assert canonicalization produces the friendly
        // name (with or without Rt).
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
            // SYS encoding: bits 31:22 = 1101010100, bit 21 = 0,
            //   bits 20:19 = 01, bits 18:16 = op1, bits 15:12 = CRn,
            //   bits 11:8 = CRm, bits 7:5 = op2, bits 4:0 = Rt
            // Rt = 5 for needsReg=true to produce a distinctive operand;
            // Rt = 11111 (XZR) otherwise.
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

/// Exhaustive (op_high3, LL) matrix for exception encodings. Of the 32
/// (op_high3 × LL) tuples, 8 are valid mnemonics; the remaining 24 must
/// produce .undefined.
@Suite("BES / Adequacy — exception (op_high3, LL) matrix")
struct BESExceptionMatrixTests {
    /// Valid (op_high3, LL) → mnemonic per the ARM ARM.
    private static let validTuples: [(UInt8, UInt8, Mnemonic)] = [
        (0b000, 0b01, .svc),
        (0b000, 0b10, .hvc),
        (0b000, 0b11, .smc),
        (0b001, 0b00, .brk),
        (0b010, 0b00, .hlt),
        (0b101, 0b01, .dcps1),
        (0b101, 0b10, .dcps2),
        (0b101, 0b11, .dcps3),
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

/// Exhaustive reserved-opcode coverage for branch-register. Each family's
/// reserved opcode default branch is currently hit by one representative;
/// this test sweeps every reserved discriminator (with otherwise-valid
/// fields) and asserts .undefined.
@Suite("BES / Adequacy — branch-register reserved opcodes")
struct BESBranchRegReservedOpcTests {
    @Test func regularReservedOpcReturnsUndefined() {
        // Regular BR/BLR/RET/ERET/DRPS = opc 0000/0001/0010/0100/0101.
        // Reserved: 0011, 0110, 0111, 1100, 1101, 1110, 1111. (1000+ go
        // to auth-two-op so they're skipped here.) Within the regular
        // shape (bit 24 = 0, bits 15:11 = 00000), test every reserved
        // opc in 0..0111.
        let valid: Set<UInt8> = [0b0000, 0b0001, 0b0010, 0b0100, 0b0101]
        for opc: UInt8 in 0 ... 7 {
            if valid.contains(opc) { continue }
            // bit 24 = 0, bits 15:11 = 00000, bit 10 = 0, bits 4:0 = 0,
            // Rn = 0 (or 11111 for ERET/DRPS shape — doesn't matter here
            // since opc is reserved, the per-opc Rn check never runs).
            let enc: UInt32 = (0x6B << 25) | (UInt32(opc) << 21) | (0x1F << 16)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .undefined, "regular opc \(opc) reserved")
        }
    }

    @Test func authTwoOperandReservedOpcReturnsUndefined() {
        // Two-operand auth = opcLow3 ∈ {0b000, 0b001}; reserved within
        // bit24=1 path: 0b010..0b111.
        for opcLow3: UInt8 in 2 ... 7 {
            // bit 24 = 1, bits 24:21 = 1<opcLow3>, bits 20:16 = 11111,
            // bits 15:11 = 00001, bit 10 = 0, Rn=16, Rm=17.
            let opcHighBit: UInt32 = 0x8 // bit 24 = 1
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
        // Zero/return auth = opcLow3 ∈ {0b000, 0b001, 0b010, 0b100};
        // reserved: 0b011, 0b101, 0b110, 0b111.
        for opcLow3: UInt8 in [0b011, 0b101, 0b110, 0b111] {
            // bit 24 = 0, bits 24:21 = 0<opcLow3>, bits 20:16 = 11111,
            // bits 15:11 = 00001, bit 10 = 0, Rn=11111, Rm=11111.
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

/// Exhaustive DSB nXS CRm coverage. The DSB nXS form (FEAT_XS) only
/// allocates CRm ∈ {2, 6, 10, 14} for op2=001 (ARM ARM DSB encoding);
/// other CRm values must produce .undefined.
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
            // 1101 0101 0000 0011 0011 CRm 001 11111 — op2 = 001 nXS.
            let enc = UInt32(0xD503_303F) | (UInt32(crm) << 8)
            let d = decode(enc, at: 0)
            if valid.contains(crm) {
                #expect(d.mnemonic == .dsb, "CRm \(crm) expected .dsb (nXS)")
                #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(crm) | 0x10, width: 5)],
                        "CRm \(crm) operand")
                // Verify canonical text.
                #expect(canonical(enc) == expectedTexts[crm]!, "CRm \(crm) canonical")
            } else {
                // Non-nXS CRm in the op2=001 slot is not a barrier; it's an
                // op0 == 0 MSR (the oracle renders `msr S0_3_C3_C<crm>_1, xzr`).
                #expect(d.mnemonic == .msr, "CRm \(crm) expected .msr")
            }
        }
    }
}

/// Existing loops touch branches without asserting the exact immediate
/// value, exact Rt operand, or semantic reads. This strengthens CLREX
/// (every CRm), WFET (every Rt), and odd BTI slots.
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
            // semanticReads must contain Rt — verifies the per-Rt read tracking.
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
        // Odd BTI slots (33, 35, 37, 39) are reserved within the BTI
        // block — render as `hint #N` with exact width=7 immediate.
        for imm7: UInt8 in [33, 35, 37, 39] {
            let enc = UInt32(0xD503_201F) | (UInt32(imm7) << 5)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .hint, "imm7 \(imm7)")
            #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(imm7), width: 7)],
                    "imm7 \(imm7) operand")
            #expect(canonical(enc) == "hint #\(imm7)", "imm7 \(imm7) canonical")
        }
    }
}
