// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func dispatch(_ encoding: UInt32, features: Features = .base) -> Instruction {
    Iris.decode(encoding, at: 0x1_0000_8000, features: features)
}

/// Validates that the substrate's top-level dispatcher routes the two encoding
/// tiers reclaimed from reserved space — SVE (`op0=2`) and SME (`op0=0`,
/// bit31=1) — without disturbing the families that already shared their `op0`.
/// `op0=0` is the delicate one: UDF, AMX, SME and the reserved holes all live
/// there, and the dispatcher resolves them in that order.
@Suite("Dispatch / SVE and SME tiers route through the standard table")
struct ScalableDispatchRoutingTests {
    @Test func sveEncodingsDispatchToTheSVEFamily() {
        // One encoding from each SVE sub-region, by top byte. The integer
        // subpiece decodes five of them to real records now — which proves the
        // routing even harder — while the rest stay UNDEFINED holes.
        let decoded: [(UInt32, Mnemonic)] = [
            (0x0400_0000, .add), (0x0500_0000, .orr), (0x2400_0000, .cmphs),
            (0x2500_0000, .cmpge), (0x04A0_0000, .add),
        ]
        for (encoding, mnemonic) in decoded {
            let draft = dispatch(encoding)
            #expect(draft.category == .sve, "0x\(String(encoding, radix: 16)) is not .sve")
            #expect(draft.mnemonic == mnemonic)
            #expect(draft.encoding == encoding)
        }
        // The memory (2s.5) samples are in-region reserved holes — 0x8400_0000
        // and 0xA400_0000 now decode to real gather/replicate loads, so the
        // UNDEFINED witnesses moved to holes inside the same top bytes.
        for encoding: UInt32 in [0x4400_0000, 0x6400_0000, 0x8400_C010, 0xA400_8000, 0x056E_4116] {
            let draft = dispatch(encoding)
            #expect(draft.category == .sve, "0x\(String(encoding, radix: 16)) is not .sve")
            #expect(draft.mnemonic == .undefined)
            #expect(draft.encoding == encoding)
        }
    }

    @Test func smeEncodingsDispatchToTheSMEFamily() {
        // The scalable tier is complete (2s.6 core + 2s.7 multi-vector), so the
        // outer-product, MOVA, ZA-memory, multi-vector and ZT0 samples all decode
        // to real records; the UNDEFINED witnesses are now genuine architectural
        // holes inside the same region, not deferred encodings.
        for (encoding, mnemonic) in [
            (UInt32(0x8080_0000), Mnemonic.fmopa), (0xA080_0000, .smopa),
            (0xC000_0000, .mov), (0xE000_0000, .ld1b),
            (0x8000_0000, .fmop4a), (0xA000_0000, .ld1b),
            (0xC100_0000, .smlall), (0xE11F_8000, .ldr),
        ] {
            let draft = dispatch(encoding)
            #expect(draft.category == .sme, "0x\(String(encoding, radix: 16)) is not .sme")
            #expect(draft.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(draft.encoding == encoding)
        }
        for encoding: UInt32 in [0x8000_0004, 0xC100_000C, 0xC00C_1000] {
            let draft = dispatch(encoding)
            #expect(draft.category == .sme, "0x\(String(encoding, radix: 16)) is not .sme")
            #expect(draft.mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
            #expect(draft.encoding == encoding)
        }
    }

    @Test func amxStillDispatchesToAMXAfterTheCompositeTookTheSlot() {
        // The regression that matters most: the composite replaced AMXDecoder's
        // direct registration at op0=0. AMX must be unaffected.
        for opcode: UInt32 in 0 ..< 23 {
            let encoding = 0x0020_1000 | (opcode << 5)
            #expect(dispatch(encoding).category == .amx, "AMX opcode \(opcode) lost its routing")
        }
    }

    @Test func udfIsStillInterceptedBeforeFamilyDispatch() {
        // UDF is bits[31:16]==0 at op0=0 — disjoint from SME (bit31=1) and
        // from AMX. The substrate owns it before the family table is consulted.
        for imm: UInt32 in [0, 1, 0xFFFF, 0x1234] {
            let draft = dispatch(imm)
            #expect(draft.mnemonic == .udf)
            #expect(draft.category == .branchesExceptionSystem)
            #expect(Array(draft.operands) == [.unsignedImmediate(value: UInt64(imm), width: 16)])
        }
    }

    @Test func op0ZeroHolesStillDispatchToUndefined() {
        // op0=0, bit31=0, bits[31:16] != 0 (not UDF), outside the AMX mask.
        for encoding: UInt32 in [0x0020_0000, 0x0020_1400, 0x0100_0000, 0x01FF_FFFF] {
            #expect((encoding >> 25) & 0xF == 0, "fixture must be an op0=0 word")
            let draft = dispatch(encoding)
            #expect(draft.category == .undefined, "0x\(String(encoding, radix: 16))")
            #expect(draft.mnemonic == .undefined)
        }
    }

    @Test func theStillUnallocatedTiersRemainUndefined() {
        // op0=1 and op0=3 are unallocated even under maximal SVE/SME features;
        // only op0=2 and op0=0 were reclaimed.
        for op0: UInt32 in [1, 3] {
            for low: UInt32 in [0, 0x00FF_FFFF, 0x01FF_FFFF] {
                let encoding = (op0 << 25) | low
                let draft = dispatch(encoding)
                #expect(draft.category == .undefined,
                        "op0=\(op0) 0x\(String(encoding, radix: 16)) should be undefined")
            }
        }
    }

    @Test func everyDispatchedSVEAndSMERecordIsWellFormed() {
        // The output guarantee: a well-formed UNDEFINED record invents no
        // register, operand, or scalable state, and preserves the raw bytes.
        // 0x0400_8400 is a reserved hole inside the integer decoder's scope
        // (its old witness 0x04A0_0000 decodes to a real `add` now); 0xA400_8000
        // is a reserved hole inside the memory (2s.5) scope (0xA400_0000 decodes
        // to a real `ld1rqb` now); 0x80A0_0004 is an SME2 residue hole (the
        // 0x80A0_0000 residue itself now decodes to `fmopa`) and 0xE000_0010 a
        // reserved-bit hole inside the SME core scope (whose 0xE000_0000 base
        // decodes to `ld1b` now).
        for encoding: UInt32 in [0x0400_8400, 0x80A0_0004, 0xE000_0010, 0xA400_8000] {
            let draft = dispatch(encoding)
            #expect(draft.operands.isEmpty)
            #expect(draft.semanticReads == .empty)
            #expect(draft.semanticWrites == .empty)
            #expect(draft.scalableReads == .empty)
            #expect(draft.scalableWrites == .empty)
            #expect(draft.scalableEffect == .none)
            #expect(draft.branchClass == .none)
            #expect(draft.memoryAccess == .none)
            #expect(draft.memoryOrdering == [])
            #expect(draft.flagEffect == .none)
            #expect(draft.address == 0x1_0000_8000)
            #expect(draft.encoding == encoding)
        }
    }
}

/// Validates that the dispatcher attributes a word to the right family across
/// the whole table — the categorization a caller reads off a decoded record.
/// `op0=0` is the case that needs the encoding, not the tier: AMX, SME and UDF
/// all live there, so only the decoded record can say which family a given
/// word belongs to.
@Suite("Dispatch / every family is reachable and correctly attributed")
struct FamilyAttributionTests {
    @Test func everyRepresentativeEncodingReachesItsCategory() {
        // One representative encoding per category the dispatcher can produce.
        let rows: [(encoding: UInt32, category: Category, features: Features)] = [
            (0x9100_0000, .dataProcessingImmediate, .base), // add x0, x0, #0
            (0x1400_0000, .branchesExceptionSystem, .base), // b .
            (0x8B02_0020, .dataProcessingRegister, .base), // add x0, x1, x2
            (0xF940_0000, .loadsAndStores, .base), // ldr x0, [x0]
            (0x1E62_2820, .simdAndFP, .base), // fadd d0, d1, d2
            (0x4E28_4800, .crypto, .base), // aese
            (0xDAC1_0020, .pointerAuthentication, .arm64e), // pacia
            (0x0020_1000, .amx, .base), // amx
            (0x9182_0C5F, .memoryTagging, .base), // addg
            (0x04A0_0000, .sve, .base), // sve
            (0x8080_0000, .sme, .base), // sme
        ]
        for row in rows {
            let category = dispatch(row.encoding, features: row.features).category
            #expect(category == row.category,
                    "0x\(String(row.encoding, radix: 16)) attributed to \(category)")
        }
    }

    @Test func amxAndSMEAreSeparatedByTheirEncodingNotTheirTier() {
        // Both families sit at op0=0, so the tier alone cannot attribute a
        // word — only the decoded record can.
        #expect(dispatch(0x0020_1000).category == .amx)
        #expect(dispatch(0x8080_0000).category == .sme)
    }

    @Test func udfIsAttributedToItsCategoryNotItsTier() {
        // UDF's category is branchesExceptionSystem even though it sits in the
        // op0=0 tier — attribution follows the record, not the op0.
        #expect(dispatch(0x0000_1234).category == .branchesExceptionSystem)
    }

    @Test func theScalableTiersNeedNoFeatureFlag() {
        // The scalable tiers carry no `Features` gate: no other instruction
        // claims their encoding space, so there is nothing to disambiguate
        // and nothing for a caller to opt into. Plain ARM64 decodes them.
        #expect(dispatch(0x04A0_0000, features: .base).category == .sve)
        #expect(dispatch(0x8080_0000, features: .base).category == .sme)
        #expect(dispatch(0x04A0_0000, features: .arm64e).category == .sve)
        #expect(dispatch(0x8080_0000, features: .arm64e).category == .sme)
    }
}
