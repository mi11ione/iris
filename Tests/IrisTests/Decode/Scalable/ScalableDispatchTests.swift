// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func dispatch(_ encoding: UInt32, features: Features = .base) -> Instruction {
    Iris.decode(encoding, at: 0x1_0000_8000, features: features)
}

/// Validates that the dispatcher routes the two tiers reclaimed from reserved
/// space.
@Suite("Dispatch / SVE and SME tiers route through the standard table")
struct ScalableDispatchRoutingTests {
    @Test func sveEncodingsDispatchToTheSVEFamily() {
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
        for encoding: UInt32 in [0x4400_0000, 0x6400_0000, 0x8400_C010, 0xA400_8000, 0x056E_4116] {
            let draft = dispatch(encoding)
            #expect(draft.category == .sve, "0x\(String(encoding, radix: 16)) is not .sve")
            #expect(draft.mnemonic == .undefined)
            #expect(draft.encoding == encoding)
        }
    }

    @Test func smeEncodingsDispatchToTheSMEFamily() {
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
        for opcode: UInt32 in 0 ..< 23 {
            let encoding = 0x0020_1000 | (opcode << 5)
            #expect(dispatch(encoding).category == .amx, "AMX opcode \(opcode) lost its routing")
        }
    }

    @Test func udfIsStillInterceptedBeforeFamilyDispatch() {
        for imm: UInt32 in [0, 1, 0xFFFF, 0x1234] {
            let draft = dispatch(imm)
            #expect(draft.mnemonic == .udf)
            #expect(draft.category == .branchesExceptionSystem)
            #expect(Array(draft.operands) == [.unsignedImmediate(value: UInt64(imm), width: 16)])
        }
    }

    @Test func op0ZeroHolesStillDispatchToUndefined() {
        for encoding: UInt32 in [0x0020_0000, 0x0020_1400, 0x0100_0000, 0x01FF_FFFF] {
            #expect((encoding >> 25) & 0xF == 0, "fixture must be an op0=0 word")
            let draft = dispatch(encoding)
            #expect(draft.category == .undefined, "0x\(String(encoding, radix: 16))")
            #expect(draft.mnemonic == .undefined)
        }
    }

    @Test func theStillUnallocatedTiersRemainUndefined() {
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

/// Validates that the dispatcher attributes a word to the right family.
@Suite("Dispatch / every family is reachable and correctly attributed")
struct FamilyAttributionTests {
    @Test func everyRepresentativeEncodingReachesItsCategory() {
        let rows: [(encoding: UInt32, category: Category, features: Features)] = [
            (0x9100_0000, .dataProcessingImmediate, .base),
            (0x1400_0000, .branchesExceptionSystem, .base),
            (0x8B02_0020, .dataProcessingRegister, .base),
            (0xF940_0000, .loadsAndStores, .base),
            (0x1E62_2820, .simdAndFP, .base),
            (0x4E28_4800, .crypto, .base),
            (0xDAC1_0020, .pointerAuthentication, .arm64e),
            (0x0020_1000, .amx, .base),
            (0x9182_0C5F, .memoryTagging, .base),
            (0x04A0_0000, .sve, .base),
            (0x8080_0000, .sme, .base),
        ]
        for row in rows {
            let category = dispatch(row.encoding, features: row.features).category
            #expect(category == row.category,
                    "0x\(String(row.encoding, radix: 16)) attributed to \(category)")
        }
    }

    @Test func amxAndSMEAreSeparatedByTheirEncodingNotTheirTier() {
        #expect(dispatch(0x0020_1000).category == .amx)
        #expect(dispatch(0x8080_0000).category == .sme)
    }

    @Test func udfIsAttributedToItsCategoryNotItsTier() {
        #expect(dispatch(0x0000_1234).category == .branchesExceptionSystem)
    }

    @Test func theScalableTiersNeedNoFeatureFlag() {
        #expect(dispatch(0x04A0_0000, features: .base).category == .sve)
        #expect(dispatch(0x8080_0000, features: .base).category == .sme)
        #expect(dispatch(0x04A0_0000, features: .arm64e).category == .sve)
        #expect(dispatch(0x8080_0000, features: .arm64e).category == .sme)
    }
}
