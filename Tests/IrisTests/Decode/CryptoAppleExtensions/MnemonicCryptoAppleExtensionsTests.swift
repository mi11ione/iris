// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the crypto/Apple-extensions mnemonic constants and the
/// sub-range carve-up: every crypto mnemonic falls in [12288, 12351],
/// every PAC standalone in [12352, 12415], every MTE in [12416, 12479],
/// every AMX (documented + amxUnknownOp) in [12480, 12527]. Also
/// verifies the family's master range [12288, 16383] from
/// `Mnemonic.allocations` contains every constant.
@Suite("CryptoAppleExtensions / Mnemonic constant allocations")
struct MnemonicCryptoAppleExtensionsTests {
    @Test func cryptoMnemonicsAllInCryptoSubRange() {
        let crypto: [Mnemonic] = [
            .aese, .aesd, .aesmc, .aesimc,
            .sha1c, .sha1p, .sha1m, .sha1su0, .sha1h, .sha1su1,
            .sha256h, .sha256h2, .sha256su0, .sha256su1,
            .eor3, .bcax, .xar, .rax1,
            .sha512h, .sha512h2, .sha512su0, .sha512su1,
            .sm3ss1, .sm3tt1a, .sm3tt1b, .sm3tt2a, .sm3tt2b,
            .sm3partw1, .sm3partw2,
            .sm4e, .sm4ekey,
        ]
        for m in crypto {
            #expect(m.rawValue >= 12288, "\(m.rawValue) below crypto sub-range")
            #expect(m.rawValue <= 12351, "\(m.rawValue) above crypto sub-range")
        }
    }

    @Test func pacMnemonicsAllInPACSubRange() {
        let pac: [Mnemonic] = [
            .pacia, .pacib, .pacda, .pacdb,
            .autia, .autib, .autda, .autdb,
            .paciza, .pacizb, .pacdza, .pacdzb,
            .autiza, .autizb, .autdza, .autdzb,
            .xpaci, .xpacd, .pacga,
        ]
        for m in pac {
            #expect(m.rawValue >= 12352, "\(m.rawValue) below PAC sub-range")
            #expect(m.rawValue <= 12415, "\(m.rawValue) above PAC sub-range")
        }
    }

    @Test func mteMnemonicsAllInMTESubRange() {
        let mte: [Mnemonic] = [
            .addg, .subg,
            .irg, .gmi, .subp, .subps,
            .ldg, .stg, .st2g, .stzg, .stz2g,
            .ldgm, .stgm, .stzgm,
        ]
        for m in mte {
            #expect(m.rawValue >= 12416, "\(m.rawValue) below MTE sub-range")
            #expect(m.rawValue <= 12479, "\(m.rawValue) above MTE sub-range")
        }
    }

    @Test func amxMnemonicsAllInAMXSubRange() {
        let amx: [Mnemonic] = [
            .amxLdx, .amxLdy, .amxStx, .amxSty,
            .amxLdz, .amxStz, .amxLdzi, .amxStzi,
            .amxExtrx, .amxExtry,
            .amxFma64, .amxFms64, .amxFma32, .amxFms32, .amxMac16,
            .amxFma16, .amxFms16,
            .amxSet, .amxClr,
            .amxVecint, .amxVecfp, .amxMatint, .amxMatfp, .amxGenlut,
            .amxUnknownOp,
        ]
        for m in amx {
            #expect(m.rawValue >= 12480, "\(m.rawValue) below AMX sub-range")
            #expect(m.rawValue <= 12527, "\(m.rawValue) above AMX sub-range")
        }
    }

    @Test func every2_7MnemonicIsInMasterAllocationRange() throws {
        let allocation = try #require(Mnemonic.allocations.first { $0.label == "Crypto + Apple Extensions" })
        let allMnemonics: [Mnemonic] = [
            .aese, .aesd, .aesmc, .aesimc,
            .sha1c, .sha1p, .sha1m, .sha1su0, .sha1h, .sha1su1,
            .sha256h, .sha256h2, .sha256su0, .sha256su1,
            .eor3, .bcax, .xar, .rax1,
            .sha512h, .sha512h2, .sha512su0, .sha512su1,
            .sm3ss1, .sm3tt1a, .sm3tt1b, .sm3tt2a, .sm3tt2b,
            .sm3partw1, .sm3partw2,
            .sm4e, .sm4ekey,
            .pacia, .pacib, .pacda, .pacdb,
            .autia, .autib, .autda, .autdb,
            .paciza, .pacizb, .pacdza, .pacdzb,
            .autiza, .autizb, .autdza, .autdzb,
            .xpaci, .xpacd, .pacga,
            .addg, .subg,
            .irg, .gmi, .subp, .subps,
            .ldg, .stg, .st2g, .stzg, .stz2g,
            .ldgm, .stgm, .stzgm,
            .amxLdx, .amxLdy, .amxStx, .amxSty,
            .amxLdz, .amxStz, .amxLdzi, .amxStzi,
            .amxExtrx, .amxExtry,
            .amxFma64, .amxFms64, .amxFma32, .amxFms32, .amxMac16,
            .amxFma16, .amxFms16,
            .amxSet, .amxClr,
            .amxVecint, .amxVecfp, .amxMatint, .amxMatfp, .amxGenlut,
            .amxUnknownOp,
        ]
        for m in allMnemonics {
            #expect(allocation.range.contains(m.rawValue),
                    "\(m.rawValue) outside the family's master range \(allocation.range)")
        }
    }

    @Test func allMnemonicValuesArePairwiseDistinct() {
        let allMnemonics: [Mnemonic] = [
            .aese, .aesd, .aesmc, .aesimc,
            .sha1c, .sha1p, .sha1m, .sha1su0, .sha1h, .sha1su1,
            .sha256h, .sha256h2, .sha256su0, .sha256su1,
            .eor3, .bcax, .xar, .rax1,
            .sha512h, .sha512h2, .sha512su0, .sha512su1,
            .sm3ss1, .sm3tt1a, .sm3tt1b, .sm3tt2a, .sm3tt2b,
            .sm3partw1, .sm3partw2,
            .sm4e, .sm4ekey,
            .pacia, .pacib, .pacda, .pacdb,
            .autia, .autib, .autda, .autdb,
            .paciza, .pacizb, .pacdza, .pacdzb,
            .autiza, .autizb, .autdza, .autdzb,
            .xpaci, .xpacd, .pacga,
            .addg, .subg,
            .irg, .gmi, .subp, .subps,
            .ldg, .stg, .st2g, .stzg, .stz2g,
            .ldgm, .stgm, .stzgm,
            .amxLdx, .amxLdy, .amxStx, .amxSty,
            .amxLdz, .amxStz, .amxLdzi, .amxStzi,
            .amxExtrx, .amxExtry,
            .amxFma64, .amxFms64, .amxFma32, .amxFms32, .amxMac16,
            .amxFma16, .amxFms16,
            .amxSet, .amxClr,
            .amxVecint, .amxVecfp, .amxMatint, .amxMatfp, .amxGenlut,
            .amxUnknownOp,
        ]
        let raws = allMnemonics.map(\.rawValue)
        #expect(Set(raws).count == raws.count)
    }
}
