// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the v9.x load/store extension families sharing the 011001 /
/// 111000 / 001001 shells.
@Suite("L/S v9 extensions — LSE128 / RCW / LSUI / RCPC3 / GCS / LS64")
struct LSV9ExtensionsTests {
    @Test func lse128PairAtomicsDecodeAllOpsAndOrderings() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1922_1061, .ldclrp, "ldclrp x1, x2, [x3]"),
            (0x1922_3061, .ldsetp, "ldsetp x1, x2, [x3]"),
            (0x1922_8061, .swpp, "swpp x1, x2, [x3]"),
            (0x19A2_1061, .ldclrpa, "ldclrpa x1, x2, [x3]"),
            (0x1962_1061, .ldclrpl, "ldclrpl x1, x2, [x3]"),
            (0x19E2_1061, .ldclrpal, "ldclrpal x1, x2, [x3]"),
            (0x19A2_3061, .ldsetpa, "ldsetpa x1, x2, [x3]"),
            (0x1962_3061, .ldsetpl, "ldsetpl x1, x2, [x3]"),
            (0x19E2_3061, .ldsetpal, "ldsetpal x1, x2, [x3]"),
            (0x19A2_8061, .swppa, "swppa x1, x2, [x3]"),
            (0x1962_8061, .swppl, "swppl x1, x2, [x3]"),
            (0x19E2_8061, .swppal, "swppal x1, x2, [x3]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .loadsAndStores)
            #expect(d.memoryAccess == .atomic)
            #expect(d.text == row.text)
            #expect(d.semanticReads.contains(.x(1)) && d.semanticReads.contains(.x(2))
                && d.semanticReads.contains(.x(3)))
            #expect(d.semanticWrites.contains(.x(1)))
        }
        #expect(decode(0x19A2_1061).memoryOrdering == [.acquire])
        #expect(decode(0x1962_1061).memoryOrdering == [.release])
        #expect(decode(0x19E2_1061).memoryOrdering == [.acquire, .release])
    }

    @Test func lse128ReservedFormsAreUndefined() {
        #expect(decode(0x1922_107F).isUndefined)
        #expect(decode(0x193F_1061).isUndefined)
        #expect(decode(0x1922_0061).isUndefined)
        #expect(decode(0x5922_1061).isUndefined)
    }

    @Test func rcwNonPairAtomicsDecodeBothStrengthsAndOrderings() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x3821_9062, .rcwclr, "rcwclr x1, x2, [x3]"),
            (0x3821_A062, .rcwswp, "rcwswp x1, x2, [x3]"),
            (0x3821_B062, .rcwset, "rcwset x1, x2, [x3]"),
            (0x7821_9062, .rcwsclr, "rcwsclr x1, x2, [x3]"),
            (0x7821_A062, .rcwsswp, "rcwsswp x1, x2, [x3]"),
            (0x7821_B062, .rcwsset, "rcwsset x1, x2, [x3]"),
            (0x38A1_9062, .rcwclra, "rcwclra x1, x2, [x3]"),
            (0x3861_9062, .rcwclrl, "rcwclrl x1, x2, [x3]"),
            (0x38E1_9062, .rcwclral, "rcwclral x1, x2, [x3]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == .atomic)
            #expect(d.text == row.text)
        }
    }

    @Test func rcwCasDecodesOrderingsAndRejectsNonZeroOp() {
        let rows: [(word: UInt32, mnemonic: Mnemonic)] = [
            (0x1921_0862, .rcwcas), (0x19A1_0862, .rcwcasa),
            (0x1961_0862, .rcwcasl), (0x19E1_0862, .rcwcasal),
            (0x5921_0862, .rcwscas), (0x59A1_0862, .rcwscasa),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == .atomic)
            #expect(d.semanticReads.contains(.x(1)) && d.semanticReads.contains(.x(2)))
            #expect(d.semanticWrites.contains(.x(2)))
        }
        #expect(decode(0x1921_0862).text == "rcwcas x1, x2, [x3]")
        #expect(decode(0x1921_1862).isUndefined)
    }

    @Test func rcwCaspDecodesPairsAndRejectsOddRegisters() {
        let rows: [(word: UInt32, mnemonic: Mnemonic)] = [
            (0x1922_0C80, .rcwcasp), (0x19A2_0C80, .rcwcaspa),
            (0x1962_0C80, .rcwcaspl), (0x19E2_0C80, .rcwcaspal),
            (0x5922_0C80, .rcwscasp),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == .atomic)
        }
        let d = decode(0x1922_0C80)
        #expect(d.text == "rcwcasp x2, x3, x0, x1, [x4]")
        #expect(d.semanticWrites.contains(.x(2)) && d.semanticWrites.contains(.x(3)))
        #expect(decode(0x1921_0C80).isUndefined)
        #expect(decode(0x1922_0C81).isUndefined)
        #expect(decode(0x1922_1C80).isUndefined)
    }

    @Test func rcwPairAtomicsDecodeAndRejectZrEncodings() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1922_9061, .rcwclrp, "rcwclrp x1, x2, [x3]"),
            (0x1922_A061, .rcwswpp, "rcwswpp x1, x2, [x3]"),
            (0x1922_B061, .rcwsetp, "rcwsetp x1, x2, [x3]"),
            (0x5922_9061, .rcwsclrp, "rcwsclrp x1, x2, [x3]"),
            (0x5922_A061, .rcwsswpp, "rcwsswpp x1, x2, [x3]"),
            (0x5922_B061, .rcwssetp, "rcwssetp x1, x2, [x3]"),
            (0x19A2_9061, .rcwclrpa, "rcwclrpa x1, x2, [x3]"),
            (0x1962_9061, .rcwclrpl, "rcwclrpl x1, x2, [x3]"),
            (0x19E2_9061, .rcwclrpal, "rcwclrpal x1, x2, [x3]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == .atomic)
            #expect(d.text == row.text)
        }
        #expect(decode(0x1922_907F).isUndefined)
        #expect(decode(0x193F_9061).isUndefined)
    }

    @Test func lsuiAtomicsDecodeAllOpsWidthsAndStAliases() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1921_0462, .ldtadd, "ldtadd w1, w2, [x3]"),
            (0x5921_0462, .ldtadd, "ldtadd x1, x2, [x3]"),
            (0x19A1_0462, .ldtadda, "ldtadda w1, w2, [x3]"),
            (0x1961_0462, .ldtaddl, "ldtaddl w1, w2, [x3]"),
            (0x19E1_0462, .ldtaddal, "ldtaddal w1, w2, [x3]"),
            (0x1921_1462, .ldtclr, "ldtclr w1, w2, [x3]"),
            (0x19A1_1462, .ldtclra, "ldtclra w1, w2, [x3]"),
            (0x1921_3462, .ldtset, "ldtset w1, w2, [x3]"),
            (0x19A1_3462, .ldtseta, "ldtseta w1, w2, [x3]"),
            (0x1921_8462, .swpt, "swpt w1, w2, [x3]"),
            (0x19A1_8462, .swpta, "swpta w1, w2, [x3]"),
            (0x1961_8462, .swptl, "swptl w1, w2, [x3]"),
            (0x19E1_8462, .swptal, "swptal w1, w2, [x3]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == .atomic)
            #expect(d.text == row.text)
        }
        let aliases: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1921_047F, .sttadd, "sttadd w1, [x3]"),
            (0x1961_047F, .sttaddl, "sttaddl w1, [x3]"),
            (0x1921_147F, .sttclr, "sttclr w1, [x3]"),
            (0x1961_147F, .sttclrl, "sttclrl w1, [x3]"),
            (0x1921_347F, .sttset, "sttset w1, [x3]"),
            (0x1961_347F, .sttsetl, "sttsetl w1, [x3]"),
            (0x1921_847F, .swpt, "swpt w1, wzr, [x3]"),
            (0x19A1_047F, .ldtadda, "ldtadda w1, wzr, [x3]"),
        ]
        for row in aliases {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.text == row.text)
        }
        #expect(decode(0x1921_2462).isUndefined)
    }

    @Test func lsuiExclusiveAndCasFormsDecode() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String, access: MemoryAccess)] = [
            (0x8901_0062, .sttxr, "sttxr w1, w2, [x3]", .exclusiveStore),
            (0x8901_8062, .stltxr, "stltxr w1, w2, [x3]", .exclusiveStore),
            (0xC901_0062, .sttxr, "sttxr w1, x2, [x3]", .exclusiveStore),
            (0x895F_0062, .ldtxr, "ldtxr w2, [x3]", .exclusiveLoad),
            (0x895F_8062, .ldatxr, "ldatxr w2, [x3]", .exclusiveLoad),
            (0xC95F_0062, .ldtxr, "ldtxr x2, [x3]", .exclusiveLoad),
            (0xC981_0062, .cast, "cast x1, x2, [x3]", .atomic),
            (0xC9C1_0062, .casat, "casat x1, x2, [x3]", .atomic),
            (0xC981_8062, .caslt, "caslt x1, x2, [x3]", .atomic),
            (0xC9C1_8062, .casalt, "casalt x1, x2, [x3]", .atomic),
            (0x4982_0080, .caspt, "caspt x2, x3, x0, x1, [x4]", .atomic),
            (0x49C2_0080, .caspat, "caspat x2, x3, x0, x1, [x4]", .atomic),
            (0x4982_8080, .casplt, "casplt x2, x3, x0, x1, [x4]", .atomic),
            (0x49C2_8080, .caspalt, "caspalt x2, x3, x0, x1, [x4]", .atomic),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == row.access)
            #expect(d.text == row.text)
        }
        #expect(decode(0x0901_0062).isUndefined)
        #expect(decode(0x0980_0080).isUndefined)
        #expect(decode(0x8980_0062).isUndefined)
        #expect(decode(0x4981_0080).isUndefined)
        #expect(decode(0x4982_0081).isUndefined)
        #expect(decode(0x8921_0062).isUndefined)
    }

    @Test func rcpc3OrderedPairsDecodeWithAndWithoutWriteback() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String, access: MemoryAccess, ordering: MemoryOrdering)] = [
            (0x9902_0861, .stilp, "stilp w1, w2, [x3, #-8]!", .store, [.release]),
            (0x9902_1861, .stilp, "stilp w1, w2, [x3]", .store, [.release]),
            (0xD902_0861, .stilp, "stilp x1, x2, [x3, #-16]!", .store, [.release]),
            (0x9942_0861, .ldiapp, "ldiapp w1, w2, [x3], #8", .load, [.acquire]),
            (0xD942_0861, .ldiapp, "ldiapp x1, x2, [x3], #16", .load, [.acquire]),
            (0xD942_1861, .ldiapp, "ldiapp x1, x2, [x3]", .load, [.acquire]),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == row.access)
            #expect(d.memoryOrdering == row.ordering)
            #expect(d.text == row.text)
        }
        #expect(decode(0x9902_0861).semanticWrites.contains(.x(3)))
        #expect(!decode(0x9902_1861).semanticWrites.contains(.x(3)))
        #expect(decode(0x1902_0861).isUndefined)
        #expect(decode(0x9902_2861).isUndefined)
    }

    @Test func rcpc3WritebackSinglesDecode() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String, access: MemoryAccess)] = [
            (0x9980_0861, .stlr, "stlr w1, [x3, #-4]!", .store),
            (0xD980_0861, .stlr, "stlr x1, [x3, #-8]!", .store),
            (0x99C0_0861, .ldapr, "ldapr w1, [x3], #4", .load),
            (0xD9C0_0861, .ldapr, "ldapr x1, [x3], #8", .load),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.memoryAccess == row.access)
            #expect(d.text == row.text)
            #expect(d.semanticWrites.contains(.x(3)))
        }
        #expect(decode(0x1980_0861).isUndefined)
        #expect(decode(0x9981_0861).isUndefined)
        #expect(decode(0x9980_1861).isUndefined)
    }

    @Test func unprivilegedNoAllocatePairLoadDecodes() {
        let d = decode(0xE840_0861)
        #expect(d.mnemonic == .ldtnp)
        #expect(d.text == "ldtnp x1, x2, [x3]")
    }

    @Test func orderedAndPrefetchReservedShapesAreUndefined() {
        #expect(decode(0xD940_0420).isUndefined)
        #expect(decode(0xF8A2_0838).isUndefined)
    }

    @Test func gcsStoresDecodeAndRejectMalformedFixedFields() {
        let str = decode(0xD91F_0C41)
        #expect(str.mnemonic == .gcsstr)
        #expect(str.memoryAccess == .store)
        #expect(str.text == "gcsstr x1, [x2]")
        #expect(str.semanticReads.contains(.x(1)) && str.semanticReads.contains(.x(2)))
        let sttr = decode(0xD91F_1C41)
        #expect(sttr.mnemonic == .gcssttr)
        #expect(sttr.text == "gcssttr x1, [x2]")
        #expect(decode(0x191F_0C41).isUndefined)
        #expect(decode(0xD95F_0C41).isUndefined)
        #expect(decode(0xD900_0C41).isUndefined)
        #expect(decode(0xD91F_2C41).isUndefined)
    }

    @Test func ls64TransfersDecodeAndEnforceRegisterGroupRules() {
        let ld = decode(0xF83F_D060)
        #expect(ld.mnemonic == .ld64b)
        #expect(ld.memoryAccess == .load)
        #expect(ld.text == "ld64b x0, [x3]")
        #expect(ld.semanticWrites.contains(.x(0)))
        let st = decode(0xF83F_9060)
        #expect(st.mnemonic == .st64b)
        #expect(st.memoryAccess == .store)
        #expect(st.text == "st64b x0, [x3]")
        let stv = decode(0xF821_B060)
        #expect(stv.mnemonic == .st64bv)
        #expect(stv.text == "st64bv x1, x0, [x3]")
        #expect(stv.semanticWrites.contains(.x(1)))
        let stv0 = decode(0xF821_A060)
        #expect(stv0.mnemonic == .st64bv0)
        #expect(stv0.text == "st64bv0 x1, x0, [x3]")
        #expect(decode(0xF83F_D061).isUndefined)
        #expect(decode(0xF83F_D078).isUndefined)
        #expect(decode(0xF821_D060).isUndefined)
        #expect(decode(0xF821_9060).isUndefined)
        #expect(decode(0xB83F_D060).isUndefined)
    }

    @Test func mopsCopyAndSetDecodeStagesOptionsAndGuards() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1901_0440, .cpyfp, "cpyfp [x0]!, [x1]!, x2!"),
            (0x1941_0440, .cpyfm, "cpyfm [x0]!, [x1]!, x2!"),
            (0x1981_0440, .cpyfe, "cpyfe [x0]!, [x1]!, x2!"),
            (0x1D01_0440, .cpyp, "cpyp [x0]!, [x1]!, x2!"),
            (0x1D41_0440, .cpym, "cpym [x0]!, [x1]!, x2!"),
            (0x1D81_0440, .cpye, "cpye [x0]!, [x1]!, x2!"),
            (0x1901_1440, .cpyfpwt, "cpyfpwt [x0]!, [x1]!, x2!"),
            (0x1901_C440, .cpyfpn, "cpyfpn [x0]!, [x1]!, x2!"),
            (0x19C2_0420, .setp, "setp [x0]!, x1!, x2"),
            (0x19C2_1420, .setpt, "setpt [x0]!, x1!, x2"),
            (0x19C2_2420, .setpn, "setpn [x0]!, x1!, x2"),
            (0x19C2_3420, .setptn, "setptn [x0]!, x1!, x2"),
            (0x19C2_4420, .setm, "setm [x0]!, x1!, x2"),
            (0x19C2_8420, .sete, "sete [x0]!, x1!, x2"),
            (0x1DC2_0420, .setgp, "setgp [x0]!, x1!, x2"),
            (0x1DC2_4420, .setgm, "setgm [x0]!, x1!, x2"),
            (0x1DC2_8420, .setge, "setge [x0]!, x1!, x2"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .loadsAndStores)
            #expect(d.memoryAccess == .atomic)
            #expect(d.text == row.text)
        }
        let cpy = decode(0x1901_0440)
        #expect(cpy.semanticReads.contains(.x(0)) && cpy.semanticReads.contains(.x(1))
            && cpy.semanticReads.contains(.x(2)))
        #expect(cpy.semanticWrites == cpy.semanticReads)
        let set = decode(0x19C2_0420)
        #expect(set.semanticReads.contains(.x(2)))
        #expect(!set.semanticWrites.contains(.x(2)))
        #expect(decode(0x5901_0440).isUndefined)
        #expect(decode(0x1901_0420).isUndefined)
        #expect(decode(0x1901_045F).isUndefined)
        #expect(decode(0x191F_0440).isUndefined)
        #expect(decode(0x19C2_C420).isUndefined)
    }
}
