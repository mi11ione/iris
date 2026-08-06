// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FEAT_LSCP acquire/release register pairs sharing the 011001
/// RCPC3-pair shell and the MOPS SETGO option forms whose source-register
/// field is fixed to 11111.
@Suite("L/S — LSCP pairs and MOPS SETGO")
struct LSPairAndSetGOTests {
    @Test func setGODecodesEveryStageAndOptionCombination() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0x1DDF_0022, .setgop, "setgop [x2]!, x1!"),
            (0x1DDF_1022, .setgopt, "setgopt [x2]!, x1!"),
            (0x1DDF_2022, .setgopn, "setgopn [x2]!, x1!"),
            (0x1DDF_3022, .setgoptn, "setgoptn [x2]!, x1!"),
            (0x1DDF_4022, .setgom, "setgom [x2]!, x1!"),
            (0x1DDF_5022, .setgomt, "setgomt [x2]!, x1!"),
            (0x1DDF_6022, .setgomn, "setgomn [x2]!, x1!"),
            (0x1DDF_7022, .setgomtn, "setgomtn [x2]!, x1!"),
            (0x1DDF_8022, .setgoe, "setgoe [x2]!, x1!"),
            (0x1DDF_9022, .setgoet, "setgoet [x2]!, x1!"),
            (0x1DDF_A022, .setgoen, "setgoen [x2]!, x1!"),
            (0x1DDF_B022, .setgoetn, "setgoetn [x2]!, x1!"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .loadsAndStores)
            #expect(d.memoryAccess == .atomic)
            #expect(d.memoryOrdering == [])
            #expect(d.flagEffect == .none)
            #expect(d.branchClass == .none)
            #expect(d.operands.count == 2)
            #expect(d.text == row.text)
        }
    }

    @Test func setGOReadsAndWritesBothAddressAndSizeRegisters() {
        let d = decode(0x1DDF_0022)
        #expect(d.semanticReads.contains(.x(1)))
        #expect(d.semanticReads.contains(.x(2)))
        #expect(d.semanticWrites.contains(.x(1)))
        #expect(d.semanticWrites.contains(.x(2)))
    }

    @Test func setGORejectsReservedStageAndAliasedRegisters() {
        #expect(decode(0x1DDF_C022).isUndefined)
        #expect(decode(0x1DDF_003F).isUndefined)
        #expect(decode(0x1DDF_0042).isUndefined)
        #expect(decode(0x1DDE_0022).isUndefined)
        #expect(decode(0x5DDF_0022).isUndefined)
    }

    @Test func setGOShellDoesNotCaptureTheThreeOperandSETGP() {
        let d = decode(0x1DDF_0422)
        #expect(d.mnemonic == .setgp)
        #expect(d.text == "setgp [x2]!, x1!, xzr")
    }

    @Test func lscpPairsDecodeAcrossRegisterFillings() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0xD900_5822, .stlp, "stlp x2, x0, [x1]"),
            (0xD91F_5BFF, .stlp, "stlp xzr, xzr, [sp]"),
            (0xD91E_5805, .stlp, "stlp x5, x30, [x0]"),
            (0xD940_5822, .ldap, "ldap x2, x0, [x1]"),
            (0xD95F_5BFF, .ldap, "ldap xzr, xzr, [sp]"),
            (0xD95E_5805, .ldap, "ldap x5, x30, [x0]"),
            (0xD940_7822, .ldapp, "ldapp x2, x0, [x1]"),
            (0xD95F_7BFF, .ldapp, "ldapp xzr, xzr, [sp]"),
            (0xD95E_7805, .ldapp, "ldapp x5, x30, [x0]"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.category == .loadsAndStores)
            #expect(d.branchClass == .none)
            #expect(d.flagEffect == .none)
            #expect(d.operands.count == 3)
            #expect(d.text == row.text)
        }
    }

    @Test func lscpLoadsAcquireAndStoresRelease() {
        let load = decode(0xD940_5822)
        #expect(load.memoryAccess == .load)
        #expect(load.memoryOrdering == [.acquire])
        #expect(load.semanticReads.contains(.x(1)))
        #expect(load.semanticWrites.contains(.x(0)))
        #expect(load.semanticWrites.contains(.x(2)))
        let pair = decode(0xD940_7822)
        #expect(pair.memoryAccess == .load)
        #expect(pair.memoryOrdering == [.acquire])
        let store = decode(0xD900_5822)
        #expect(store.memoryAccess == .store)
        #expect(store.memoryOrdering == [.release])
        #expect(store.semanticReads.contains(.x(0)))
        #expect(store.semanticReads.contains(.x(1)))
        #expect(store.semanticReads.contains(.x(2)))
        #expect(store.semanticWrites == .empty)
    }

    @Test func lscpRejectsNarrowSizesAndUnallocatedShells() {
        #expect(decode(0x9940_5822).isUndefined)
        #expect(decode(0xD980_5822).isUndefined)
        #expect(decode(0xD900_7822).isUndefined)
        #expect(decode(0xD940_4822).isUndefined)
    }
}
