// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FEAT_LRCPC2 unscaled LDAPUR* / STLUR* forms.
@Suite("L/S LRCPC2 decode")
struct LSLRCPC2Tests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func stlurWordCarriesRelease() {
        let d = decode(0x9900_0000)
        #expect(d.mnemonic == .stlur)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func ldapurDoublewordCarriesAcquire() {
        let d = decode(0xD940_0000)
        #expect(d.mnemonic == .ldapur)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldapurbByteForm() {
        let d = decode(0x1940_0000)
        #expect(d.mnemonic == .ldapurb)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func stlurhHalfwordCarriesRelease() {
        let d = decode(0x5900_0000)
        #expect(d.mnemonic == .stlurh)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func ldapursbSignExtendsToXt() {
        let d = decode(0x1980_0000)
        #expect(d.mnemonic == .ldapursb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func ldapurshAndLdapurswForms() {
        #expect(decode(0x5980_0000).mnemonic == .ldapursh)
        #expect(decode(0x9980_0000).mnemonic == .ldapursw)
    }

    @Test func nonZeroBits11To10ReturnsUndefined() {
        #expect(decode(0x9900_0400).mnemonic == .undefined)
    }

    @Test func nonZeroBit21RoutesToMTE() {
        let d = decode(0xD920_0000)
        #expect(d.mnemonic == .stzgm)
        #expect(d.category == .memoryTagging)
    }

    @Test func nonZeroBit21OutsideMTERowReturnsUndefined() {
        #expect(decode(0x9920_0000).mnemonic == .undefined)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        let d = decode(0xD9C0_0000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }
}
