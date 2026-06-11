// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L14 LRCPC2 class (FEAT_LRCPC2) — the
/// unscaled-immediate load-acquire / store-release forms LDAPUR* / STLUR*.
/// Loads carry `.acquire`, stores carry `.release`; checks the (size,
/// opc) → mnemonic map and the three reserved-encoding guards.
@Suite("L/S LRCPC2 decode")
struct LSLRCPC2Tests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func stlurWordCarriesRelease() {
        // 0x99000000 = stlur w0, [x0].
        let d = decode(0x9900_0000)
        #expect(d.mnemonic == .stlur)
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [.release])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func ldapurDoublewordCarriesAcquire() {
        // 0xd9400000 = ldapur x0, [x0].
        let d = decode(0xD940_0000)
        #expect(d.mnemonic == .ldapur)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldapurbByteForm() {
        // 0x19400000 = ldapurb w0, [x0].
        let d = decode(0x1940_0000)
        #expect(d.mnemonic == .ldapurb)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func stlurhHalfwordCarriesRelease() {
        // 0x59000000 = stlurh w0, [x0].
        let d = decode(0x5900_0000)
        #expect(d.mnemonic == .stlurh)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func ldapursbSignExtendsToXt() {
        // 0x19800000 = ldapursb x0, [x0] — opc=10 → 64-bit Xt.
        let d = decode(0x1980_0000)
        #expect(d.mnemonic == .ldapursb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func ldapurshAndLdapurswForms() {
        // 0x59800000 = ldapursh x0, [x0]; 0x99800000 = ldapursw x0, [x0].
        #expect(decode(0x5980_0000).mnemonic == .ldapursh)
        #expect(decode(0x9980_0000).mnemonic == .ldapursw)
    }

    @Test func nonZeroBits11To10ReturnsUndefined() {
        // 0x99000400 — bits[11:10] must be 00 for a valid LRCPC2 encoding.
        #expect(decode(0x9900_0400).mnemonic == .undefined)
    }

    @Test func nonZeroBit21RoutesToMTE() {
        // 0xD9200000 — bits[31:24] = 0xD9 with bit 21 = 1 selects the MTE
        // L/S row (the crypto/Apple-extensions family owns it); the L/S
        // decoder's case 0b011001 delegates
        // to MemoryTaggingDecode.decodeLS. opc1=00, op2=00, simm9=0 → STZGM.
        let d = decode(0xD920_0000)
        #expect(d.mnemonic == .stzgm)
        #expect(d.category == .memoryTagging)
    }

    @Test func nonZeroBit21OutsideMTERowReturnsUndefined() {
        // 0x99200000 — bit 21 = 1 but bits[31:24] = 0x99 (not 0xD9, so
        // outside MTE L/S row). After routing into the LRCPC2 case branch
        // and bit-21 discriminator, MemoryTaggingDecode.decodeLS rejects
        // the row and the L/S decoder emits UNDEFINED.
        #expect(decode(0x9920_0000).mnemonic == .undefined)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        // 0xd9c00000 — size=11, opc=11 has no LRCPC2 instruction.
        let d = decode(0xD9C0_0000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }
}
