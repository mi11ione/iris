// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// PAC standalone decoder. Decodes the DPR 1-source PAC family
// (PACIA/B/DA/DB, AUTIA/B/DA/DB, PACIZA/B/DZA/DZB, AUTIZA/B/DZA/DZB,
// XPACI, XPACD) plus PACGA in the DPR 2-source row. Invoked by
// `DataProc2or1SourceDecode` on its deferred PAC branches. The
// HINT-space PAC variants (PACIASP/PACIBSP/PACIAZ/PACIBZ/AUTIASP/
// AUTIBSP/AUTIAZ/AUTIBZ/XPACLRI/PACIA1716/PACIB1716/AUTIA1716/
// AUTIB1716) are owned by BES and NOT handled here.
//
// PACIA vs PACIZA distinction is encoding-driven, not alias-driven:
// the Z bit (bit 13) selects "register-source" (Rn is the modifier) vs
// "zero-source" (Rn fixed XZR, modifier is literal zero). With Z=0 and
// Rn=11111, PACIA still computes AddPACIA(Xd, X31)=SP semantics, NOT
// zero. The mnemonic is therefore chosen by bit 13, never by `Rn==31`.

enum PointerAuthenticationDecode {
    /// PAC standalone in the DPR 1-source slab. Returns nil if opc6 is
    /// outside the PAC subspace [0b000000, 0b010001].
    @_optimize(speed)
    static func decodeOneSource(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        // Self-validate the DPR 1-source PAC row prefix:
        //   bits[31:15] = 11011010110000010 (sf=1, bit 30=1, S=0,
        //   bits[28:21]=11010110, opcode2=00001, bit 15=0).
        if (encoding & 0xFFFF_8000) != 0xDAC1_0000 { return nil }
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        switch opc6 {
        case 0b000000 ... 0b000111:
            // Register-source PAC/AUT. opc6 = 00 0 P D K where
            //   P (bit 12) = 0 PAC / 1 AUT
            //   D (bit 11) = 0 instruction / 1 data
            //   K (bit 10) = 0 A-key / 1 B-key
            return registerSourceDraft(
                opcLow3: opc6 & 0b111, Rn: Rn, Rd: Rd,
                encoding: encoding, address: address,
            )

        case 0b001000 ... 0b001111:
            // Zero-source PAC/AUT. Rn must be 11111 (architecturally
            // required); other values are reserved.
            if Rn != 0b11111 { return nil }
            return zeroSourceDraft(
                opcLow3: opc6 & 0b111, Rd: Rd,
                encoding: encoding, address: address,
            )

        case 0b010000:
            if Rn != 0b11111 { return nil }
            return xpacDraft(.xpaci, Rd: Rd, encoding: encoding, address: address)

        case 0b010001:
            if Rn != 0b11111 { return nil }
            return xpacDraft(.xpacd, Rd: Rd, encoding: encoding, address: address)

        default:
            return nil
        }
    }

    /// PACGA in the DPR 2-source slab. Returns nil otherwise.
    @_optimize(speed)
    static func decodeTwoSource(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft? {
        // Self-validate the DPR 2-source PACGA row prefix:
        //   bits[31:21] = 10011010110 (sf=1, S=0, bit 30=0, bits[28:21]=
        //   11010110), bits[15:10] = 001100 (opc6=PACGA).
        if (encoding & 0xFFE0_FC00) != 0x9AC0_3000 { return nil }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)
        // PACGA operand grammar: <Xd>, <Xn>, <Xm|SP>. Rd/Rn are GPR
        // (no SP); Rm is SP-allowed.
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: .x64, form: .spOrGeneral)
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        reads = insertingNonZero(reg: rmRef, into: reads)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: .pacga,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
        )
    }

    // MARK: - Per-row mnemonic + operand builders

    @inline(__always)
    private static func registerSourceDraft(
        opcLow3: UInt8, Rn: UInt8, Rd: UInt8,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let mnemonic: Mnemonic = switch opcLow3 {
        case 0b000: .pacia
        case 0b001: .pacib
        case 0b010: .pacda
        case 0b011: .pacdb
        case 0b100: .autia
        case 0b101: .autib
        case 0b110: .autda
        default:
            // opcLow3 is `opc6 & 0b111` — a 3-bit field; the only
            // remaining case is 0b111.
            .autdb
        }
        // Rd: GPR (no SP). Rn: GPR-or-SP (modifier source, SP-allowed).
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        // Both sign and auth are in-place transforms of the pointer in Rd:
        // X[d] = AddPAC/Auth(X[d], X[n]). Rd is read (the input pointer) and
        // written (the result); the modifier Rn is read. (ARM ARM
        // `X[d] = AddPACIA(X[d], X[n])`; LLVM ties $dst=$Rd for PAC and AUT.)
        var reads = insertingNonZero(reg: rnRef, into: .empty)
        reads = insertingNonZero(reg: rdRef, into: reads)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operands: [.register(rdRef), .register(rnRef)],
        )
    }

    @inline(__always)
    private static func zeroSourceDraft(
        opcLow3: UInt8, Rd: UInt8,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let mnemonic: Mnemonic = switch opcLow3 {
        case 0b000: .paciza
        case 0b001: .pacizb
        case 0b010: .pacdza
        case 0b011: .pacdzb
        case 0b100: .autiza
        case 0b101: .autizb
        case 0b110: .autdza
        default:
            // opcLow3 is a 3-bit field; the only remaining case is 0b111.
            .autdzb
        }
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        // Zero-modifier sign and auth are both in-place on the pointer in Rd:
        // X[d] = AddPAC/Auth(X[d], 0). Rd is read (input pointer) and written
        // (result). (LLVM ties $dst=$Rd for SignAuthZero, PAC and AUT alike.)
        let reads = insertingNonZero(reg: rdRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operands: [.register(rdRef)],
        )
    }

    @inline(__always)
    private static func xpacDraft(
        _ mnemonic: Mnemonic, Rd: UInt8,
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        // XPACI/XPACD: Rd is read (the signed pointer) and written (the
        // stripped pointer).
        let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
        let reads = insertingNonZero(reg: rdRef, into: .empty)
        let writes = insertingNonZero(reg: rdRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .pointerAuthentication,
            operands: [.register(rdRef)],
        )
    }
}
