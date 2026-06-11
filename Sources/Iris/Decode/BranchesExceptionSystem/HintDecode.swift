// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// HINT (CRm:op2 = 7-bit imm) decode via HintTable lookup.
// Encoding: 1101 0101 0000 0011 0010 imm7 11111
// Every imm7 produces a record. Named aliases (NOP, YIELD, BTI variants,
// PAC HINT-space, etc.) get dedicated mnemonics + optional sub-target
// operand; unrecognized encodings emit `.hint` + `.unsignedImmediate`.

/// One entry in `HintTable.entries`. `mnemonic == .hint` means "unknown
/// imm7"; otherwise the entry's mnemonic is the named alias. `subTargetOperand`
/// is non-zero only for BTI variants (1 = c, 2 = j, 3 = jc); other
/// named aliases carry no operand.
struct HintEntry: Sendable {
    let mnemonic: Mnemonic
    let subTargetOperand: UInt8
}

/// 128-entry static lookup table. Index = imm7 (bits 11:5 of the HINT
/// encoding). Constant-folded at module load.
enum HintTable {
    static let entries: [HintEntry] = HintTable.makeEntries()

    private static func makeEntries() -> [HintEntry] {
        let unknown = HintEntry(mnemonic: .hint, subTargetOperand: 0)
        var table = [HintEntry](repeating: unknown, count: 128)
        // Named aliases. PAC HINT-space mapping per corpus:
        // 1716 variants at 8/10/12/14; Z/SP variants at 24..31.
        table[0] = HintEntry(mnemonic: .nop, subTargetOperand: 0)
        table[1] = HintEntry(mnemonic: .yield, subTargetOperand: 0)
        table[2] = HintEntry(mnemonic: .wfe, subTargetOperand: 0)
        table[3] = HintEntry(mnemonic: .wfi, subTargetOperand: 0)
        table[4] = HintEntry(mnemonic: .sev, subTargetOperand: 0)
        table[5] = HintEntry(mnemonic: .sevl, subTargetOperand: 0)
        table[6] = HintEntry(mnemonic: .dgh, subTargetOperand: 0)
        table[7] = HintEntry(mnemonic: .xpaclri, subTargetOperand: 0)
        table[8] = HintEntry(mnemonic: .pacia1716, subTargetOperand: 0)
        table[10] = HintEntry(mnemonic: .pacib1716, subTargetOperand: 0)
        table[12] = HintEntry(mnemonic: .autia1716, subTargetOperand: 0)
        table[14] = HintEntry(mnemonic: .autib1716, subTargetOperand: 0)
        table[16] = HintEntry(mnemonic: .esb, subTargetOperand: 0)
        table[17] = HintEntry(mnemonic: .psb, subTargetOperand: 0)
        table[18] = HintEntry(mnemonic: .tsb, subTargetOperand: 0)
        table[19] = HintEntry(mnemonic: .gcsbDsync, subTargetOperand: 0)
        table[20] = HintEntry(mnemonic: .csdb, subTargetOperand: 0)
        table[22] = HintEntry(mnemonic: .clrbhb, subTargetOperand: 0)
        table[24] = HintEntry(mnemonic: .paciaz, subTargetOperand: 0)
        table[25] = HintEntry(mnemonic: .paciasp, subTargetOperand: 0)
        table[26] = HintEntry(mnemonic: .pacibz, subTargetOperand: 0)
        table[27] = HintEntry(mnemonic: .pacibsp, subTargetOperand: 0)
        table[28] = HintEntry(mnemonic: .autiaz, subTargetOperand: 0)
        table[29] = HintEntry(mnemonic: .autiasp, subTargetOperand: 0)
        table[30] = HintEntry(mnemonic: .autibz, subTargetOperand: 0)
        table[31] = HintEntry(mnemonic: .autibsp, subTargetOperand: 0)
        table[32] = HintEntry(mnemonic: .bti, subTargetOperand: 0)
        table[34] = HintEntry(mnemonic: .bti, subTargetOperand: 1) // bti c
        table[36] = HintEntry(mnemonic: .bti, subTargetOperand: 2) // bti j
        table[38] = HintEntry(mnemonic: .bti, subTargetOperand: 3) // bti jc
        table[40] = HintEntry(mnemonic: .chkfeat, subTargetOperand: 0)
        return table
    }
}

enum HintDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, imm7: UInt8) -> DecodedDraft {
        let entry = HintTable.entries[Int(imm7)]
        if entry.mnemonic == .hint {
            // Unknown HINT — emit as generic hint with the raw imm7.
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .hint,
                category: .branchesExceptionSystem,
                operands: [.unsignedImmediate(value: UInt64(imm7), width: 7)],
            )
        }
        if entry.subTargetOperand != 0 {
            // Named alias with a sub-target operand (currently only the
            // 3 non-bare BTI variants).
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: entry.mnemonic,
                category: .branchesExceptionSystem,
                operands: [.unsignedImmediate(value: UInt64(entry.subTargetOperand), width: 2)],
            )
        }
        let (reads, writes) = HintDecode.pacImplicitRegisters(for: entry.mnemonic)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: entry.mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            category: .branchesExceptionSystem,
            operands: [],
        )
    }

    /// Implicit register effects of the operand-less HINT-space pointer-auth
    /// instructions (the modifier register and signing/auth target are fixed
    /// in the encoding, so they never appear as operands but must show in the
    /// dataflow sets). Sources: ARM ARM K1 (PACIASP/AUTIASP § sign/auth X30
    /// using SP; PACIAZ/AUTIAZ § zero modifier; PAC*1716/AUT*1716 § X17 from
    /// X16; XPACLRI § strip X30). Every non-PAC HINT (NOP, BTI, barrier-like
    /// sync hints, …) touches no general register, so it falls through to the
    /// empty pair. The {x30, sp} read matches the validated RETAA/RETAB model
    /// in `BranchRegDecode`.
    @inline(__always)
    private static func pacImplicitRegisters(
        for mnemonic: Mnemonic,
    ) -> (reads: RegisterSet, writes: RegisterSet) {
        switch mnemonic {
        // Sign/authenticate X30 using SP as the modifier: read X30 + SP,
        // write X30 (X30 = AddPAC/Auth(X30, SP)).
        case .paciasp, .pacibsp, .autiasp, .autibsp:
            (RegisterSet.empty.inserting(.x(30)).inserting(.sp()),
             RegisterSet.empty.inserting(.x(30)))
        // Sign/authenticate X30 with a zero modifier: read X30, write X30.
        case .paciaz, .pacibz, .autiaz, .autibz:
            (RegisterSet.empty.inserting(.x(30)),
             RegisterSet.empty.inserting(.x(30)))
        // Sign/authenticate X17 using X16 as the modifier: read X17 + X16,
        // write X17 (X17 = AddPAC/Auth(X17, X16)).
        case .pacia1716, .pacib1716, .autia1716, .autib1716:
            (RegisterSet.empty.inserting(.x(17)).inserting(.x(16)),
             RegisterSet.empty.inserting(.x(17)))
        // Strip PAC from X30 (LR): read X30, write X30.
        case .xpaclri:
            (RegisterSet.empty.inserting(.x(30)),
             RegisterSet.empty.inserting(.x(30)))
        default:
            (.empty, .empty)
        }
    }
}
