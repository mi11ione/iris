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
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: entry.mnemonic,
            category: .branchesExceptionSystem,
            operands: [],
        )
    }
}
