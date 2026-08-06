// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// One entry in `HintTable.entries`.
struct HintEntry: Sendable {
    let mnemonic: Mnemonic
    let subTargetOperand: UInt8
}

/// 128-entry static lookup table.
enum HintTable {
    static let entries: [HintEntry] = HintTable.makeEntries()

    private static func makeEntries() -> [HintEntry] {
        let unknown = HintEntry(mnemonic: .hint, subTargetOperand: 0)
        var table = [HintEntry](repeating: unknown, count: 128)
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
        table[34] = HintEntry(mnemonic: .bti, subTargetOperand: 1)
        table[36] = HintEntry(mnemonic: .bti, subTargetOperand: 2)
        table[38] = HintEntry(mnemonic: .bti, subTargetOperand: 3)
        table[39] = HintEntry(mnemonic: .pacm, subTargetOperand: 0)
        table[40] = HintEntry(mnemonic: .chkfeat, subTargetOperand: 0)
        table[48] = HintEntry(mnemonic: .stshh, subTargetOperand: 0)
        table[49] = HintEntry(mnemonic: .stshh, subTargetOperand: 1)
        table[50] = HintEntry(mnemonic: .shuh, subTargetOperand: 0)
        table[51] = HintEntry(mnemonic: .shuh, subTargetOperand: 1)
        table[52] = HintEntry(mnemonic: .stcph, subTargetOperand: 0)
        table[53] = HintEntry(mnemonic: .stshh, subTargetOperand: 5)
        table[54] = HintEntry(mnemonic: .stshh, subTargetOperand: 6)
        table[55] = HintEntry(mnemonic: .stshh, subTargetOperand: 7)
        return table
    }
}

enum HintDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, imm7: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let entry = HintTable.entries[Int(imm7)]
        if entry.mnemonic == .hint {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .hint,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.unsignedImmediate(value: UInt64(imm7), width: 7)),
            )
        }
        let width = HintDecode.subTargetWidth(for: entry.mnemonic)
        if width != 0 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: entry.mnemonic,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.unsignedImmediate(value: UInt64(entry.subTargetOperand), width: width)),
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
            operandCount: 0,
        )
    }

    /// Bit width of the sub-target operand a HINT alias carries, or 0 when the
    /// alias takes none.
    @inline(__always)
    private static func subTargetWidth(for mnemonic: Mnemonic) -> UInt8 {
        switch mnemonic {
        case .bti: 2
        case .stshh, .shuh: 3
        default: 0
        }
    }

    /// Implicit register effects of the operand-less HINT-space pointer-auth
    /// instructions.
    @inline(__always)
    private static func pacImplicitRegisters(
        for mnemonic: Mnemonic,
    ) -> (reads: RegisterSet, writes: RegisterSet) {
        switch mnemonic {
        case .paciasp, .pacibsp, .autiasp, .autibsp:
            (RegisterSet.empty.inserting(.x(30)).inserting(.sp()),
             RegisterSet.empty.inserting(.x(30)))
        case .paciaz, .pacibz, .autiaz, .autibz:
            (RegisterSet.empty.inserting(.x(30)),
             RegisterSet.empty.inserting(.x(30)))
        case .pacia1716, .pacib1716, .autia1716, .autib1716:
            (RegisterSet.empty.inserting(.x(17)).inserting(.x(16)),
             RegisterSet.empty.inserting(.x(17)))
        case .xpaclri:
            (RegisterSet.empty.inserting(.x(30)),
             RegisterSet.empty.inserting(.x(30)))
        default:
            (.empty, .empty)
        }
    }
}
