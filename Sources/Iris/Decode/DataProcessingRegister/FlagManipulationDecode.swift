// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_FlagM flag-manipulation decode: RMIF (rotate right
// into flags) and SETF8 / SETF16 (evaluate into flags). All three live in
// the op0=0xD, bit24=0, bits[23:21]=000 tier alongside add/subtract-with-
// carry, distinguished by the sub-fields that ADC/SBC leave zero. The
// DPR family decoder runs this before the add/subtract-with-carry decoder.

enum FlagManipulationDecode {
    /// Decode an RMIF / SETF8 / SETF16 encoding; returns `nil` when the
    /// word is not one of them (so the add/subtract-with-carry decoder
    /// handles the rest of the `bits[23:21]=000` tier).
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft? {
        let op = (encoding >> 30) & 1
        let s = (encoding >> 29) & 1
        guard op == 0, s == 1 else { return nil }
        let sf = (encoding >> 31) & 1

        // RMIF: sf=1, bits[14:10]=00001, bit4=0. imm6=bits[20:15] (rotation),
        // mask=bits[3:0], Rn=bits[9:5] (Xn). Reads Rn, sets NZCV, no GP write.
        if sf == 1, (encoding >> 10) & 0x1F == 0b00001, (encoding >> 4) & 1 == 0 {
            let imm6 = UInt64((encoding >> 15) & 0x3F)
            let mask = UInt64(encoding & 0xF)
            // RMIF writes exactly the flags `mask` selects (bit3→N, bit2→Z,
            // bit1→C, bit0→V); the unselected flags are preserved. It reads
            // no condition flags (the source is Xn rotated by imm6).
            var rmifFlags: FlagEffect = []
            if mask & 0x8 != 0 { rmifFlags.insert(.writesN) }
            if mask & 0x4 != 0 { rmifFlags.insert(.writesZ) }
            if mask & 0x2 != 0 { rmifFlags.insert(.writesC) }
            if mask & 0x1 != 0 { rmifFlags.insert(.writesV) }
            let rn = gprOperand(encoding: UInt8((encoding >> 5) & 0x1F), width: .x64, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .rmif,
                semanticReads: insertingNonZero(reg: rn, into: .empty),
                semanticWrites: .empty,
                flagEffect: rmifFlags,
                category: .dataProcessingRegister,
                operands: [
                    .register(rn),
                    .unsignedImmediate(value: imm6, width: 6),
                    .unsignedImmediate(value: mask, width: 4),
                ],
            )
        }

        // SETF8 / SETF16: sf=0, bits[20:16]=00000, bit15=0, bits[13:10]=0010,
        // bit4=0, bits[3:0]=1101. sz=bit14 (0 → SETF8, 1 → SETF16). Rn=bits[9:5]
        // (Wn). Reads Rn, sets NZV, no GP write.
        if sf == 0,
           (encoding >> 16) & 0x1F == 0,
           (encoding >> 15) & 1 == 0,
           (encoding >> 10) & 0xF == 0b0010,
           (encoding >> 4) & 1 == 0,
           encoding & 0xF == 0b1101
        {
            let rn = gprOperand(encoding: UInt8((encoding >> 5) & 0x1F), width: .w32, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: (encoding >> 14) & 1 == 0 ? .setf8 : .setf16,
                semanticReads: insertingNonZero(reg: rn, into: .empty),
                semanticWrites: .empty,
                // SETF8 / SETF16 set N, Z, V from the operand; C is preserved.
                flagEffect: [.writesN, .writesZ, .writesV],
                category: .dataProcessingRegister,
                operands: [.register(rn)],
            )
        }

        return nil
    }
}
