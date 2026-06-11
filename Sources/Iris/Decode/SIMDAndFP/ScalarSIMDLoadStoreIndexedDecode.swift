// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Scalar SIMD LDR/STR/LDUR/STUR (register-offset, unscaled, pre-
// indexed, post-indexed; V=1). Encoding shell:
// `size 11 1 1 0 0 V 00 opc 0 ... Rn Rt` with V=1. Sub-discriminate by
// bits[11:10]: 00=unscaled, 01=post-index, 10=register-offset, 11=pre-
// index. (size, opc) selects the destination element width (B/H/S/D/Q).

enum ScalarSIMDLoadStoreIndexedDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let bits11_10 = UInt8((encoding >> 10) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        guard let (elementSize, isLoad) = mapSizeOpc(size: size, opc: opc) else {
            return .undefined(at: address, encoding: encoding)
        }
        // bit21 = 1 only for the register-offset form (bits[11:10]=10); the
        // immediate forms (unscaled/post/pre) require bit21 = 0.
        if (bits11_10 == 0b10) != (((encoding >> 21) & 1) == 1) {
            return .undefined(at: address, encoding: encoding)
        }
        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let vt = simdfpScalarOperand(Rt, size: elementSize)

        let mnemonic: Mnemonic
        let memOperand: MemoryOperand
        var rmRead: RegisterRef?
        var basePostUpdate = false
        switch bits11_10 {
        case 0b00:
            // Unscaled offset: LDUR/STUR with 9-bit signed imm9.
            let imm9 = UInt32((encoding >> 12) & 0x1FF)
            let disp = lsSignExtendImm9Local(imm9)
            mnemonic = isLoad ? .ldur : .stur
            memOperand = MemoryOperand(
                base: .register(rnRef), index: nil,
                displacement: disp, extend: .none, shift: 0,
                writeback: .none,
            )
        case 0b01:
            // Post-indexed: LDR/STR with 9-bit signed imm9 and writeback.
            let imm9 = UInt32((encoding >> 12) & 0x1FF)
            let disp = lsSignExtendImm9Local(imm9)
            mnemonic = isLoad ? .ldr : .str
            memOperand = MemoryOperand(
                base: .register(rnRef), index: nil,
                displacement: disp, extend: .none, shift: 0,
                writeback: .postIndex,
            )
            basePostUpdate = true
        case 0b10:
            // Register offset: LDR/STR with Rm + extend + S-shift.
            // ARM ARM constrains option ∈ {010, 011, 110, 111}; the
            // remaining values are reserved.
            let Rm = UInt8((encoding >> 16) & 0x1F)
            let option = UInt8((encoding >> 13) & 0x7)
            let S = UInt8((encoding >> 12) & 0x1)
            if option != 0b010, option != 0b011, option != 0b110, option != 0b111 {
                return .undefined(at: address, encoding: encoding)
            }
            let optionExtend = extendFromOption(option)
            // option 011 (UXTX/LSL) and 111 (SXTX) index with a 64-bit Xm;
            // 010 (UXTW) / 110 (SXTW) with a 32-bit Wm. extendFromOption maps
            // 011 to .lsl, so key the index width off `option` directly.
            let rmWidth: RegisterWidth = (option == 0b011 || option == 0b111) ? .x64 : .w32
            let rmRef = simdfpGprOperand(encoding: Rm, width: rmWidth, spOrGeneral: false)
            rmRead = rmRef
            // S=1 always shows #amount (= log2(access size); 0 for byte);
            // S=0 + LSL/UXTX (option 011) collapses to bare `[Rn, Xm]`;
            // S=0 + other shows the extend keyword with no #amount (the 0xFF
            // sentinel) — mirroring LoadStoreRegisterOffsetDecode.
            let extendKind: ExtendKind
            let displayShift: UInt8
            if S == 1 {
                extendKind = optionExtend
                displayShift = logBytes(elementSize)
            } else if option == 0b011 {
                extendKind = .none
                displayShift = 0
            } else {
                extendKind = optionExtend
                displayShift = 0xFF
            }
            mnemonic = isLoad ? .ldr : .str
            memOperand = MemoryOperand(
                base: .register(rnRef), index: rmRef,
                displacement: 0, extend: extendKind, shift: displayShift,
                writeback: .none,
            )
        default:
            // bits11_10 == 0b11 (only remaining 2-bit value after mask).
            // Pre-indexed: LDR/STR with 9-bit signed imm9 and writeback.
            let imm9 = UInt32((encoding >> 12) & 0x1FF)
            let disp = lsSignExtendImm9Local(imm9)
            mnemonic = isLoad ? .ldr : .str
            memOperand = MemoryOperand(
                base: .register(rnRef), index: nil,
                displacement: disp, extend: .none, shift: 0,
                writeback: .preIndex,
            )
            basePostUpdate = true
        }

        var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
        if let rm = rmRead {
            reads = simdfpInsertingNonZeroGPR(reg: rm, into: reads)
        }
        var writes: RegisterSet = .empty
        if isLoad {
            writes = simdfpInsertingVector(Rt, into: writes)
        } else {
            reads = simdfpInsertingVector(Rt, into: reads)
        }
        if basePostUpdate {
            writes = simdfpInsertingNonZeroGPR(reg: rnRef, into: writes)
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none,
            memoryAccess: isLoad ? .load : .store,
            memoryOrdering: [], flagEffect: .none, category: .simdAndFP,
            operands: [vt, .memory(memOperand)],
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func mapSizeOpc(size: UInt8, opc: UInt8) -> (ScalarSize, Bool)? {
        switch (size, opc) {
        case (0b00, 0b00): (.b, false)
        case (0b00, 0b01): (.b, true)
        case (0b00, 0b10): (.q, false)
        case (0b00, 0b11): (.q, true)
        case (0b01, 0b00): (.h, false)
        case (0b01, 0b01): (.h, true)
        case (0b10, 0b00): (.s, false)
        case (0b10, 0b01): (.s, true)
        case (0b11, 0b00): (.d, false)
        case (0b11, 0b01): (.d, true)
        default: nil
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func extendFromOption(_ option: UInt8) -> ExtendKind {
        // Call site filters option ∈ {010, 011, 110, 111}; the default
        // catches 111 (sxtx) plus any unreachable value as sentinel.
        switch option {
        case 0b010: .uxtw
        case 0b011: .lsl // LSL alias of UXTX when option=011
        case 0b110: .sxtw
        default: .sxtx // option == 0b111 — only remaining filtered value.
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func logBytes(_ s: ScalarSize) -> UInt8 {
        switch s {
        case .b: 0
        case .h: 1
        case .s: 2
        case .d: 3
        case .q: 4
        }
    }
}

/// Local imm9 sign-extender (not shared with L/S helpers since they're
/// file-internal to the L/S family).
@inline(__always)
@_effects(readonly)
func lsSignExtendImm9Local(_ imm9: UInt32) -> Int64 {
    let mask: UInt32 = 0x1FF
    let value = imm9 & mask
    let signBit = (value >> 8) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}
