// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD scalar copy per ARM ARM § C4.1.96.9.
// Encoding: `0 1 op 0 1110 000 imm5 0 imm4 1 Rn Rd`. Only the DUP
// element form is valid here (op=0, imm4=0000); decoder emits DUP with
// scalar destination view derived from the element size encoded in imm5
// per the same first-set-bit convention as vector copy.

enum AdvSIMDScalarCopyDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let op = UInt8((encoding >> 29) & 0x1)
        let imm5 = UInt8((encoding >> 16) & 0x1F)
        let imm4 = UInt8((encoding >> 11) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if op != 0 || imm4 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        guard let (elementSize, index) = decodeElementSizeAndIndex(imm5: imm5) else {
            return .undefined(at: address, encoding: encoding)
        }
        let dst = simdfpScalarOperand(Rd, size: elementSize)
        let src = simdfpElementOperand(Rn, elementSize: elementSize, index: index)
        // DUP-element scalar is aliased to MOV in ARM ARM canonical form.
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: .mov,
            semanticReads: simdfpInsertingVector(Rn, into: .empty),
            semanticWrites: simdfpInsertingVector(Rd, into: .empty),
            branchClass: .none, memoryAccess: .none, memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: [dst, src],
        )
    }

    @inline(__always)
    @_effects(readonly)
    private static func decodeElementSizeAndIndex(imm5: UInt8) -> (ScalarSize, UInt8)? {
        if imm5 == 0 { return nil }
        if (imm5 & 0x01) != 0 { return (.b, (imm5 >> 1) & 0xF) }
        if (imm5 & 0x02) != 0 { return (.h, (imm5 >> 2) & 0x7) }
        if (imm5 & 0x04) != 0 { return (.s, (imm5 >> 3) & 0x3) }
        if (imm5 & 0x08) != 0 { return (.d, (imm5 >> 4) & 0x1) }
        return nil
    }
}
