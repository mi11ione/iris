// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AdvSIMD load/store single-structure (and LDxR replicate)
// per ARM ARM § C4.1.96.44 + .45 (merged on writeback
// discriminator). Encoding:
// No-offset: `0 Q 0011 010 L R 00000 opcode S size Rn Rt`.
// Post-index: `0 Q 0011 011 L R Rm opcode S size Rn Rt`.
// Bits[15:13] opcode + L:R selects byte / halfword / word / doubleword
// single-element form OR the LDxR replicate forms (opcode=110/111).

enum AdvSIMDLoadStoreSingleStructureDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let Q = UInt8((encoding >> 30) & 0x1)
        let postIndexed = ((encoding >> 23) & 1) == 1
        let L = UInt8((encoding >> 22) & 0x1)
        let R = UInt8((encoding >> 21) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode = UInt8((encoding >> 13) & 0x7)
        let S = UInt8((encoding >> 12) & 0x1)
        let size = UInt8((encoding >> 10) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // bit31 is fixed 0 for AdvSIMD load/store structure forms; a 1 is
        // reserved → UNDEFINED.
        if (encoding >> 31) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        // FEAT_RCPC3 ordered SIMD single-element: ldap1/stl1 { Vt.d }[index],
        // [Xn|SP]. These occupy the no-offset single-structure space with the
        // RCpc marker bits[20:16] = 00001 (which the generic path below rejects
        // as a reserved Rm), R = 0, opcode = 0b100, S = 0, size = 0b01 (.d).
        // index = Q (bit30); bit22 = L (1 = ldap1 load-acquire, 0 = stl1
        // store-release).
        if (encoding >> 23) & 1 == 0,
           (encoding >> 16) & 0x1F == 0b00001,
           (encoding >> 21) & 1 == 0,
           (encoding >> 13) & 0x7 == 0b100,
           (encoding >> 12) & 1 == 0,
           (encoding >> 10) & 0x3 == 0b01
        {
            let isLoad = (encoding >> 22) & 1 == 1
            let elementIndex = UInt8((encoding >> 30) & 1)
            let rtNum = UInt8(encoding & 0x1F)
            let rnNum = UInt8((encoding >> 5) & 0x1F)
            let rnRef = simdfpGprOperand(encoding: rnNum, width: .x64, spOrGeneral: true)
            let element = simdfpElementOperand(rtNum, elementSize: .d, index: elementIndex)
            let mem = MemoryOperand(
                base: .register(rnRef), index: nil, displacement: 0,
                extend: .none, shift: 0, writeback: .none,
            )
            var reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: .empty)
            var writes: RegisterSet = .empty
            if isLoad {
                // Single-element load preserves the other lanes, so Vt is both
                // read and written.
                reads = simdfpInsertingVector(rtNum, into: reads)
                writes = simdfpInsertingVector(rtNum, into: writes)
            } else {
                reads = simdfpInsertingVector(rtNum, into: reads)
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: isLoad ? .ldap1 : .stl1,
                semanticReads: reads, semanticWrites: writes,
                branchClass: .none,
                memoryAccess: isLoad ? .load : .store,
                memoryOrdering: isLoad ? [.acquire] : [.release],
                flagEffect: .none, category: .simdAndFP,
                operands: [element, .memory(mem)],
            )
        }

        // No-offset form: bits[20:16] (Rm) are reserved and must be 0; a
        // nonzero value is UNDEFINED (only the post-index form uses Rm).
        if !postIndexed, Rm != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        // Determine (selem, mnemonic) per (opcode high bits + L + R).
        guard let info = singleStructLayout(opcode: opcode, L: L, R: R) else {
            return .undefined(at: address, encoding: encoding)
        }
        let isReplicate = info.isReplicate
        // Replicate forms (LDxR) reserve S (bit12); a nonzero value is UNDEFINED.
        if isReplicate, S != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        // For replicate forms (LDxR): element size comes from `size`
        // field via the standard (size, Q) arrangement table; there's no
        // element index (the load broadcasts a single element).
        let elementSize: ScalarSize
        let index: UInt8
        if isReplicate {
            elementSize = scalarElementFromSize(size)
            index = 0
        } else {
            // Non-replicate single-element forms: element size is per
            // opcode[2:1] (byte/half/word-d) and index is packed from
            // (Q, S, size) per the ARM ARM table. `(opcode >> 1) & 0x3`
            // covers values 00/01/10/11; 11 cannot reach here because
            // opcode 0b11_X routes through the replicate path above (where
            // `info.isReplicate` is true). The default arm handles the
            // remaining cases by sentinel — unreachable in practice.
            switch (opcode >> 1) & 0x3 {
            case 0b00:
                // Byte: index = Q:S:size (4 bits).
                elementSize = .b
                index = (Q << 3) | (S << 2) | size
            case 0b01:
                // Halfword: index = Q:S:size[1] (3 bits); size[0] must be 0.
                if (size & 1) != 0 {
                    return .undefined(at: address, encoding: encoding)
                }
                elementSize = .h
                index = (Q << 2) | (S << 1) | (size >> 1)
            default:
                // (opcode >> 1) & 0x3 == 0b10 — Word or doubleword. size[1]
                // must be 0: size=10/11 are reserved for the .s/.d forms
                // (.S requires size=00, .D requires size=01).
                if (size & 0b10) != 0 {
                    return .undefined(at: address, encoding: encoding)
                }
                if (size & 1) == 0 {
                    elementSize = .s
                    index = (Q << 1) | S
                } else {
                    if S != 0 {
                        return .undefined(at: address, encoding: encoding)
                    }
                    elementSize = .d
                    index = Q
                }
            }
        }

        // Build vector list (selem consecutive registers).
        var operands: [Operand] = []
        operands.reserveCapacity(Int(info.selem) + 1)
        var listReads: RegisterSet = .empty
        var listWrites: RegisterSet = .empty
        for i in 0 ..< Int(info.selem) {
            let r = (Rt &+ UInt8(i)) & 0x1F
            if isReplicate {
                // LDxR replicates to all lanes; destination arrangement is
                // (size, Q) per the standard table.
                let arrangement = arrangementFromSizeQ(size: size, Q: Q)
                operands.append(simdfpVectorOperand(r, arrangement: arrangement))
            } else {
                operands.append(simdfpElementOperand(r, elementSize: elementSize, index: index))
            }
            if L == 1 {
                listWrites = simdfpInsertingVector(r, into: listWrites)
                // Single-element load preserves other lanes; destination is
                // read AND written.
                if !isReplicate {
                    listReads = simdfpInsertingVector(r, into: listReads)
                }
            } else {
                listReads = simdfpInsertingVector(r, into: listReads)
            }
        }

        // Memory operand.
        let rnRef = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        let elementBytes = UInt64(elementSize.byteWidth)
        let increment = isReplicate
            ? elementBytes * UInt64(info.selem)
            : elementBytes * UInt64(info.selem)
        var memOperand: MemoryOperand
        if postIndexed {
            if Rm == 0b11111 {
                memOperand = MemoryOperand(
                    base: .register(rnRef), index: nil,
                    displacement: Int64(increment),
                    extend: .none, shift: 0, writeback: .postIndex,
                )
            } else {
                let rmRef = simdfpGprOperand(encoding: Rm, width: .x64, spOrGeneral: false)
                memOperand = MemoryOperand(
                    base: .register(rnRef), index: rmRef,
                    displacement: 0,
                    extend: .none, shift: 0, writeback: .postIndex,
                )
            }
        } else {
            memOperand = MemoryOperand(
                base: .register(rnRef), index: nil, displacement: 0,
                extend: .none, shift: 0, writeback: .none,
            )
        }
        operands.append(.memory(memOperand))

        var reads = listReads
        reads = simdfpInsertingNonZeroGPR(reg: rnRef, into: reads)
        var writes = listWrites
        if postIndexed {
            writes = simdfpInsertingNonZeroGPR(reg: rnRef, into: writes)
        }
        if postIndexed, Rm != 0b11111 {
            let rmRef = simdfpGprOperand(encoding: Rm, width: .x64, spOrGeneral: false)
            reads = simdfpInsertingNonZeroGPR(reg: rmRef, into: reads)
        }

        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: info.mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: L == 1 ? .load : .store,
            memoryOrdering: [],
            flagEffect: .none, category: .simdAndFP,
            operands: operands,
        )
    }

    private struct SingleStructInfo {
        let mnemonic: Mnemonic
        let selem: UInt8
        let isReplicate: Bool
    }

    @inline(__always)
    @_effects(readonly)
    private static func singleStructLayout(
        opcode: UInt8, L: UInt8, R: UInt8,
    ) -> SingleStructInfo? {
        // opcode[2:0] is a 3-bit field — cases 0b000..0b111 exhaust the
        // domain. The final case (0b111) is folded into the `default` arm.
        let isLoad = L == 1
        switch opcode {
        case 0b000:
            // ST1/LD1 if R=0; ST2/LD2 if R=1. selem accordingly.
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b001:
            // ST3/LD3 if R=0; ST4/LD4 if R=1.
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b010, 0b100:
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b011, 0b101:
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(
                mnemonic: isLoad ? loadMnemonic(selem: selem) : storeMnemonic(selem: selem),
                selem: selem, isReplicate: false,
            )
        case 0b110:
            if !isLoad { return nil }
            let selem: UInt8 = R == 0 ? 1 : 2
            return .init(mnemonic: replicateMnemonic(selem: selem), selem: selem, isReplicate: true)
        default:
            // opcode == 0b111 — LDxR (selem=3 or 4).
            if !isLoad { return nil }
            let selem: UInt8 = R == 0 ? 3 : 4
            return .init(mnemonic: replicateMnemonic(selem: selem), selem: selem, isReplicate: true)
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func loadMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .ld1
        case 2: .ld2
        case 3: .ld3
        default: .ld4 // selem ∈ {1, 2, 3, 4} by construction; final case = 4.
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func storeMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .st1
        case 2: .st2
        case 3: .st3
        default: .st4
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func replicateMnemonic(selem: UInt8) -> Mnemonic {
        switch selem {
        case 1: .ld1r
        case 2: .ld2r
        case 3: .ld3r
        default: .ld4r
        }
    }
}
