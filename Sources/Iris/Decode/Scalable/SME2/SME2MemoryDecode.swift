// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME2 multi-vector contiguous loads/stores (cells 101|x|0)
// and the ZT0 fill/spill patterns (cell 111|1|0). The whole 128-iclass
// memory family shares one parameterized layout:
// `0xA0000000 | K<<24 | Q<<22 | O<<21 | F<<15 | msz<<13 | N` with K=strided,
// Q=immediate-offset, O=store, F=4-way, msz=element, N=non-temporal (bit0
// consecutive / bit3 strided). Register geometry: consecutive pairs start
// even ({2t, 2t+1}), quads at multiples of 4; strided members step by
// 16/count from `16·T + t`. `Rm=31` is a real `xzr` index (unlike SME-core's
// tile loads, where 31 means "no index").

/// SME2 multi-vector load/store decoders.
extension SME2Decode {
    /// Decode a cell-`101|x|0` multi-vector load/store word.
    @_optimize(speed)
    static func decodeMultiVector(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let strided = e & 0x0100_0000 != 0
        let immediateForm = e & 0x0040_0000 != 0
        let isStore = e & 0x0020_0000 != 0
        let fourWay = e & 0x8000 != 0
        // Structural zero bits — set means a claimed hole, not an instruction.
        if immediateForm, e & 0x0010_0000 != 0 { return undefined(e, a) }
        if strided {
            if fourWay, e & 0x4 != 0 { return undefined(e, a) }
        } else {
            if fourWay, e & 0x2 != 0 { return undefined(e, a) }
        }

        let msz = UInt8((e >> 13) & 0x3)
        let element: ScalarSize = switch msz {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
        let nonTemporal = (strided ? e & 0x8 : e & 0x1) != 0
        let count: UInt8 = fourWay ? 4 : 2
        let first: UInt8 = if strided {
            (UInt8((e >> 4) & 1) &* 16) &+ UInt8(e & (fourWay ? 0x3 : 0x7))
        } else {
            fourWay ? UInt8(e & 0x1C) : UInt8(e & 0x1E)
        }

        let mnemonic = memoryMnemonic(element, isStore: isStore, nonTemporal: nonTemporal)
        let pn = UInt8((e >> 10) & 0x7)
        let rnIndex = UInt8((e >> 5) & 0x1F)
        let memory = if immediateForm {
            ScalableMemoryOperand(
                base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)),
                displacement: signExtend4(UInt8((e >> 16) & 0xF)) &* Int32(count),
                mulVL: true,
            )
        } else {
            ScalableMemoryOperand(
                base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)),
                scalarIndex: rm31IsXZR(e),
                scaleShift: msz,
            )
        }

        let registers = groupMask(first, count, strided: strided)
        let rmRead: RegisterSet = immediateForm ? .empty : dataMask(UInt8((e >> 16) & 0x1F))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: baseMask(rnIndex).union(rmRead).union(isStore ? registers : .empty),
            semanticWrites: isStore ? .empty : registers,
            memoryAccess: isStore ? .store : .load,
            category: .sme,
            operandCount: sink.emit(group(first, count, element, strided: strided), governPN(pn, isStore ? .none : .zeroing), .scalableMemory(memory)),
            scalableReads: predMask(8 &+ pn),
            scalableEffect: nonTemporal
                ? [.readsStreamingMode, .nonTemporal] : [.readsStreamingMode],
        )
    }

    /// Decode a cell-`111|1|0` word — only the two `ZT0` fill/spill patterns
    /// are in SME2's claim (`LDR ZT0` / `STR ZT0`); the cell's remainder is
    /// SME-core's.
    @_optimize(speed)
    static func decodeZT0FillSpill(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // The routing gate (`smeIsZT0FillSpill`) admits exactly these two
        // patterns, so the fill test decides between them — there is no third
        // case to reject here.
        let isLoad = e & 0xFFFF_FC1F == 0xE11F_8000
        let rnIndex = UInt8((e >> 5) & 0x1F)
        let memory = ScalableMemoryOperand(base: .gpr(rnIndex == 31 ? .sp() : .x(rnIndex)))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: isLoad ? .ldr : .str,
            semanticReads: baseMask(rnIndex),
            memoryAccess: isLoad ? .load : .store,
            category: .sme,
            operandCount: sink.emit(.zt0(elementIndex: nil), .scalableMemory(memory)),
            scalableReads: isLoad ? .empty : zt0Mask(),
            scalableWrites: isLoad ? zt0Mask() : .empty,
        )
    }

    /// The load/store mnemonic for an element size and form.
    @inline(__always)
    private static func memoryMnemonic(
        _ element: ScalarSize, isStore: Bool, nonTemporal: Bool,
    ) -> Mnemonic {
        switch element {
        case .b: isStore ? (nonTemporal ? .stnt1b : .st1b) : (nonTemporal ? .ldnt1b : .ld1b)
        case .h: isStore ? (nonTemporal ? .stnt1h : .st1h) : (nonTemporal ? .ldnt1h : .ld1h)
        case .s: isStore ? (nonTemporal ? .stnt1w : .st1w) : (nonTemporal ? .ldnt1w : .ld1w)
        default: isStore ? (nonTemporal ? .stnt1d : .st1d) : (nonTemporal ? .ldnt1d : .ld1d)
        }
    }

    /// The scalar-offset index register — `Xm`, with `31` a real `XZR`.
    @inline(__always)
    private static func rm31IsXZR(_ e: UInt32) -> RegisterRef {
        let rm = UInt8((e >> 16) & 0x1F)
        return rm == 31 ? .xzr() : .x(rm)
    }

    /// Sign-extend a 4-bit immediate.
    @inline(__always)
    private static func signExtend4(_ imm4: UInt8) -> Int32 {
        imm4 & 0x8 != 0 ? Int32(imm4) - 16 : Int32(imm4)
    }
}
