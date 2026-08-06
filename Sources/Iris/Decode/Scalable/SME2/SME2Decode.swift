// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SME2 multi-vector decoder for SME2 (op0=0 SME region).
enum SME2Decode {
    /// Decode an in-scope SME-region SME2 word.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch e & 0xE000_0000 {
        case 0x8000_0000:
            SME2OuterProductDecode.decode(e, a, &sink)
        case 0xA000_0000:
            e & 0x0080_0000 != 0
                ? SME2OuterProductDecode.decode(e, a, &sink)
                : decodeMultiVector(e, a, &sink)
        case 0xC000_0000:
            e & 0x0100_0000 != 0
                ? SME2ArithmeticDecode.decode(e, a, &sink)
                : SME2MoveLookupDecode.decode(e, a, &sink)
        default:
            decodeZT0FillSpill(e, a, &sink)
        }
    }

    /// Restricted broadcast register.
    @inline(__always) static func zm4(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0xF)
    }

    /// Destination scalable register.
    @inline(__always) static func zd5(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    /// Vector-select field — bits[14:13] (2-bit `Rv`).
    @inline(__always) static func rv(_ e: UInt32) -> UInt8 {
        UInt8((e >> 13) & 0x3)
    }

    /// The ZA-array vector-select GPR `Wv` (`W8`-`W11`).
    @inline(__always) static func selectW8(_ e: UInt32) -> RegisterRef {
        .w(8 &+ rv(e))
    }

    /// The tile-slice vector-select GPR `Ws` (`W12`-`W15`).
    @inline(__always) static func selectW12(_ e: UInt32) -> RegisterRef {
        .w(12 &+ rv(e))
    }

    /// A plain scalable vector `Zn` / `Zn.<T>` / `Zn.<T>[i]`.
    @inline(__always)
    static func vec(_ index: UInt8, _ element: ScalarSize?, index elementIndex: UInt8? = nil) -> Operand {
        .scalableVector(ScalableVectorRef(
            registerIndex: index, element: element, elementIndex: elementIndex,
        ))
    }

    /// A multi-vector register group `{ Zn.<T>, ... }`.
    @inline(__always)
    static func group(
        _ first: UInt8, _ count: UInt8, _ element: ScalarSize?, strided: Bool = false,
    ) -> Operand {
        .scalableVectorGroup(ScalableVectorGroup(
            firstIndex: first, count: count, element: element,
            layout: strided ? .strided : .consecutive,
        ))
    }

    /// A `ZA`-array vector operand `za.<T>[Wv, off{:high}{, vgxN}]` (select
    /// register `W8+Rv`).
    @inline(__always)
    static func zaVector(
        _ e: UInt32, _ element: ScalarSize, offset: UInt8, offsetHigh: UInt8? = nil,
        group vectorGroup: ZAArrayVectorOperand.VectorGroup,
    ) -> Operand {
        .zaArrayVector(ZAArrayVectorOperand(
            element: element, selectRegister: selectW8(e), offset: offset,
            offsetHigh: offsetHigh, group: vectorGroup,
        ))
    }

    /// A governing predicate-as-counter `PNg` / `PNg/z` (`PN8`-`PN15`).
    @inline(__always)
    static func governPN(_ index3: UInt8, _ qualifier: PredicateQualifier) -> Operand {
        .scalablePredicate(ScalablePredicateRef(
            registerIndex: 8 &+ (index3 & 0x7), qualifier: qualifier,
            role: .governing, isCounter: true,
        ))
    }

    /// The Z/V register-set bit `32+n`.
    @inline(__always)
    static func vecMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: index))
    }

    /// The union of a group's member register bits.
    @inline(__always)
    static func groupMask(_ first: UInt8, _ count: UInt8, strided: Bool = false) -> RegisterSet {
        let g = ScalableVectorGroup(
            firstIndex: first, count: count, element: nil,
            layout: strided ? .strided : .consecutive,
        )
        var mask = RegisterSet.empty
        for j in 0 ..< count {
            mask = mask.inserting(ScalableVectorRef(registerIndex: g.memberIndex(j)))
        }
        return mask
    }

    /// The GPR register-set bit for a base register (`SP` at 31).
    @inline(__always)
    static func baseMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(index == 31 ? RegisterRef.sp() : RegisterRef.x(index))
    }

    /// The GPR register-set bit for a data register (`XZR` at 31 ⇒ empty).
    @inline(__always)
    static func dataMask(_ index: UInt8) -> RegisterSet {
        index == 31 ? .empty : RegisterSet.empty.inserting(RegisterRef.x(index))
    }

    /// The GPR register-set bit for a select register (`W8`-`W15`).
    @inline(__always)
    static func selectMask(_ ref: RegisterRef) -> RegisterSet {
        RegisterSet.empty.inserting(ref)
    }

    /// A single-predicate read/write set (`P0`-`P15`; `PN` aliases the same
    /// bits).
    @inline(__always)
    static func predMask(_ index: UInt8) -> ScalableRegisterSet {
        ScalableRegisterSet.empty.insertingPredicate(index & 0xF)
    }

    /// The whole-`ZA` overlap set (every SME2 ZA-array access is a dynamic row
    /// selection.
    @inline(__always)
    static func zaWholeMask() -> ScalableRegisterSet {
        ScalableRegisterSet.empty.inserting(ZATileMask.whole)
    }

    /// The `ZT0` register set.
    @inline(__always)
    static func zt0Mask() -> ScalableRegisterSet {
        ScalableRegisterSet.empty.insertingZT0()
    }

    /// A `ZA`-array accumulate record.
    @inline(__always)
    static func zaAccumulate(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic,
        operandCount: UInt8, sourceReads: RegisterSet,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: sourceReads.union(selectMask(selectW8(e))),
            category: .sme, operandCount: operandCount,
            scalableReads: zaWholeMask(), scalableWrites: zaWholeMask(),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// A well-formed in-scope UNDEFINED SME record (`category = .sme`, raw
    /// encoding preserved), matching llvm-mc's empty output for a claimed
    /// hole.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sme)
    }
}
