// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPermuteMemoryDecode {
    /// Build a load record.
    @inline(__always)
    static func memLoadDraft(
        _ e: UInt32, _ a: UInt64, mn: Mnemonic, zt: UInt8, el: ScalarSize,
        g: UInt8, addr: ScalableMemoryOperand, groupCount count: UInt8 = 1, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: addressReads(addr),
            semanticWrites: groupMask(zt, count: count),
            memoryAccess: .load, category: .sve,
            operandCount: sink.emit(group(zt, count: count, el), govern(g, .zeroing), .scalableMemory(addr)),
            scalableReads: predRead(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// Build a store record.
    @inline(__always)
    static func memStoreDraft(
        _ e: UInt32, _ a: UInt64, mn: Mnemonic, zt: UInt8, el: ScalarSize,
        g: UInt8, addr: ScalableMemoryOperand, groupCount count: UInt8 = 1, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: addressReads(addr).union(groupMask(zt, count: count)),
            semanticWrites: .empty,
            memoryAccess: .store, category: .sve,
            operandCount: sink.emit(group(zt, count: count, el), govern(g, .none), .scalableMemory(addr)),
            scalableReads: predRead(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// A prefetch record.
    @inline(__always)
    static func memPrefetchDraft(
        _ e: UInt32, _ a: UInt64, mn: Mnemonic, g: UInt8, addr: ScalableMemoryOperand, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if (e >> 4) & 1 != 0 { return undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: addressReads(addr),
            semanticWrites: .empty,
            memoryAccess: .prefetch, category: .sve,
            operandCount: sink.emit(prfop(e), govern(g, .none), .scalableMemory(addr)),
            scalableReads: predRead(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// The register reads implied by an address.
    @inline(__always)
    static func addressReads(_ addr: ScalableMemoryOperand) -> RegisterSet {
        var set = RegisterSet.empty
        switch addr.base {
        case let .gpr(r): set = set.inserting(r)
        case let .vector(v): set = set.inserting(v)
        }
        if let si = addr.scalarIndex { set = set.inserting(si) }
        if let vi = addr.index { set = set.inserting(vi) }
        return set
    }

    /// Mark a load as first-faulting.
    @inline(__always)
    static func markFirstFault(_ d: DecodedDraft) -> DecodedDraft {
        var draft = d
        draft.scalableReads = draft.scalableReads.insertingFFR()
        draft.scalableWrites = draft.scalableWrites.insertingFFR()
        draft.scalableEffect.insert(.firstFaulting)
        return draft
    }

    /// Mark a load as non-faulting.
    @inline(__always)
    static func markNonFault(_ d: DecodedDraft) -> DecodedDraft {
        var draft = d
        draft.scalableReads = draft.scalableReads.insertingFFR()
        draft.scalableWrites = draft.scalableWrites.insertingFFR()
        draft.scalableEffect.insert(.nonFaulting)
        return draft
    }

    /// Mark a load/store as non-temporal.
    @inline(__always)
    static func markNonTemporal(_ d: DecodedDraft) -> DecodedDraft {
        var draft = d
        draft.scalableEffect.insert(.nonTemporal)
        return draft
    }

    /// The contiguous-load dtype table (speca).
    @inline(__always)
    static func loadDtype(_ dtype: UInt8, nonFault: Bool) -> (Mnemonic, ScalarSize) {
        let (base, el) = loadDtypeBase(dtype)
        return (nonFault ? nonFaultName(base) : base, el)
    }

    /// The access (loaded-element) log2 size for a contiguous-load dtype.
    @inline(__always)
    static func loadAccessScale(_ dtype: UInt8) -> UInt8 {
        switch dtype {
        case 0b0000, 0b0001, 0b0010, 0b0011, 0b1100, 0b1101, 0b1110: 0
        case 0b0101, 0b0110, 0b0111, 0b1000, 0b1001: 1
        case 0b1010, 0b1011, 0b0100: 2
        default: 3
        }
    }

    /// The plain LD1 dtype table.
    @inline(__always)
    static func loadDtypeBase(_ dtype: UInt8) -> (Mnemonic, ScalarSize) {
        switch dtype {
        case 0b0000: (.ld1b, .b)
        case 0b0001: (.ld1b, .h)
        case 0b0010: (.ld1b, .s)
        case 0b0011: (.ld1b, .d)
        case 0b0100: (.ld1sw, .d)
        case 0b0101: (.ld1h, .h)
        case 0b0110: (.ld1h, .s)
        case 0b0111: (.ld1h, .d)
        case 0b1000: (.ld1sh, .d)
        case 0b1001: (.ld1sh, .s)
        case 0b1010: (.ld1w, .s)
        case 0b1011: (.ld1w, .d)
        case 0b1100: (.ld1sb, .d)
        case 0b1101: (.ld1sb, .s)
        case 0b1110: (.ld1sb, .h)
        default: (.ld1d, .d)
        }
    }

    /// The contiguous-store dtype table (`sve_mem_cst_ss_base`).
    @inline(__always)
    static func storeDtype(_ dtype: UInt8) -> (Mnemonic, ScalarSize)? {
        switch dtype {
        case 0b0000: (.st1b, .b)
        case 0b0001: (.st1b, .h)
        case 0b0010: (.st1b, .s)
        case 0b0011: (.st1b, .d)
        case 0b0101: (.st1h, .h)
        case 0b0110: (.st1h, .s)
        case 0b0111: (.st1h, .d)
        case 0b1010: (.st1w, .s)
        case 0b1011: (.st1w, .d)
        case 0b1000: (.st1w, .q)
        case 0b1110: (.st1d, .q)
        case 0b1111: (.st1d, .d)
        default: nil
        }
    }

    /// The contiguous single-vector store `msz` → mnemonic (element from esz).
    @inline(__always)
    static func storeMsz(_ msz: UInt8) -> Mnemonic {
        switch msz {
        case 0b00: .st1b
        case 0b01: .st1h
        case 0b10: .st1w
        default: .st1d
        }
    }

    /// LD1 → LDNF1 mnemonic swap.
    @inline(__always)
    static func nonFaultName(_ m: Mnemonic) -> Mnemonic {
        switch m {
        case .ld1b: .ldnf1b
        case .ld1h: .ldnf1h
        case .ld1w: .ldnf1w
        case .ld1d: .ldnf1d
        case .ld1sb: .ldnf1sb
        case .ld1sh: .ldnf1sh
        default: .ldnf1sw
        }
    }

    /// LD1 → LDFF1 mnemonic swap.
    @inline(__always)
    static func firstFaultName(_ m: Mnemonic) -> Mnemonic {
        switch m {
        case .ld1b: .ldff1b
        case .ld1h: .ldff1h
        case .ld1w: .ldff1w
        case .ld1d: .ldff1d
        case .ld1sb: .ldff1sb
        case .ld1sh: .ldff1sh
        default: .ldff1sw
        }
    }

    /// Non-temporal load/store `msz` → mnemonic.
    @inline(__always)
    static func ntName(msz: UInt8, isStore: Bool) -> Mnemonic {
        switch (msz, isStore) {
        case (0b00, false): .ldnt1b
        case (0b01, false): .ldnt1h
        case (0b10, false): .ldnt1w
        case (0b11, false): .ldnt1d
        case (0b00, true): .stnt1b
        case (0b01, true): .stnt1h
        case (0b10, true): .stnt1w
        default: .stnt1d
        }
    }

    /// LD1RQ<sz> replicate-quadword mnemonic.
    @inline(__always)
    static func quadReplicateName(_ sz: UInt8) -> Mnemonic {
        switch sz {
        case 0b00: .ld1rqb
        case 0b01: .ld1rqh
        case 0b10: .ld1rqw
        default: .ld1rqd
        }
    }

    /// LD1RO<sz> replicate-octoword mnemonic (F64MM).
    @inline(__always)
    static func octoReplicateName(_ sz: UInt8) -> Mnemonic {
        switch sz {
        case 0b00: .ld1rob
        case 0b01: .ld1roh
        case 0b10: .ld1row
        default: .ld1rod
        }
    }

    /// Structured contiguous-load form (imm).
    @inline(__always)
    static func structuredForm(_ e: UInt32) -> (UInt8, ScalarSize, Mnemonic)? {
        let sz = UInt8((e >> 23) & 0b11)
        let count: UInt8
        switch (e >> 20) & 0b111 {
        case 0b010: count = 2
        case 0b100: count = 3
        case 0b110: count = 4
        case 0b001: return quadStructured(e, sz)
        default: return nil
        }
        return (count, esize(sz), structuredName(count: count, element: esize(sz), isStore: false))
    }

    /// The SVE2p1 quadword structured count from sz (01→2, 10→3, 11→4, `.q`).
    @inline(__always)
    static func quadStructured(_: UInt32, _ sz: UInt8) -> (UInt8, ScalarSize, Mnemonic)? {
        let qCount: UInt8
        switch sz {
        case 0b01: qCount = 2
        case 0b10: qCount = 3
        case 0b11: qCount = 4
        default: return nil
        }
        return (qCount, .q, structuredName(count: qCount, element: .q, isStore: false))
    }

    /// Structured mnemonic from vector count, element, and load/store.
    @inline(__always)
    static func structuredName(count: UInt8, element: ScalarSize, isStore: Bool) -> Mnemonic {
        switch (count, isStore) {
        case (2, false): loadN2(element)
        case (3, false): loadN3(element)
        case (4, false): loadN4(element)
        case (2, true): storeN2(element)
        case (3, true): storeN3(element)
        default: storeN4(element)
        }
    }

    @inline(__always)
    static func loadN2(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .ld2b; case .h: .ld2h; case .s: .ld2w; case .d: .ld2d; case .q: .ld2q }
    }

    @inline(__always)
    static func loadN3(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .ld3b; case .h: .ld3h; case .s: .ld3w; case .d: .ld3d; case .q: .ld3q }
    }

    @inline(__always)
    static func loadN4(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .ld4b; case .h: .ld4h; case .s: .ld4w; case .d: .ld4d; case .q: .ld4q }
    }

    @inline(__always)
    static func storeN2(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .st2b; case .h: .st2h; case .s: .st2w; case .d: .st2d; case .q: .st2q }
    }

    @inline(__always)
    static func storeN3(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .st3b; case .h: .st3h; case .s: .st3w; case .d: .st3d; case .q: .st3q }
    }

    @inline(__always)
    static func storeN4(_ el: ScalarSize) -> Mnemonic {
        switch el { case .b: .st4b; case .h: .st4h; case .s: .st4w; case .d: .st4d; case .q: .st4q }
    }

    /// The `lsl #k` scale for a scalar register offset.
    @inline(__always)
    static func elementScale(_ el: ScalarSize) -> UInt8 {
        el.rawValue
    }

    /// Sign-extend a 4-bit value to Int32.
    @inline(__always)
    static func signExtend4(_ v: UInt32) -> Int32 {
        Int32(Int8(truncatingIfNeeded: v << 4)) >> 4
    }

    /// Sign-extend a 6-bit value to Int32.
    @inline(__always)
    static func signExtend6(_ v: UInt32) -> Int32 {
        Int32(Int8(truncatingIfNeeded: v << 2)) >> 2
    }

    /// Sign-extend a 9-bit value to Int32.
    @inline(__always)
    static func signExtend9(_ v: UInt32) -> Int32 {
        Int32(Int16(truncatingIfNeeded: v << 7)) >> 7
    }
}
