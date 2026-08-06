// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AtomicExtensionsDecode {
    /// Shell bits[29:24]=011001, bit[21]=1, bits[11:10]=01, size ∈ {00,01} (W
    /// / X operand width); op bits[15:12] ∈ {0000=add,0001=clr,0011=set,
    /// 1000=swp}.
    private static let lsuiRows: [[Mnemonic]] = [
        [.ldtadd, .ldtaddl, .ldtadda, .ldtaddal],
        [.ldtclr, .ldtclrl, .ldtclra, .ldtclral],
        [.ldtset, .ldtsetl, .ldtseta, .ldtsetal],
        [.swpt, .swptl, .swpta, .swptal],
    ]

    @_optimize(speed)
    static func decodeLSUI(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let op = UInt8((encoding >> 12) & 0xF)
        let opSlot: Int
        switch op {
        case 0b0000: opSlot = 0
        case 0b0001: opSlot = 1
        case 0b0011: opSlot = 2
        case 0b1000: opSlot = 3
        default: return .undefined(at: address, encoding: encoding)
        }
        let A = UInt8((encoding >> 23) & 1)
        let R = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let width: RegisterWidth = (size == 0b01) ? .x64 : .w32

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rsRef = lsGprOperand(encoding: Rs, width: width, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: width, form: .zrOrGeneral)

        if Rt == 31, A == 0, let alias = lsuiStAlias(opSlot: opSlot, R: R) {
            let reads = lsInsertingNonZero(reg: rnRef, into: lsInsertingNonZero(reg: rsRef, into: .empty))
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: alias,
                semanticReads: reads, semanticWrites: .empty, branchClass: .none,
                memoryAccess: .atomic, memoryOrdering: ordering, flagEffect: .none,
                category: .loadsAndStores,
                operandCount: sink.emit(.register(rsRef), .memory(MemoryOperand(base: .register(rnRef)))),
            )
        }

        let mnemonic = lsuiRows[opSlot][Int(A) * 2 + Int(R)]
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: .atomic, memoryOrdering: ordering, flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    /// ST-alias mnemonic for an LSUI (opSlot, R) at A=0, or nil for SWPT.
    @inline(__always)
    @_effects(readonly)
    private static func lsuiStAlias(opSlot: Int, R: UInt8) -> Mnemonic? {
        switch opSlot {
        case 0: R == 0 ? .sttadd : .sttaddl
        case 1: R == 0 ? .sttclr : .sttclrl
        case 2: R == 0 ? .sttset : .sttsetl
        default: nil
        }
    }

    /// Shell bits[29:24]=111000, bit[21]=1, bits[11:10]=00, size ∈ {00=rcw,
    /// 01=rcws}; op bits[15:12] ∈ {1001=clr,1010=swp,1011=set}.
    private static let rcwRows: [[Mnemonic]] = [
        [.rcwclr, .rcwclrl, .rcwclra, .rcwclral],
        [.rcwswp, .rcwswpl, .rcwswpa, .rcwswpal],
        [.rcwset, .rcwsetl, .rcwseta, .rcwsetal],
        [.rcwsclr, .rcwsclrl, .rcwsclra, .rcwsclral],
        [.rcwsswp, .rcwsswpl, .rcwsswpa, .rcwsswpal],
        [.rcwsset, .rcwssetl, .rcwsseta, .rcwssetal],
    ]

    @_optimize(speed)
    static func decodeRCWNonPair(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let op = UInt8((encoding >> 12) & 0xF)
        let opSlot = switch op {
        case 0b1001: 0
        case 0b1010: 1
        default: 2
        }
        let row = Int(size) * 3 + opSlot
        return decodeRCWThreeReg(
            encoding: encoding, address: address, mnemonic: rcwRows[row][orderSlot(encoding)], &sink,
        )
    }

    /// Shell bits[29:24]=011001, bit[21]=1, bits[11:10]=10, op
    /// bits[15:12]=0000, size ∈ {00=rcwcas, 01=rcwscas}.
    private static let rcwCasRows: [[Mnemonic]] = [
        [.rcwcas, .rcwcasl, .rcwcasa, .rcwcasal],
        [.rcwscas, .rcwscasl, .rcwscasa, .rcwscasal],
    ]

    @_optimize(speed)
    static func decodeRCWCas(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        if (encoding >> 12) & 0xF != 0b0000 {
            return .undefined(at: address, encoding: encoding)
        }
        return decodeRCWThreeReg(
            encoding: encoding, address: address,
            mnemonic: rcwCasRows[Int(size)][orderSlot(encoding)], &sink,
        )
    }

    /// Shared body for RCW non-pair / CAS.
    @_optimize(speed)
    private static func decodeRCWThreeReg(
        encoding: UInt32, address: UInt64, mnemonic: Mnemonic, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let rsRef = lsGprOperand(encoding: Rs, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: .atomic, memoryOrdering: orderingFor(encoding), flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    private static let rcwPairRows: [[Mnemonic]] = [
        [.rcwclrp, .rcwclrpl, .rcwclrpa, .rcwclrpal],
        [.rcwswpp, .rcwswppl, .rcwswppa, .rcwswppal],
        [.rcwsetp, .rcwsetpl, .rcwsetpa, .rcwsetpal],
        [.rcwsclrp, .rcwsclrpl, .rcwsclrpa, .rcwsclrpal],
        [.rcwsswpp, .rcwsswppl, .rcwsswppa, .rcwsswppal],
        [.rcwssetp, .rcwssetpl, .rcwssetpa, .rcwssetpal],
    ]

    /// Decode an RCW pair op (op ∈ {1001,1010,1011}); returns nil for ops
    /// outside the RCW-pair set so the caller can try LSE128.
    @_optimize(speed)
    static func decodeRCWPair(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft? {
        let size = UInt8((encoding >> 30) & 0x3)
        let op = UInt8((encoding >> 12) & 0xF)
        let opSlot: Int
        switch op {
        case 0b1001: opSlot = 0
        case 0b1010: opSlot = 1
        case 0b1011: opSlot = 2
        default: return nil
        }
        let row = Int(size) * 3 + opSlot
        let mnemonic = rcwPairRows[row][orderSlot(encoding)]
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        if Rt == 31 || Rs == 31 {
            return .undefined(at: address, encoding: encoding)
        }
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rsRef = lsGprOperand(encoding: Rs, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rtRef, into: .empty)
        reads = lsInsertingNonZero(reg: rsRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: .atomic, memoryOrdering: orderingFor(encoding), flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .register(rsRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    private static let rcwCaspRows: [[Mnemonic]] = [
        [.rcwcasp, .rcwcaspl, .rcwcaspa, .rcwcaspal],
        [.rcwscasp, .rcwscaspl, .rcwscaspa, .rcwscaspal],
    ]

    @_optimize(speed)
    static func decodeRCWCasp(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        if (encoding >> 12) & 0xF != 0b0000 {
            return .undefined(at: address, encoding: encoding)
        }
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        if (Rs & 1) != 0 || (Rt & 1) != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let mnemonic = rcwCaspRows[Int(size)][orderSlot(encoding)]
        let rs0 = lsGprOperand(encoding: Rs, width: .x64, form: .zrOrGeneral)
        let rs1 = lsGprOperand(encoding: (Rs &+ 1) & 0x1F, width: .x64, form: .zrOrGeneral)
        let rt0 = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rt1 = lsGprOperand(encoding: (Rt &+ 1) & 0x1F, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rs0, into: .empty)
        reads = lsInsertingNonZero(reg: rs1, into: reads)
        reads = lsInsertingNonZero(reg: rt0, into: reads)
        reads = lsInsertingNonZero(reg: rt1, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        var writes = lsInsertingNonZero(reg: rs0, into: .empty)
        writes = lsInsertingNonZero(reg: rs1, into: writes)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: .atomic, memoryOrdering: orderingFor(encoding), flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rs0), .register(rs1), .register(rt0), .register(rt1), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    /// FEAT_LSCP acquire/release register pairs, which share the RCPC3-pair
    /// shell: size=11, bits[15:10] ∈ {010110, 011110}, Rt2 in bits[20:16].
    @inline(__always)
    @_effects(readonly)
    private static func lscpPairMnemonic(_ encoding: UInt32) -> Mnemonic? {
        guard (encoding >> 30) == 0b11 else { return nil }
        switch ((encoding >> 22) & 0x3, (encoding >> 10) & 0x3F) {
        case (0b00, 0b010110): return .stlp
        case (0b01, 0b010110): return .ldap
        case (0b01, 0b011110): return .ldapp
        default: return nil
        }
    }

    @_optimize(speed)
    static func decodeRCPC3Pair(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if let mnemonic = lscpPairMnemonic(encoding) {
            return decodeLSCPPair(encoding: encoding, address: address, mnemonic: mnemonic, &sink)
        }
        let size = UInt8((encoding >> 30) & 0x3)
        if size < 0b10 {
            return .undefined(at: address, encoding: encoding)
        }
        if (encoding >> 13) & 0x7 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 22) & 0x3)
        let noWriteback = (encoding >> 12) & 1 == 1
        let Rt2 = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let width: RegisterWidth = (size == 0b11) ? .x64 : .w32
        let dataSize: Int64 = (size == 0b11) ? 8 : 4
        let isLoad: Bool
        let mnemonic: Mnemonic
        switch opc {
        case 0b00: mnemonic = .stilp; isLoad = false
        default: mnemonic = .ldiapp; isLoad = true
        }
        let displacement: Int64
        let writeback: Writeback
        if noWriteback {
            displacement = 0; writeback = .none
        } else if isLoad {
            displacement = 2 * dataSize; writeback = .postIndex
        } else {
            displacement = -2 * dataSize; writeback = .preIndex
        }
        let rtRef = lsGprOperand(encoding: Rt, width: width, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: width, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(
            base: .register(rnRef), displacement: displacement, writeback: writeback,
        )
        var reads: RegisterSet = lsInsertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = (writeback == .none)
            ? .empty
            : lsInsertingNonZero(reg: rnRef, into: .empty)
        if isLoad {
            writes = lsInsertingNonZero(reg: rtRef, into: writes)
            writes = lsInsertingNonZero(reg: rt2Ref, into: writes)
        } else {
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            reads = lsInsertingNonZero(reg: rt2Ref, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: isLoad ? .load : .store, memoryOrdering: isLoad ? [.acquire] : [.release],
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .register(rt2Ref), .memory(mem)),
        )
    }

    /// LDAP / LDAPP / STLP: `<Xt>, <Xt2>, [<Xn|SP>]`, no writeback.
    @_optimize(speed)
    private static func decodeLSCPPair(
        encoding: UInt32, address: UInt64, mnemonic: Mnemonic, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let Rt2 = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let isLoad = mnemonic != .stlp
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = .empty
        if isLoad {
            writes = lsInsertingNonZero(reg: rtRef, into: writes)
            writes = lsInsertingNonZero(reg: rt2Ref, into: writes)
        } else {
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            reads = lsInsertingNonZero(reg: rt2Ref, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: isLoad ? .load : .store,
            memoryOrdering: isLoad ? [.acquire] : [.release],
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(
                .register(rtRef), .register(rt2Ref),
                .memory(MemoryOperand(base: .register(rnRef))),
            ),
        )
    }

    /// Shell bits[29:24]=011001, bit[21]=0, bits[11:10]=10, bits[20:16]=00000,
    /// size ∈ {10=W,11=X}.
    @_optimize(speed)
    static func decodeRCPC3Single(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        if size < 0b10 {
            return .undefined(at: address, encoding: encoding)
        }
        if (encoding >> 16) & 0x1F != 0 || (encoding >> 12) & 0xF != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let opc = UInt8((encoding >> 22) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let width: RegisterWidth = (size == 0b11) ? .x64 : .w32
        let dataSize: Int64 = (size == 0b11) ? 8 : 4
        let isLoad: Bool
        let mnemonic: Mnemonic
        let displacement: Int64
        let writeback: Writeback
        var ordering: MemoryOrdering
        switch opc {
        case 0b10:
            mnemonic = .stlr; isLoad = false
            displacement = -dataSize; writeback = .preIndex; ordering = [.release]
        default:
            mnemonic = .ldapr; isLoad = true
            displacement = dataSize; writeback = .postIndex; ordering = [.acquire]
        }
        let rtRef = lsGprOperand(encoding: Rt, width: width, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let mem = MemoryOperand(
            base: .register(rnRef), displacement: displacement, writeback: writeback,
        )
        var reads: RegisterSet = lsInsertingNonZero(reg: rnRef, into: .empty)
        var writes: RegisterSet = lsInsertingNonZero(reg: rnRef, into: .empty)
        if isLoad {
            writes = lsInsertingNonZero(reg: rtRef, into: writes)
        } else {
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
        }
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, branchClass: .none,
            memoryAccess: isLoad ? .load : .store, memoryOrdering: ordering,
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(mem)),
        )
    }

    @_optimize(speed)
    static func decodeGCS(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 30) != 0b11 || (encoding >> 22) & 0x3 != 0b00
            || (encoding >> 16) & 0x1F != 0x1F
        {
            return .undefined(at: address, encoding: encoding)
        }
        let op = UInt8((encoding >> 12) & 0xF)
        let mnemonic: Mnemonic
        switch op {
        case 0b0000: mnemonic = .gcsstr
        case 0b0001: mnemonic = .gcssttr
        default: return .undefined(at: address, encoding: encoding)
        }
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rtRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: .empty, branchClass: .none,
            memoryAccess: .store, memoryOrdering: [], flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    /// Ordering slot from bits[23:22] = (A, R).
    @inline(__always)
    @_effects(readonly)
    private static func orderSlot(_ encoding: UInt32) -> Int {
        let A = Int((encoding >> 23) & 1)
        let R = Int((encoding >> 22) & 1)
        return A * 2 + R
    }

    @inline(__always)
    @_effects(readonly)
    private static func orderingFor(_ encoding: UInt32) -> MemoryOrdering {
        var ordering: MemoryOrdering = []
        if (encoding >> 23) & 1 == 1 { ordering.insert(.acquire) }
        if (encoding >> 22) & 1 == 1 { ordering.insert(.release) }
        return ordering
    }
}
