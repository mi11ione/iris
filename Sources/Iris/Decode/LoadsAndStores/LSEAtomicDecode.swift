// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LSEAtomicDecode {
    /// Base RMW mnemonics, one row per `op` (rows match opc 0000..1000).
    private static let basesByOp: [[Mnemonic]] = [
        [.ldadd, .ldadda, .ldaddl, .ldaddal,
         .ldaddb, .ldaddab, .ldaddlb, .ldaddalb,
         .ldaddh, .ldaddah, .ldaddlh, .ldaddalh],
        [.ldclr, .ldclra, .ldclrl, .ldclral,
         .ldclrb, .ldclrab, .ldclrlb, .ldclralb,
         .ldclrh, .ldclrah, .ldclrlh, .ldclralh],
        [.ldeor, .ldeora, .ldeorl, .ldeoral,
         .ldeorb, .ldeorab, .ldeorlb, .ldeoralb,
         .ldeorh, .ldeorah, .ldeorlh, .ldeoralh],
        [.ldset, .ldseta, .ldsetl, .ldsetal,
         .ldsetb, .ldsetab, .ldsetlb, .ldsetalb,
         .ldseth, .ldsetah, .ldsetlh, .ldsetalh],
        [.ldsmax, .ldsmaxa, .ldsmaxl, .ldsmaxal,
         .ldsmaxb, .ldsmaxab, .ldsmaxlb, .ldsmaxalb,
         .ldsmaxh, .ldsmaxah, .ldsmaxlh, .ldsmaxalh],
        [.ldsmin, .ldsmina, .ldsminl, .ldsminal,
         .ldsminb, .ldsminab, .ldsminlb, .ldsminalb,
         .ldsminh, .ldsminah, .ldsminlh, .ldsminalh],
        [.ldumax, .ldumaxa, .ldumaxl, .ldumaxal,
         .ldumaxb, .ldumaxab, .ldumaxlb, .ldumaxalb,
         .ldumaxh, .ldumaxah, .ldumaxlh, .ldumaxalh],
        [.ldumin, .ldumina, .lduminl, .lduminal,
         .lduminb, .lduminab, .lduminlb, .lduminalb,
         .lduminh, .lduminah, .lduminlh, .lduminalh],
        [.swp, .swpa, .swpl, .swpal,
         .swpb, .swpab, .swplb, .swpalb,
         .swph, .swpah, .swplh, .swpalh],
    ]

    /// ST*-alias mnemonics, one row per RMW `op` (opc 0000..0111; SWP has no
    /// alias).
    private static let aliasesByOp: [[Mnemonic]] = [
        [.stadd, .staddl, .staddb, .staddlb, .staddh, .staddlh],
        [.stclr, .stclrl, .stclrb, .stclrlb, .stclrh, .stclrlh],
        [.steor, .steorl, .steorb, .steorlb, .steorh, .steorlh],
        [.stset, .stsetl, .stsetb, .stsetlb, .stseth, .stsetlh],
        [.stsmax, .stsmaxl, .stsmaxb, .stsmaxlb, .stsmaxh, .stsmaxlh],
        [.stsmin, .stsminl, .stsminb, .stsminlb, .stsminh, .stsminlh],
        [.stumax, .stumaxl, .stumaxb, .stumaxlb, .stumaxh, .stumaxlh],
        [.stumin, .stuminl, .stuminb, .stuminlb, .stuminh, .stuminlh],
    ]

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let A = UInt8((encoding >> 23) & 1)
        let R = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let op = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if op > 0b1000 {
            return .undefined(at: address, encoding: encoding)
        }

        let regWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        let (baseMnemonic, aliasMnemonic) = lseMnemonics(op: op, size: size, A: A, R: R)

        let useAlias = (Rt == 31) && (aliasMnemonic != nil)
        let mnemonic = useAlias ? aliasMnemonic! : baseMnemonic

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)

        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes: RegisterSet = useAlias
            ? .empty
            : lsInsertingNonZero(reg: rtRef, into: .empty)

        let operandCount = useAlias
            ? sink.emit(.register(rsRef), .memory(MemoryOperand(base: .register(rnRef))))
            : sink.emit(
                .register(rsRef), .register(rtRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            )

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: ordering,
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: operandCount,
        )
    }

    /// Return the (base, optional ST-alias) mnemonics for a given LSE atomic
    /// (operation, size, A, R) tuple.
    @_effects(readonly)
    static func lseMnemonics(
        op: UInt8, size: UInt8, A: UInt8, R: UInt8,
    ) -> (Mnemonic, Mnemonic?) {
        let sizeSlot = switch size {
        case 0b00: 1
        case 0b01: 2
        default: 0
        }
        let ord = switch (A, R) {
        case (0, 0): 0
        case (1, 0): 1
        case (0, 1): 2
        default: 3
        }
        let baseIdx = sizeSlot * 4 + ord
        let aliasIdx = sizeSlot * 2 + Int(R)
        switch op {
        case 0b0000: return (basesByOp[0][baseIdx], A == 0 ? aliasesByOp[0][aliasIdx] : nil)
        case 0b0001: return (basesByOp[1][baseIdx], A == 0 ? aliasesByOp[1][aliasIdx] : nil)
        case 0b0010: return (basesByOp[2][baseIdx], A == 0 ? aliasesByOp[2][aliasIdx] : nil)
        case 0b0011: return (basesByOp[3][baseIdx], A == 0 ? aliasesByOp[3][aliasIdx] : nil)
        case 0b0100: return (basesByOp[4][baseIdx], A == 0 ? aliasesByOp[4][aliasIdx] : nil)
        case 0b0101: return (basesByOp[5][baseIdx], A == 0 ? aliasesByOp[5][aliasIdx] : nil)
        case 0b0110: return (basesByOp[6][baseIdx], A == 0 ? aliasesByOp[6][aliasIdx] : nil)
        case 0b0111: return (basesByOp[7][baseIdx], A == 0 ? aliasesByOp[7][aliasIdx] : nil)
        default: return (basesByOp[8][baseIdx], nil)
        }
    }
}
