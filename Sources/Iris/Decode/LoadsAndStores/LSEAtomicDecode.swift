// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// LSE atomic memory operations (Armv8.1 FEAT_LSE).
// Encoding shell bits[29:24] = 111000, V=0, bit[21]=1, bits[11:10]=00.
//
//   bits[31:30] = size: 00=byte (B suffix), 01=halfword (H suffix),
//                       10=word (Wt), 11=dword (Xt)
//   bit[23] = A, bit[22] = R: ordering bits.
//     (0,0) = no-ordering (no suffix)
//     (1,0) = acquire (A suffix)
//     (0,1) = release (L suffix)
//     (1,1) = acquire+release (AL suffix)
//   bits[20:16] = Rs (the operand register)
//   bits[15:12] = opc: selects the RMW operation
//     0000=LDADD, 0001=LDCLR, 0010=LDEOR, 0011=LDSET
//     0100=LDSMAX, 0101=LDSMIN, 0110=LDUMAX, 0111=LDUMIN
//     1000=SWP
//   bits[9:5] = Rn (base)
//   bits[4:0] = Rt (destination; loaded original value)
//
// ST*-alias collapse: when Rt=ZR/WZR/XZR and the acquire bit A=0, the
// eight RMW operations alias to STADD / STCLR / STEOR / STSET / STSMAX /
// STSMIN / STUMAX / STUMIN at the plain and release orderings, all sizes.
// llvm-mc keeps the LD* form for the A=1 orderings, and SWP never
// aliases. The aliased form drops Rt from the operand list (Rs, [Rn|SP]).

enum LSEAtomicDecode {
    /// Base RMW mnemonics, one row per `op` (rows match opc 0000..1000).
    /// Each row holds 12 entries — [plain, A, L, AL] for the word/dword,
    /// byte, then halfword size groups — indexed `sizeSlot * 4 + ord`.
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

    /// ST*-alias mnemonics, one row per RMW `op` (rows match opc 0000..0111
    /// — SWP has no alias). Each row holds 6 entries — [plain, L] for the
    /// word/dword, byte, then halfword size groups — indexed
    /// `sizeSlot * 2 + R`. Only the two A=0 orderings collapse to an alias.
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
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let A = UInt8((encoding >> 23) & 1)
        let R = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let op = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // op ∈ {0000..1000} valid; others reserved here.
        if op > 0b1000 {
            return .undefined(at: address, encoding: encoding)
        }

        let regWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        // Lookup the (base mnemonic, ST-alias) pair for this (op × size ×
        // ordering) cube cell. The alias is nil for SWP and for the A=1
        // orderings — neither has an ST* collapse.
        let (baseMnemonic, aliasMnemonic) = lseMnemonics(op: op, size: size, A: A, R: R)

        // ST*-alias collapse: llvm-mc emits an ST* alias only when Rt is
        // ZR/WZR/XZR (Rt == 31). `lseMnemonics` already gates the alias on
        // A=0 — with A=1 the acquire bit keeps the LD* mnemonic even though
        // the loaded value is discarded into ZR.
        let useAlias = (Rt == 31) && (aliasMnemonic != nil)
        let mnemonic = useAlias ? aliasMnemonic! : baseMnemonic

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)

        // Semantics: reads Rs + Rn; writes Rt (loaded original memory value).
        // For ST* alias (Rt=ZR), Rt write is discarded.
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes: RegisterSet = useAlias
            ? .empty
            : lsInsertingNonZero(reg: rtRef, into: .empty)

        let operands: [Operand] = useAlias
            ? [.register(rsRef), .memory(MemoryOperand(base: .register(rnRef)))]
            : [.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))]

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
            operands: operands,
        )
    }

    /// Return the (base, optional ST-alias) mnemonics for a given LSE atomic
    /// (operation, size, A, R) tuple. The ST alias is non-nil only for the
    /// two A=0 orderings of the eight RMW ops, and is always nil for SWP.
    @_effects(readonly)
    static func lseMnemonics(
        op: UInt8, size: UInt8, A: UInt8, R: UInt8,
    ) -> (Mnemonic, Mnemonic?) {
        // Size-suffix slot: 0 = no suffix (word/dword via Wt/Xt width),
        // 1 = B (byte), 2 = H (halfword). size ∈ {00,01,10,11} enumerated.
        let sizeSlot = switch size {
        case 0b00: 1 // B
        case 0b01: 2 // H
        default: 0 // word or dword (no suffix)
        }
        // Ordering slot: 0=plain, 1=acquire, 2=release, 3=AL.
        // (A,R) ∈ {0,1}² all enumerated; (1,1)=AL is `default`.
        let ord = switch (A, R) {
        case (0, 0): 0
        case (1, 0): 1
        case (0, 1): 2
        default: 3
        }
        let baseIdx = sizeSlot * 4 + ord
        let aliasIdx = sizeSlot * 2 + Int(R)
        // `decode` rejects op > 0b1000 before calling, so op ∈ {0..8}. The
        // switch maps each op to its row in the precomputed tables; SWP
        // (op 8, the `default` arm) has no ST* alias.
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
