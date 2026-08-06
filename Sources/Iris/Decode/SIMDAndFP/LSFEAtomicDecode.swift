// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LSFEAtomicDecode {
    /// Load forms, one row per operation, columns `bf` then `f` and within each
    /// infix the (A, R) order plain / `a` / `l` / `al`.
    private static let loadsByOperation: [[Mnemonic]] = [
        [.ldbfadd, .ldbfadda, .ldbfaddl, .ldbfaddal,
         .ldfadd, .ldfadda, .ldfaddl, .ldfaddal],
        [.ldbfmax, .ldbfmaxa, .ldbfmaxl, .ldbfmaxal,
         .ldfmax, .ldfmaxa, .ldfmaxl, .ldfmaxal],
        [.ldbfmin, .ldbfmina, .ldbfminl, .ldbfminal,
         .ldfmin, .ldfmina, .ldfminl, .ldfminal],
        [.ldbfmaxnm, .ldbfmaxnma, .ldbfmaxnml, .ldbfmaxnmal,
         .ldfmaxnm, .ldfmaxnma, .ldfmaxnml, .ldfmaxnmal],
        [.ldbfminnm, .ldbfminnma, .ldbfminnml, .ldbfminnmal,
         .ldfminnm, .ldfminnma, .ldfminnml, .ldfminnmal],
    ]

    /// Store forms, one row per operation, columns `bf` then `f` and within
    /// each infix the R order plain / `l`.
    private static let storesByOperation: [[Mnemonic]] = [
        [.stbfadd, .stbfaddl, .stfadd, .stfaddl],
        [.stbfmax, .stbfmaxl, .stfmax, .stfmaxl],
        [.stbfmin, .stbfminl, .stfmin, .stfminl],
        [.stbfmaxnm, .stbfmaxnml, .stfmaxnm, .stfmaxnml],
        [.stbfminnm, .stbfminnml, .stfminnm, .stfminnml],
    ]

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let A = UInt8((encoding >> 23) & 0x1)
        let R = UInt8((encoding >> 22) & 0x1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let o3 = UInt8((encoding >> 15) & 0x1)
        let opc = UInt8((encoding >> 12) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        guard let operation = operationRow(opc: opc) else {
            return .undefined(at: address, encoding: encoding)
        }
        let elementSize: ScalarSize = switch size {
        case 0b10: .s
        case 0b11: .d
        default: .h
        }
        let infix = size == 0b00 ? 0 : 1
        let base = simdfpGprOperand(encoding: Rn, width: .x64, spOrGeneral: true)
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }
        var reads = simdfpInsertingVector(Rs, into: .empty)
        reads = simdfpInsertingNonZeroGPR(reg: base, into: reads)
        let memory = MemoryOperand(base: .register(base))
        let source = simdfpScalarOperand(Rs, size: elementSize)

        if o3 == 1 {
            if A == 1 || Rt != 0b11111 {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address, encoding: encoding,
                mnemonic: storesByOperation[operation][infix * 2 + Int(R)],
                semanticReads: reads, semanticWrites: .empty,
                branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
                flagEffect: .none, category: .simdAndFP,
                operandCount: sink.emit(source, .memory(memory)),
            )
        }
        return DecodedDraft(
            address: address, encoding: encoding,
            mnemonic: loadsByOperation[operation][infix * 4 + Int(A) + Int(R) * 2],
            semanticReads: reads,
            semanticWrites: simdfpInsertingVector(Rt, into: .empty),
            branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
            flagEffect: .none, category: .simdAndFP,
            operandCount: sink.emit(source, simdfpScalarOperand(Rt, size: elementSize), .memory(memory)),
        )
    }

    /// `opc` → row in the mnemonic tables; nil for the three unallocated
    /// operation codes.
    @inline(__always)
    @_effects(readonly)
    private static func operationRow(opc: UInt8) -> Int? {
        switch opc {
        case 0b000: 0
        case 0b100: 1
        case 0b101: 2
        case 0b110: 3
        case 0b111: 4
        default: nil
        }
    }
}
