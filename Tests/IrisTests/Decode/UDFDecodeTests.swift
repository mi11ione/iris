// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `UDF` recognition.
@Suite struct UDFDecodeTests {
    @Test func everyImm16DecodesToUDF() {
        let divergences = (UInt32(0) ... 0xFFFF).filter { imm in
            let draft = decode(imm, at: 0)
            return !(draft.mnemonic == .udf
                && draft.category == .branchesExceptionSystem
                && draft.branchClass == .exception
                && Array(draft.operands) == [.unsignedImmediate(value: UInt64(imm), width: 16)]
                && draft.semanticReads == .empty
                && draft.semanticWrites == .empty
                && draft.encoding == imm)
        }
        #expect(divergences.isEmpty,
                "UDF decode diverged at imm=\(divergences.first.map(String.init) ?? "none")")
    }

    @Test func boundaryImmediates() {
        let zero = decode(0x0000_0000, at: 0)
        #expect(zero.mnemonic == .udf)
        #expect(Array(zero.operands) == [.unsignedImmediate(value: 0, width: 16)])

        let top = decode(0x0000_FFFF, at: 0)
        #expect(top.mnemonic == .udf)
        #expect(Array(top.operands) == [.unsignedImmediate(value: 0xFFFF, width: 16)])
    }

    @Test func ownedByTheDispatcherNotAFamilyDecoder() {
        let draft = decode(0x0000_000C, at: 0)
        #expect(draft.mnemonic == .udf)
        #expect(Array(draft.operands) == [.unsignedImmediate(value: 0x0C, width: 16)])
    }

    @Test func nonUDFOp0ZeroEncodingIsNotCaptured() {
        let draft = decode(0x0020_0000, at: 0)
        #expect(draft.mnemonic == .undefined)
        #expect(draft.mnemonic != .udf)
    }
}
