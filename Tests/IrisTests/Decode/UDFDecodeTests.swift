// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the decoder core's `UDF` (Permanently Undefined) recognition:
/// the `op0=0` reserved tier's single allocated encoding `0x0000_NNNN`
/// decodes to `udf #imm16` across the whole 16-bit immediate space, is owned
/// by the dispatcher itself independent of which family decoders are
/// registered, and does not capture neighbouring non-UDF `op0=0` encodings
/// (which stay with family dispatch). Closes the op0=0 blind spot the
/// per-family sweeps (op0 ∈ 4…15) structurally could not cover.
@Suite struct UDFDecodeTests {
    @Test func everyImm16DecodesToUDF() {
        var firstDivergence: UInt32?
        for imm in UInt32(0) ... 0xFFFF {
            let draft = decode(imm, at: 0)
            let ok = draft.mnemonic == .udf
                && draft.category == .branchesExceptionSystem
                && draft.branchClass == .exception
                && Array(draft.operands) == [.unsignedImmediate(value: UInt64(imm), width: 16)]
                && draft.semanticReads == .empty
                && draft.semanticWrites == .empty
                && draft.encoding == imm
            if !ok {
                firstDivergence = imm
                break
            }
        }
        #expect(firstDivergence == nil,
                "UDF decode diverged at imm=\(firstDivergence.map(String.init) ?? "none")")
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
        // UDF is intercepted before family dispatch — the AMX family also
        // sits at op0=0 but never sees bits[31:16] == 0 words.
        let draft = decode(0x0000_000C, at: 0)
        #expect(draft.mnemonic == .udf)
        #expect(Array(draft.operands) == [.unsignedImmediate(value: 0x0C, width: 16)])
    }

    @Test func nonUDFOp0ZeroEncodingIsNotCaptured() {
        // op0 = 0 but bits[31:16] != 0 → not UDF: it routes to the op0=0
        // family (AMX), where a non-AMX bit pattern is honest UNDEFINED.
        let draft = decode(0x0020_0000, at: 0)
        #expect(draft.mnemonic == .undefined)
        #expect(draft.mnemonic != .udf)
    }
}
