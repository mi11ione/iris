// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates prefetch decoding across the four classes that carry a
/// `PRFM`/`PRFUM` operand: literal,
/// unscaled, register-offset and unsigned-offset. Every prefetch
/// instruction is `.prefetch`, writes nothing, and carries the raw 5-bit
/// `Rt` field in a `.prefetchOperation` operand.
@Suite("L/S prefetch operand decode")
struct LSPrefetchTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func prfmLiteralCarriesRtAsPrefetchOperand() {
        // 0xd8000000 = prfm pldl1keep, #0 — Rt=0.
        let d = decode(0xD800_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads == .empty)
    }

    @Test func prfumUnscaledCarriesPrefetchOperand() {
        // 0xf8800000 = prfum pldl1keep, [x0] — Rt=0.
        let d = decode(0xF880_0000)
        #expect(d.mnemonic == .prfum)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticWrites == .empty)
    }

    @Test func prfmUnsignedOffsetCarriesPrefetchOperand() {
        // 0xf9800000 = prfm pldl1keep, [x0] — Rt=0.
        let d = decode(0xF980_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
    }

    @Test func prfmRegisterOffsetCarriesPrefetchOperand() {
        // 0xf8a04800 = prfm pldl1keep, [x0, w0, uxtw] — Rt=0.
        let d = decode(0xF8A0_4800)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
    }

    @Test func rtFieldFlowsThroughToThePrefetchOperationRawValue() {
        // The 5-bit Rt slot is the raw prefetch operation; spot-check a
        // few distinct values against the corpus-verified literal forms.
        #expect(decode(0xD800_0005).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 5)))
        #expect(decode(0xD800_0010).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 16)))
        #expect(decode(0xD800_001F).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 31)))
    }

    @Test func prefetchOperandRendersSymbolicallyWhenDecodable() {
        // pldl1keep / pldl3strm / pstl1keep — three valid prfop encodings.
        #expect(decode(0xD800_0000).text == "prfm pldl1keep, #0")
        #expect(decode(0xD800_0005).text == "prfm pldl3strm, #0")
        #expect(decode(0xD800_0010).text == "prfm pstl1keep, #0")
    }

    @Test func reservedPrefetchOperandRendersAsRawNumber() {
        // 0xf880001f = prfum #31, [x0] — Rt=31 has a reserved operation
        // field, so it renders as the raw 5-bit value.
        #expect(decode(0xF880_001F).text == "prfum #31, [x0]")
    }
}
