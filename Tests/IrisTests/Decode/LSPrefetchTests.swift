// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates prefetch across all four carrying classes.
@Suite("L/S prefetch operand decode")
struct LSPrefetchTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func prfmLiteralCarriesRtAsPrefetchOperand() {
        let d = decode(0xD800_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads == .empty)
    }

    @Test func prfumUnscaledCarriesPrefetchOperand() {
        let d = decode(0xF880_0000)
        #expect(d.mnemonic == .prfum)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticWrites == .empty)
    }

    @Test func prfmUnsignedOffsetCarriesPrefetchOperand() {
        let d = decode(0xF980_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
    }

    @Test func prfmRegisterOffsetCarriesPrefetchOperand() {
        let d = decode(0xF8A0_4800)
        #expect(d.mnemonic == .prfm)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
    }

    @Test func rtFieldFlowsThroughToThePrefetchOperationRawValue() {
        #expect(decode(0xD800_0005).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 5)))
        #expect(decode(0xD800_0010).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 16)))
        #expect(decode(0xD800_001F).operands.first == .prefetchOperation(PrefetchOperation(rawValue: 31)))
    }

    @Test func prefetchOperandRendersSymbolicallyWhenDecodable() {
        #expect(decode(0xD800_0000).text == "prfm pldl1keep, #0")
        #expect(decode(0xD800_0005).text == "prfm pldl3strm, #0")
        #expect(decode(0xD800_0010).text == "prfm pstl1keep, #0")
    }

    @Test func reservedPrefetchOperandRendersAsRawNumber() {
        #expect(decode(0xF880_001F).text == "prfum #31, [x0]")
    }
}
