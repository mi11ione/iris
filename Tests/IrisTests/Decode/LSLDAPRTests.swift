// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FEAT_LRCPC LDAPR class.
@Suite("L/S LDAPR (RCpc) decode")
struct LSLDAPRTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldaprbByteForm() {
        let d = decode(0x38BF_C000)
        #expect(d.mnemonic == .ldaprb)
        #expect(Array(d.operands) == [.register(.w(0)), .memory(MemoryOperand(base: .register(.x(0))))])
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldaprhHalfwordForm() {
        let d = decode(0x78BF_C000)
        #expect(d.mnemonic == .ldaprh)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func ldaprWordForm() {
        let d = decode(0xB8BF_C000)
        #expect(d.mnemonic == .ldapr)
        #expect(d.operands.first == .register(.w(0)))
        #expect(d.memoryAccess == .load)
    }

    @Test func ldaprDoublewordForm() {
        let d = decode(0xF8BF_C000)
        #expect(d.mnemonic == .ldapr)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.memoryOrdering == [.acquire])
    }
}
