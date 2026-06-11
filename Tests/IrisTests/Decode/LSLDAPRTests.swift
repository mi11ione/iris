// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L4b LDAPR class (FEAT_LRCPC) — the
/// RCpc-acquire register loads LDAPR / LDAPRB / LDAPRH. Each is a plain
/// `.load` with `.acquire` ordering and a bare `[Rn|SP]` operand.
@Suite("L/S LDAPR (RCpc) decode")
struct LSLDAPRTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldaprbByteForm() {
        // 0x38bfc000 = ldaprb w0, [x0].
        let d = decode(0x38BF_C000)
        #expect(d.mnemonic == .ldaprb)
        #expect(Array(d.operands) == [.register(.w(0)), .memory(MemoryOperand(base: .register(.x(0))))])
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldaprhHalfwordForm() {
        // 0x78bfc000 = ldaprh w0, [x0].
        let d = decode(0x78BF_C000)
        #expect(d.mnemonic == .ldaprh)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func ldaprWordForm() {
        // 0xb8bfc000 = ldapr w0, [x0] — size=10 selects Wt.
        let d = decode(0xB8BF_C000)
        #expect(d.mnemonic == .ldapr)
        #expect(d.operands.first == .register(.w(0)))
        #expect(d.memoryAccess == .load)
    }

    @Test func ldaprDoublewordForm() {
        // 0xf8bfc000 = ldapr x0, [x0] — size=11 selects Xt.
        let d = decode(0xF8BF_C000)
        #expect(d.mnemonic == .ldapr)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.memoryOrdering == [.acquire])
    }
}
