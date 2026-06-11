// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates SystemRegisterEncoding — the 5-field tuple
/// `(op0, op1, CRn, CRm, op2)` packed into a single UInt16, with field
/// widths 2 / 3 / 4 / 4 / 3 bits respectively.
@Suite("SystemRegisterEncoding / tuple pack and unpack")
struct SystemRegisterEncodingTests {
    @Test func packedZeroDecodesToAllZeroSubFields() {
        let e = SystemRegisterEncoding(packed: 0)
        #expect(e.op0 == 0)
        #expect(e.op1 == 0)
        #expect(e.crn == 0)
        #expect(e.crm == 0)
        #expect(e.op2 == 0)
    }

    @Test func subFieldInitRoundTrips() {
        let e = SystemRegisterEncoding(op0: 3, op1: 5, crn: 9, crm: 11, op2: 6)
        #expect(e.op0 == 3)
        #expect(e.op1 == 5)
        #expect(e.crn == 9)
        #expect(e.crm == 11)
        #expect(e.op2 == 6)
    }

    @Test func tpidrEl0PacksToKnownLiteral() {
        // TPIDR_EL0 — op0=3 op1=3 CRn=13 CRm=0 op2=2 — packs to 0xDE82.
        // Literal expectation rather than re-derived formula so the
        // test catches any reshuffle of the bit-pack layout (which
        // would silently round-trip if both sides used the same code).
        let e = SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)
        #expect(e.packed == 0xDE82)
        #expect(e.op0 == 3)
        #expect(e.op1 == 3)
        #expect(e.crn == 13)
        #expect(e.crm == 0)
        #expect(e.op2 == 2)
    }

    @Test func cntvctEl0PacksToKnownLiteral() {
        // CNTVCT_EL0 — op0=3 op1=3 CRn=14 CRm=0 op2=2 — packs to 0xDF02.
        let e = SystemRegisterEncoding(op0: 3, op1: 3, crn: 14, crm: 0, op2: 2)
        #expect(e.packed == 0xDF02)
    }

    @Test func subFieldsAreMaskedToTheirArchitecturalWidths() {
        let e = SystemRegisterEncoding(op0: 0xFF, op1: 0xFF, crn: 0xFF, crm: 0xFF, op2: 0xFF)
        #expect(e.op0 == 0b11)
        #expect(e.op1 == 0b111)
        #expect(e.crn == 0b1111)
        #expect(e.crm == 0b1111)
        #expect(e.op2 == 0b111)
    }

    @Test func packedRoundTrip() {
        for packed: UInt16 in [0, 1, 0xFFFF, 0xDEAD, 0x1234] {
            let e = SystemRegisterEncoding(packed: packed)
            #expect(e.packed == packed)
        }
    }

    @Test func equalEncodingsHashEqual() {
        let a = SystemRegisterEncoding(packed: 0xABCD)
        let b = SystemRegisterEncoding(packed: 0xABCD)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates SystemOp — raw-bits wrapper for IC/DC/AT/TLBI operands.
@Suite("SystemOp / raw-bits round-trip")
struct SystemOpTests {
    @Test func rawEncodingIsPreserved() {
        let op = SystemOp(rawEncoding: 0xDEAD_BEEF)
        #expect(op.rawEncoding == 0xDEAD_BEEF)
    }

    @Test func zeroIsValid() {
        #expect(SystemOp(rawEncoding: 0).rawEncoding == 0)
    }

    @Test func maxIsValid() {
        #expect(SystemOp(rawEncoding: UInt32.max).rawEncoding == UInt32.max)
    }

    @Test func equalRawsHashEqual() {
        let a = SystemOp(rawEncoding: 0x1234_5678)
        let b = SystemOp(rawEncoding: 0x1234_5678)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates AMXField — raw-bits wrapper for AMX operand payloads.
@Suite("AMXField / raw-bits round-trip")
struct AMXFieldTests {
    @Test func rawBitsArePreserved() {
        let f = AMXField(rawBits: 0xCAFE_F00D)
        #expect(f.rawBits == 0xCAFE_F00D)
    }

    @Test func zeroIsValid() {
        #expect(AMXField(rawBits: 0).rawBits == 0)
    }

    @Test func maxIsValid() {
        #expect(AMXField(rawBits: UInt32.max).rawBits == UInt32.max)
    }

    @Test func equalRawsHashEqual() {
        let a = AMXField(rawBits: 0x4242_4242)
        let b = AMXField(rawBits: 0x4242_4242)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}
