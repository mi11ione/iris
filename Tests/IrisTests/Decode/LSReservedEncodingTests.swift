// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Exhaustive catalogue of the named reserved-encoding classes
/// (E6 register-offset options, E8 CAS fixed bits, E9 LSE reserved
/// operations, E30 exclusive-pair sizes, plus the pair/indexed/CASP
/// reserved sub-patterns). The per-class suites cover one example per
/// branch; this suite proves every documented reserved sub-pattern
/// decodes UNDEFINED — a malformed encoding must never produce a
/// plausible-looking record (the inherited invariant: silent skip,
/// never silent guess).
@Suite("L/S reserved-encoding catalogue")
struct LSReservedEncodingTests {
    /// `(encoding, spec-class, description)`. Every row must decode to
    /// `mnemonic == .undefined` and `category == .undefined` under an
    /// ARM64E context (the strictest — LDRAA/LDRAB decode there, so a
    /// reserved row staying UNDEFINED proves it is genuinely rejected,
    /// not merely gated off by a non-ARM64E context).
    static let reservedEncodings: [(encoding: UInt32, specClass: String, description: String)] = [
        // E6 — register-offset reserved extend options 000/001/100/101
        // (only 010/011/110/111 are architecturally valid).
        (0x3820_0800, "E6", "register-offset extend option 000"),
        (0x3820_2800, "E6", "register-offset extend option 001"),
        (0x3820_8800, "E6", "register-offset extend option 100"),
        (0x3820_A800, "E6", "register-offset extend option 101"),
        // E8 — CAS requires bits[14:10] = 11111; any other value reserved.
        (0x88A0_7800, "E8", "CAS bits[14:10] = 11110"),
        (0x88A0_3C00, "E8", "CAS bits[14:10] = 01111"),
        // (FEAT_THE RCW now decodes the 1001/1010/1011 operation fields in
        // this shell as rcw{clr,swp,set}* — no longer reserved.)
        // E30 — exclusive-pair shell with size 00/01 (no byte/halfword
        // exclusive pair); routed to the CASP path, rejected on the
        // fixed bits[14:10] = 11111 requirement.
        (0x0820_0000, "E30", "exclusive-pair shell, size 00"),
        (0x4820_0000, "E30", "exclusive-pair shell, size 01"),
        // CASP even-register constraint — odd Rs, odd Rt, and both odd.
        (0x0821_7C00, "E29", "CASP odd Rs"),
        (0x0820_7C01, "E29", "CASP odd Rt"),
        (0x0821_7C01, "E29", "CASP odd Rs and odd Rt"),
        // Load/store pair reserved sub-patterns. (opc=11 no-allocate is now
        // STTNP, a valid temporal-pair store — removed from the reserved set.)
        (0x6800_0000, "L6", "LDPSW/STGP no-allocate form (indexing 00)"),
        // Indexed register reserved — size 11, opc 10 has no indexed form.
        (0xF880_0400, "L8", "post-indexed size 11 opc 10"),
        // LDRAA/LDRAB are 64-bit doubleword only — size 01 reserved.
        (0x7820_0400, "E13", "LDRAA size 01 (non-doubleword)"),
    ]

    @Test func everyReservedEncodingDecodesToUndefined() {
        for row in Self.reservedEncodings {
            let d = decode(row.encoding, at: 0, features: .arm64e)
            #expect(
                d.mnemonic == .undefined,
                "[\(row.specClass)] 0x\(String(format: "%08x", row.encoding)) \(row.description): expected .undefined, got mnemonic \(d.mnemonic.rawValue)",
            )
            #expect(
                d.category == .undefined,
                "[\(row.specClass)] 0x\(String(format: "%08x", row.encoding)) \(row.description): expected .undefined category, got \(d.category)",
            )
            // A reserved encoding still preserves its raw bytes verbatim
            // (the UNDEFINED-record convention) for downstream inspection.
            #expect(
                d.encoding == row.encoding,
                "[\(row.specClass)] 0x\(String(format: "%08x", row.encoding)): raw encoding not preserved",
            )
            #expect(d.operands.isEmpty, "[\(row.specClass)]: UNDEFINED draft must carry no operands")
        }
    }

    @Test func validLdraaIsUnallocatedOutsideArm64E() {
        // E13 — a well-formed LDRAA encoding is unallocated on plain
        // ARM64; the dispatcher's `context.isARM64E` gate yields UNDEFINED.
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        // The same encoding IS valid under an ARM64E context — proves the
        // gate is context-driven, not a blanket rejection.
        let e = decode(0xF820_0400, at: 0, features: .arm64e)
        #expect(e.mnemonic == .ldraa)
    }
}
