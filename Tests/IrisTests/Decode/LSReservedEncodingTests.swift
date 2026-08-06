// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Exhaustive catalogue of the named reserved-encoding classes.
@Suite("L/S reserved-encoding catalogue")
struct LSReservedEncodingTests {
    static let reservedEncodings: [(encoding: UInt32, specClass: String, description: String)] = [
        (0x3820_0800, "E6", "register-offset extend option 000"),
        (0x3820_2800, "E6", "register-offset extend option 001"),
        (0x3820_8800, "E6", "register-offset extend option 100"),
        (0x3820_A800, "E6", "register-offset extend option 101"),
        (0x88A0_7800, "E8", "CAS bits[14:10] = 11110"),
        (0x88A0_3C00, "E8", "CAS bits[14:10] = 01111"),
        (0x0820_0000, "E30", "exclusive-pair shell, size 00"),
        (0x4820_0000, "E30", "exclusive-pair shell, size 01"),
        (0x0821_7C00, "E29", "CASP odd Rs"),
        (0x0820_7C01, "E29", "CASP odd Rt"),
        (0x0821_7C01, "E29", "CASP odd Rs and odd Rt"),
        (0x6800_0000, "L6", "LDPSW/STGP no-allocate form (indexing 00)"),
        (0xF880_0400, "L8", "post-indexed size 11 opc 10"),
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
            #expect(
                d.encoding == row.encoding,
                "[\(row.specClass)] 0x\(String(format: "%08x", row.encoding)): raw encoding not preserved",
            )
            #expect(d.operands.isEmpty, "[\(row.specClass)]: UNDEFINED draft must carry no operands")
        }
    }

    @Test func validLdraaIsUnallocatedOutsideArm64E() {
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        let e = decode(0xF820_0400, at: 0, features: .arm64e)
        #expect(e.mnemonic == .ldraa)
    }
}
