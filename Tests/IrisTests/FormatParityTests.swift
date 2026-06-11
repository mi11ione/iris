// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Old-vs-new equivalence for the two formatting sites whose
// Foundation `String(format:)` implementations were replaced with
// pure Swift in the library: zero-padded lowercase hex
// (`"%0<digits>llx"`) and fixed 8-fraction-digit decimal (`"%.8f"`).
// The test target deliberately imports Foundation to compare against
// the original implementations.

import Foundation
import Iris
import Testing

/// Deterministic 64-bit generator (SplitMix64) so the random sweeps are
/// reproducible run to run.
private struct SplitMix64 {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Render one decoded word's SIMD/FP canonical text.
private func simdfpText(of word: UInt32) -> String {
    let bytes: [UInt8] = [
        UInt8(word & 0xFF), UInt8((word >> 8) & 0xFF),
        UInt8((word >> 16) & 0xFF), UInt8((word >> 24) & 0xFF),
    ]
    let stream = InstructionStream(bytes: bytes, at: 0)
    let record = stream.records[0]
    return Instruction(
        address: record.address,
        encoding: record.encoding,
        mnemonic: record.mnemonic,
        semanticReads: record.semanticReads,
        semanticWrites: record.semanticWrites,
        branchClass: record.branchClass,
        memoryAccess: record.memoryAccess,
        memoryOrdering: record.memoryOrdering,
        flagEffect: record.flagEffect,
        category: record.category,
        operands: Array(stream.operands(for: record)),
    ).text
}

/// Render a hand-built single-operand FMOV draft (direct exercise of the
/// float-immediate formatting path with arbitrary bit patterns).
private func fmovText(bits: UInt64, kind: FloatImmediateKind) -> String {
    Instruction(
        address: 0,
        encoding: 0,
        mnemonic: .fmov,
        category: .simdAndFP,
        operands: [.floatImmediate(bits: bits, kind: kind)],
    ).text
}

/// Reference copy of the ARM VFPExpandImm pseudo-code, kept test-local
/// so the parity sweep can construct each imm8's expanded bit pattern
/// without consuming the library's internal expansion (the library's
/// result is observed through the decoded text on the other side of
/// the comparison).
private func referenceVFPExpandImm(imm8: UInt8, kind: FloatImmediateKind) -> UInt64 {
    let sign = UInt64((imm8 >> 7) & 1)
    let b = (UInt64(imm8) >> 6) & 1
    let cde = (UInt64(imm8) >> 4) & 0x7
    let efgh = UInt64(imm8) & 0xF
    let notB = (b ^ 1) & 1
    switch kind {
    case .half:
        let exp = (notB << 4) | ((b == 0 ? 0 : 0b11) << 2) | cde
        return (sign << 15) | (exp << 10) | (efgh << 6)
    case .single:
        let exp = (notB << 7) | ((b == 0 ? 0 : 0b11111) << 2) | cde
        return (sign << 31) | (exp << 23) | (efgh << 19)
    case .double:
        let exp = (notB << 10) | ((b == 0 ? 0 : 0xFF) << 2) | cde
        return (sign << 63) | (exp << 52) | (efgh << 48)
    }
}

// Float16 does not exist on Intel macOS and requires macOS 11+ /
// iOS 14+ floors elsewhere; the float-parity reference is gated
// accordingly (the library itself no longer uses Float16).
#if !(os(macOS) && arch(x86_64))
    /// The reference rendering the replaced site must match: Darwin libc's
    /// `%.8f` of the value the canonicalizer derives from (bits, kind).
    ///
    /// Linux carve-out: glibc's `%.8f` renders a
    /// negative NaN as `-nan` where Darwin — the convention the library
    /// is canonical to — prints unsigned `nan`. The carve-out removes
    /// exactly that sign character, only when the value is NaN, only on
    /// Linux; every other rendering (all finite values, infinities, and
    /// positive NaN) must still match glibc byte-for-byte, and the
    /// Darwin reference is compiled without the carve-out entirely.
    /// NaN is unreachable from decoded FP immediates (VFPExpandImm
    /// cannot produce an all-ones exponent), so this concerns only the
    /// arbitrary-bit-pattern sweeps of the formatter itself.
    private func referenceFloatText(bits: UInt64, kind: FloatImmediateKind) -> String {
        let value = switch kind {
        case .half: Double(Float16(bitPattern: UInt16(truncatingIfNeeded: bits)))
        case .single: Double(Float(bitPattern: UInt32(truncatingIfNeeded: bits)))
        case .double: Double(bitPattern: bits)
        }
        var text = String(format: "%.8f", value)
        #if os(Linux)
            if value.isNaN, text.hasPrefix("-") { text.removeFirst() }
        #endif
        return text
    }
#endif

/// Proves the pure-Swift zero-padded-hex rendering is output-identical
/// to the replaced `String(format: "%0<digits>llx")` site, over the
/// decode-reachable MOVI-64 domain (exhaustive) and a broad arbitrary
/// `UInt64` sweep through the public draft surface.
@Suite struct HexPaddingParityTests {
    /// Every byte of the expansion is 0xFF where the seed bit is set.
    private func movi64Expansion(of seed: UInt8) -> UInt64 {
        var value: UInt64 = 0
        for bit in 0 ..< 8 where (seed >> bit) & 1 == 1 {
            value |= 0xFF << (8 * bit)
        }
        return value
    }

    private func referenceHexText(_ value: UInt64) -> String {
        if value == 0 { return "#0000000000000000" }
        let digits = (value >> 56) != 0 ? 16 : 14
        return "#0x" + String(format: "%0\(digits)llx", value)
    }

    @Test func moviReplicatedByteDomainIsExhaustivelyIdentical() {
        for seed in 0 ... 255 {
            let abc = UInt32(seed >> 5)
            let defgh = UInt32(seed & 0x1F)
            let encoding = 0x2F00_E400 | (abc << 16) | (defgh << 5)
            let expansion = movi64Expansion(of: UInt8(seed))
            let expected = "movi d0, " + referenceHexText(expansion)
            #expect(simdfpText(of: encoding) == expected, "imm8 seed \(seed)")
        }
    }

    @Test func arbitraryWidth64ImmediatesMatchReference() {
        var values: [UInt64] = [UInt64.max]
        for shift in 0 ..< 64 {
            values.append(1 << shift)
            values.append(UInt64.max >> shift)
            values.append(UInt64.max << shift)
        }
        // 2^56 digit-width boundary, both sides.
        values.append(contentsOf: [
            (1 << 56) - 1, 1 << 56, (1 << 56) + 1, 0xDEAD_BEEF_CAFE_F00D,
        ])
        var generator = SplitMix64(state: 0x1233_4455_6677_8899)
        for _ in 0 ..< 10000 {
            values.append(generator.next())
        }
        for value in values where value != 0 {
            let text = Instruction(
                address: 0,
                encoding: 0,
                mnemonic: .movi,
                category: .simdAndFP,
                operands: [.unsignedImmediate(value: value, width: 64)],
            ).text
            #expect(text == "movi " + referenceHexText(value), "value \(value)")
        }
    }

    @Test func zeroRendersFixedSixteenZeros() {
        let text = Instruction(
            address: 0,
            encoding: 0,
            mnemonic: .movi,
            category: .simdAndFP,
            operands: [.unsignedImmediate(value: 0, width: 64)],
        ).text
        #expect(text == "movi #0000000000000000")
    }
}

// Proves the pure-Swift fixed 8-fraction-digit decimal rendering is
// output-identical to the replaced `String(format: "%.8f")` site:
// exhaustively over the decode-reachable FMOV-immediate domain (all
// 256 imm8 expansions at all three precisions), exhaustively over the
// full 16-bit half-precision pattern space, and over special-value and
// random sweeps of single and double patterns.
#if !(os(macOS) && arch(x86_64))
    @Suite struct FloatFormatParityTests {
        @Test func fmovImmediateDecodeDomainIsExhaustivelyIdentical() {
            let forms: [(ftype: UInt32, register: String, kind: FloatImmediateKind)] = [
                (0b00, "s", .single), (0b01, "d", .double), (0b11, "h", .half),
            ]
            for form in forms {
                for imm8 in 0 ... 255 {
                    let encoding = 0x1E20_1000 | (form.ftype << 22) | (UInt32(imm8) << 13)
                    let expandedBits = referenceVFPExpandImm(imm8: UInt8(imm8), kind: form.kind)
                    let expected = "fmov \(form.register)0, #"
                        + referenceFloatText(bits: expandedBits, kind: form.kind)
                    #expect(simdfpText(of: encoding) == expected, "imm8 \(imm8) ftype \(form.ftype)")
                }
            }
        }

        @Test func halfPrecisionPatternSpaceIsExhaustivelyIdentical() {
            for pattern in 1 ... 0xFFFF {
                let bits = UInt64(pattern)
                let expected = "fmov #" + referenceFloatText(bits: bits, kind: .half)
                #expect(fmovText(bits: bits, kind: .half) == expected, "half pattern \(pattern)")
            }
        }

        @Test func doubleSpecialValuesMatchReference() {
            let specials: [UInt64] = [
                0x8000_0000_0000_0000, // -0.0
                0x7FF0_0000_0000_0000, // +inf
                0xFFF0_0000_0000_0000, // -inf
                0x7FF8_0000_0000_0000, // quiet nan
                0xFFF8_0000_0000_0000, // negative quiet nan
                0x7FF0_0000_0000_0001, // signaling nan payload
                0x0000_0000_0000_0001, // min subnormal
                0x000F_FFFF_FFFF_FFFF, // max subnormal
                0x0010_0000_0000_0000, // min normal
                0x7FEF_FFFF_FFFF_FFFF, // max finite (309 integer digits)
                0.001953125.bitPattern, // tie at digit 9, rounds down to even
                0.005859375.bitPattern, // tie at digit 9, rounds up to even
                1.5.bitPattern,
                (-13.0).bitPattern,
                0.1.bitPattern,
                1e-9.bitPattern,
                (-1e-12).bitPattern, // rounds to -0.00000000
                1e9.bitPattern,
                123_456.123456785.bitPattern,
            ]
            for bits in specials {
                let expected = "fmov #" + referenceFloatText(bits: bits, kind: .double)
                #expect(fmovText(bits: bits, kind: .double) == expected, "double bits 0x\(String(bits, radix: 16))")
            }
        }

        @Test func doubleRandomSweepMatchesReference() {
            var generator = SplitMix64(state: 0xA5A5_5A5A_DEAD_BEEF)
            for _ in 0 ..< 20000 {
                let bits = generator.next()
                if bits == 0 { continue }
                let expected = "fmov #" + referenceFloatText(bits: bits, kind: .double)
                #expect(fmovText(bits: bits, kind: .double) == expected, "double bits 0x\(String(bits, radix: 16))")
            }
            // Bias a sweep toward small exponents (fraction-heavy renderings).
            for _ in 0 ..< 20000 {
                let bits = generator.next() & 0x403F_FFFF_FFFF_FFFF
                if bits == 0 { continue }
                let expected = "fmov #" + referenceFloatText(bits: bits, kind: .double)
                #expect(fmovText(bits: bits, kind: .double) == expected, "double bits 0x\(String(bits, radix: 16))")
            }
        }

        @Test func singleSpecialAndRandomSweepMatchesReference() {
            var patterns: [UInt32] = [
                0x8000_0000, // -0.0
                0x7F80_0000, // +inf
                0xFF80_0000, // -inf
                0x7FC0_0000, // quiet nan
                0xFFC0_0000, // negative quiet nan
                0x0000_0001, // min subnormal
                0x007F_FFFF, // max subnormal
                0x0080_0000, // min normal
                0x7F7F_FFFF, // max finite
                Float(1.5).bitPattern,
                Float(-13.0).bitPattern,
                Float(0.1).bitPattern,
            ]
            var generator = SplitMix64(state: 0x0123_4567_89AB_CDEF)
            for _ in 0 ..< 20000 {
                patterns.append(UInt32(truncatingIfNeeded: generator.next()))
            }
            for pattern in patterns where pattern != 0 {
                let bits = UInt64(pattern)
                let expected = "fmov #" + referenceFloatText(bits: bits, kind: .single)
                #expect(fmovText(bits: bits, kind: .single) == expected, "single bits 0x\(String(pattern, radix: 16))")
            }
        }

        @Test func storedBitsAboveKindWidthAreTruncatedIdentically() {
            // The canonicalizer truncates stored bits to the kind's width;
            // the reference computation mirrors it, pinning the behavior.
            let cases: [(bits: UInt64, kind: FloatImmediateKind)] = [
                (0xFFFF_FFFF_0000_3C00, .half),
                (0xDEAD_BEEF_3FC0_0000, .single),
            ]
            for testCase in cases {
                let expected = "fmov #" + referenceFloatText(bits: testCase.bits, kind: testCase.kind)
                #expect(fmovText(bits: testCase.bits, kind: testCase.kind) == expected)
            }
        }

        @Test func zeroBitsKeepTheCompareWithZeroSpelling() {
            // bits == 0 is the FCMP/FCMPE compare-with-zero path, deliberately
            // rendered `#0.0` (not `#0.00000000`) — preserved, not replaced.
            #expect(fmovText(bits: 0, kind: .half) == "fmov #0.0")
            #expect(fmovText(bits: 0, kind: .single) == "fmov #0.0")
            #expect(fmovText(bits: 0, kind: .double) == "fmov #0.0")
        }
    }
#endif
