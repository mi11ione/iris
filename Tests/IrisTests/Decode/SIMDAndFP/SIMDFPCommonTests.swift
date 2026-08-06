// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates the shared SIMD/FP helpers.
@Suite("SIMD/FP / VectorArrangement extensions")
struct VectorArrangementExtensionTests {
    @Test func b8ElementSizeIsByte() {
        #expect(VectorArrangement.b8.elementSize == .b)
        #expect(VectorArrangement.b16.elementSize == .b)
    }

    @Test func h4ElementSizeIsHalfword() {
        #expect(VectorArrangement.h4.elementSize == .h)
        #expect(VectorArrangement.h8.elementSize == .h)
    }

    @Test func s2ElementSizeIsWord() {
        #expect(VectorArrangement.s2.elementSize == .s)
        #expect(VectorArrangement.s4.elementSize == .s)
    }

    @Test func d1ElementSizeIsDoubleword() {
        #expect(VectorArrangement.d1.elementSize == .d)
        #expect(VectorArrangement.d2.elementSize == .d)
    }

    @Test func laneCountMatchesArrangement() {
        #expect(VectorArrangement.b8.laneCount == 8)
        #expect(VectorArrangement.b16.laneCount == 16)
        #expect(VectorArrangement.h4.laneCount == 4)
        #expect(VectorArrangement.h8.laneCount == 8)
        #expect(VectorArrangement.s2.laneCount == 2)
        #expect(VectorArrangement.s4.laneCount == 4)
        #expect(VectorArrangement.d1.laneCount == 1)
        #expect(VectorArrangement.d2.laneCount == 2)
    }

    @Test func byteWidthIs8For64BitArrangements() {
        #expect(VectorArrangement.b8.byteWidth == 8)
        #expect(VectorArrangement.h4.byteWidth == 8)
        #expect(VectorArrangement.s2.byteWidth == 8)
        #expect(VectorArrangement.d1.byteWidth == 8)
    }

    @Test func byteWidthIs16For128BitArrangements() {
        #expect(VectorArrangement.b16.byteWidth == 16)
        #expect(VectorArrangement.h8.byteWidth == 16)
        #expect(VectorArrangement.s4.byteWidth == 16)
        #expect(VectorArrangement.d2.byteWidth == 16)
    }

    @Test func isFullVectorTrueForQ1Forms() {
        #expect(VectorArrangement.b16.isFullVector)
        #expect(VectorArrangement.h8.isFullVector)
        #expect(VectorArrangement.s4.isFullVector)
        #expect(VectorArrangement.d2.isFullVector)
    }

    @Test func isFullVectorFalseForQ0Forms() {
        #expect(!VectorArrangement.b8.isFullVector)
        #expect(!VectorArrangement.h4.isFullVector)
        #expect(!VectorArrangement.s2.isFullVector)
        #expect(!VectorArrangement.d1.isFullVector)
    }
}

/// Validates ScalarSize.byteWidth — 1, 2, 4, 8, 16 across B/H/S/D/Q.
@Suite("SIMD/FP / ScalarSize.byteWidth")
struct ScalarSizeByteWidthTests {
    @Test func byteScalarHasWidth1() {
        #expect(ScalarSize.b.byteWidth == 1)
    }

    @Test func halfScalarHasWidth2() {
        #expect(ScalarSize.h.byteWidth == 2)
    }

    @Test func singleScalarHasWidth4() {
        #expect(ScalarSize.s.byteWidth == 4)
    }

    @Test func doubleScalarHasWidth8() {
        #expect(ScalarSize.d.byteWidth == 8)
    }

    @Test func quadScalarHasWidth16() {
        #expect(ScalarSize.q.byteWidth == 16)
    }
}

/// Validates canonicalElementArrangement(for:) — the 128-bit arrangement that
/// backs an element-subscript operand
@Suite("SIMD/FP / canonicalElementArrangement(for:)")
struct CanonicalElementArrangementTests {
    @Test func byteElementMapsToB16() {
        #expect(canonicalElementArrangement(for: .b) == .b16)
    }

    @Test func halfElementMapsToH8() {
        #expect(canonicalElementArrangement(for: .h) == .h8)
    }

    @Test func singleElementMapsToS4() {
        #expect(canonicalElementArrangement(for: .s) == .s4)
    }

    @Test func doubleElementMapsToD2() {
        #expect(canonicalElementArrangement(for: .d) == .d2)
    }

    @Test func quadElementHasNoVectorArrangement() {
        #expect(canonicalElementArrangement(for: .q) == nil)
    }
}

/// Validates `isSIMDAndFPEncoding(_:)`, the corpus pre-filter.
@Suite("SIMD/FP / isSIMDAndFPEncoding")
struct IsSIMDAndFPEncodingTests {
    private func encoding(op0: UInt8) -> UInt32 {
        UInt32(op0 & 0xF) << 25
    }

    @Test func op0Of0x7Accepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0x7)))
    }

    @Test func op0Of0xFAccepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0xF)))
    }

    @Test func op0Of0x6Accepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0x6)))
    }

    @Test func op0Of0xEAccepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0xE)))
    }

    @Test func op0Of0x4RejectedBecauseVIsZero() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x4)))
    }

    @Test func op0Of0xCRejectedBecauseVIsZero() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xC)))
    }

    @Test func op0Of0x0Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x0)))
    }

    @Test func op0Of0x1Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x1)))
    }

    @Test func op0Of0x2Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x2)))
    }

    @Test func op0Of0x3Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x3)))
    }

    @Test func op0Of0x5Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x5)))
    }

    @Test func op0Of0x8Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x8)))
    }

    @Test func op0Of0x9Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x9)))
    }

    @Test func op0Of0xAOrXBRejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xA)))
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xB)))
    }

    @Test func op0Of0xDRejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xD)))
    }
}

/// Validates the VFPExpandImm expansion through the decoded `.floatImmediate`
/// operand of FMOV.
@Suite("SIMD/FP / VFPExpandImm via FMOV-immediate decode")
struct VFPExpandImmTests {
    private func expandedBits(imm8: UInt32, ftype: UInt32) -> UInt64? {
        let word = 0x1E20_1000 | (ftype << 22) | (imm8 << 13)
        guard case let .floatImmediate(bits, _) = decode(word).operands.last else { return nil }
        return bits
    }

    @Test func unallocatedFtypeHasNoImmediateOperand() {
        #expect(expandedBits(imm8: 0x70, ftype: 0b10) == nil)
    }

    @Test func singlePrecisionOnePointZero() {
        let bits = expandedBits(imm8: 0x70, ftype: 0b00)
        #expect(bits == 0x3F80_0000, "expected 1.0 ⇒ 0x3F800000, got \(String(bits ?? 0, radix: 16))")
    }

    @Test func singlePrecisionNegativeOnePointZero() {
        #expect(expandedBits(imm8: 0xF0, ftype: 0b00) == 0xBF80_0000)
    }

    @Test func singlePrecisionTwoPointZero() {
        #expect(expandedBits(imm8: 0x00, ftype: 0b00) == 0x4000_0000)
    }

    @Test func doublePrecisionOnePointZero() {
        #expect(expandedBits(imm8: 0x70, ftype: 0b01) == 0x3FF0_0000_0000_0000)
    }

    @Test func halfPrecisionOnePointZero() {
        #expect(expandedBits(imm8: 0x70, ftype: 0b11) == 0x3C00)
    }

    @Test func halfPrecisionSignBitOnly() {
        #expect(expandedBits(imm8: 0x80, ftype: 0b11) == 0xC000)
    }

    @Test func singlePrecisionAllOnesImm() {
        #expect(expandedBits(imm8: 0xFF, ftype: 0b00) == 0xBFF8_0000)
    }
}

/// Validates `decodeAdvSIMDModifiedImmediate`, returning the 64-bit replicated
/// value and the kind distinguishing integer from FP forms.
@Suite("SIMD/FP / decodeAdvSIMDModifiedImmediate")
struct DecodeAdvSIMDModifiedImmediateTests {
    @Test func cmode0000Op0IntegerByteShiftZero() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0000, op: 0, abcdefgh: 0xAB,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_00AB_0000_00AB)
    }

    @Test func cmode0010IntegerByteShiftEight() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0010, op: 0, abcdefgh: 0xCD,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_CD00_0000_CD00)
    }

    @Test func cmode0001IsOrrIntegerForm() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0001, op: 0, abcdefgh: 0x10,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_0010_0000_0010)
    }

    @Test func cmode1000IsSixteenBitMovi() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1000, op: 0, abcdefgh: 0x12,
        )
        #expect(kind == .integer)
        #expect(value == 0x0012_0012_0012_0012)
    }

    @Test func cmode1010IsSixteenBitMoviShift8() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1010, op: 0, abcdefgh: 0x34,
        )
        #expect(kind == .integer)
        #expect(value == 0x3400_3400_3400_3400)
    }

    @Test func cmode1001IsSixteenBitOrr() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1001, op: 0, abcdefgh: 0x12,
        )
        #expect(kind == .integer)
        #expect(value == 0x0012_0012_0012_0012)
    }

    @Test func cmode1100IsMoviMslShift8() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1100, op: 0, abcdefgh: 0x05,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_05FF_0000_05FF)
    }

    @Test func cmode1101IsMoviMslShift16() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1101, op: 0, abcdefgh: 0x07,
        )
        #expect(kind == .integer)
        #expect(value == 0x0007_FFFF_0007_FFFF)
    }

    @Test func cmode1110Op0IsEightBitReplicatedByte() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1110, op: 0, abcdefgh: 0xA5,
        )
        #expect(kind == .integer)
        #expect(value == 0xA5A5_A5A5_A5A5_A5A5)
    }

    @Test func cmode1110Op1IsSixtyFourBitBitFanout() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1110, op: 1, abcdefgh: 0b1010_0101,
        )
        #expect(kind == .integer)
        #expect(value == 0xFF00_FF00_00FF_00FF)
    }

    @Test func cmode1111Op0IsFMovSingle() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1111, op: 0, abcdefgh: 0x70,
        )
        #expect(kind == .floatSingle)
        #expect(value == 0x3F80_0000_3F80_0000)
    }

    @Test func cmode1111Op1IsFMovDouble() {
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1111, op: 1, abcdefgh: 0x70,
        )
        #expect(kind == .floatDouble)
        #expect(value == 0x3FF0_0000_0000_0000)
    }
}

/// Validates `AdvSIMDImmediateKind`, the discriminator telling integer-
/// replicated from FP immediates.
@Suite("SIMD/FP / AdvSIMDImmediateKind cases")
struct AdvSIMDImmediateKindTests {
    @Test func integerDistinctFromFloats() {
        #expect(AdvSIMDImmediateKind.integer != .floatHalf)
        #expect(AdvSIMDImmediateKind.integer != .floatSingle)
        #expect(AdvSIMDImmediateKind.integer != .floatDouble)
    }

    @Test func threeFloatKindsDistinct() {
        #expect(AdvSIMDImmediateKind.floatHalf != .floatSingle)
        #expect(AdvSIMDImmediateKind.floatSingle != .floatDouble)
        #expect(AdvSIMDImmediateKind.floatHalf != .floatDouble)
    }

    @Test func kindsAreHashable() {
        var set: Set<AdvSIMDImmediateKind> = []
        set.insert(.integer)
        set.insert(.floatSingle)
        set.insert(.floatSingle)
        #expect(set.count == 2)
    }

    @Test func quadAndTwoHalfArrangementsReportTheirShape() {
        #expect(VectorArrangement.q1.elementSize == .q)
        #expect(VectorArrangement.q1.laneCount == 1)
        #expect(VectorArrangement.h2.elementSize == .h)
        #expect(VectorArrangement.h2.laneCount == 2)
    }
}
