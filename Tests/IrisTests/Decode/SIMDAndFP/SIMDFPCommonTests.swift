// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates shared SIMD/FP helpers exposed by SIMDFPCommon.swift —
/// the public extensions on VectorArrangement and ScalarSize, the
/// canonicalElementArrangement(for:) factory, and the
/// isSIMDAndFPEncoding(_:) tier-membership predicate.
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

/// Validates canonicalElementArrangement(for:) — the 128-bit arrangement
/// that backs an element-subscript operand
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

/// Validates isSIMDAndFPEncoding(_:) — the corpus pre-filter for the
/// validation sweep. Returns true for top-level op0 ∈ {0x7, 0xF} (the FP
/// scalar / AdvSIMD arithmetic tier) and for op0 ∈ {0x4, 0x6, 0xC, 0xE}
/// with V=1 (the V=1 load/store tier delegated from integer L/S). Note
/// that V is bit[26] which is bit-1 of op0 itself, so op0=0x4 / 0xC
/// always have V=0 and op0=0x6 / 0xE always have V=1.
@Suite("SIMD/FP / isSIMDAndFPEncoding")
struct IsSIMDAndFPEncodingTests {
    /// Encoding with bits[28:25] = `op0` and bit[26] = `V` (note that
    /// the predicate reads V from bit 26 independently of op0). All
    /// other bits zero.
    private func encoding(op0: UInt8) -> UInt32 {
        UInt32(op0 & 0xF) << 25
    }

    @Test func op0Of0x7Accepted() {
        // op0=0x7 = 0111 ⇒ bit 26 = 1 inherently. Predicate returns true
        // via the op0-only early return.
        #expect(isSIMDAndFPEncoding(encoding(op0: 0x7)))
    }

    @Test func op0Of0xFAccepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0xF)))
    }

    @Test func op0Of0x6Accepted() {
        // op0=0x6 = 0110 ⇒ V=1 ⇒ accepted as the V=1-LS tier.
        #expect(isSIMDAndFPEncoding(encoding(op0: 0x6)))
    }

    @Test func op0Of0xEAccepted() {
        #expect(isSIMDAndFPEncoding(encoding(op0: 0xE)))
    }

    @Test func op0Of0x4RejectedBecauseVIsZero() {
        // op0=0x4 = 0100 ⇒ bit 26 = 0 ⇒ V=0 ⇒ rejected (this is
        // integer L/S territory).
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x4)))
    }

    @Test func op0Of0xCRejectedBecauseVIsZero() {
        // op0=0xC = 1100 ⇒ V=0 ⇒ rejected.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xC)))
    }

    @Test func op0Of0x0Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x0)))
    }

    @Test func op0Of0x1Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x1)))
    }

    @Test func op0Of0x2Rejected() {
        // bit 26 = 1 here but op0 not in the V=1 set.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x2)))
    }

    @Test func op0Of0x3Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x3)))
    }

    @Test func op0Of0x5Rejected() {
        // DPR territory.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x5)))
    }

    @Test func op0Of0x8Rejected() {
        // DPI territory.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x8)))
    }

    @Test func op0Of0x9Rejected() {
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0x9)))
    }

    @Test func op0Of0xAOrXBRejected() {
        // BES territory.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xA)))
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xB)))
    }

    @Test func op0Of0xDRejected() {
        // DPR top half.
        #expect(!isSIMDAndFPEncoding(encoding(op0: 0xD)))
    }
}

/// Validates the VFPExpandImm IEEE 754 mantissa/exponent expansion
/// shared by FMOV-imm and vector FMOV-imm immediates, through the
/// decoded `.floatImmediate(bits:kind:)` operand of FMOV (scalar,
/// immediate) words. Covers half/single/double widths plus boundary
/// imm8 values (all zeros, all ones, sign bit only, exponent edge).
@Suite("SIMD/FP / VFPExpandImm via FMOV-immediate decode")
struct VFPExpandImmTests {
    /// Decoded expansion bits for `FMOV <ftype>0, #imm8`.
    private func expandedBits(imm8: UInt32, ftype: UInt32) -> UInt64? {
        let word = 0x1E20_1000 | (ftype << 22) | (imm8 << 13)
        guard case let .floatImmediate(bits, _) = decode(word).operands.last else { return nil }
        return bits
    }

    @Test func singlePrecisionOnePointZero() {
        // FMOV S0, #1.0 — imm8 = 0b01110000 (0x70).
        // Per VFPExpandImm: a=0 (sign+), b=1 (notB=0), cde=110, efgh=0000.
        // exp = 0:11111:10 = 0b01111110 = 126; mantissa = 0 = 0x3F800000.
        let bits = expandedBits(imm8: 0x70, ftype: 0b00)
        #expect(bits == 0x3F80_0000, "expected 1.0 ⇒ 0x3F800000, got \(String(bits ?? 0, radix: 16))")
    }

    @Test func singlePrecisionNegativeOnePointZero() {
        // FMOV S0, #-1.0 — imm8 = 0b11110000 (0xF0).
        #expect(expandedBits(imm8: 0xF0, ftype: 0b00) == 0xBF80_0000)
    }

    @Test func singlePrecisionTwoPointZero() {
        // FMOV S0, #2.0 — imm8 = 0x00. a=0,b=0,notB=1,cde=000,efgh=0000.
        // exp = 1:00000:00 = 0b10000000 = 128; mantissa = 0. ⇒ 0x40000000.
        #expect(expandedBits(imm8: 0x00, ftype: 0b00) == 0x4000_0000)
    }

    @Test func doublePrecisionOnePointZero() {
        #expect(expandedBits(imm8: 0x70, ftype: 0b01) == 0x3FF0_0000_0000_0000)
    }

    @Test func halfPrecisionOnePointZero() {
        // imm8 = 0x70: sign=0, b=1, cde=7 (bits[6:4]=111), efgh=0.
        // notB = 0; exp = (0<<4) | (0b11<<2) | 7 = 15; mantissa = 0.
        // Half-precision 1.0 = sign 0, exp 15 (bias), mantissa 0
        // ⇒ raw bits 0x3C00 = 15360.
        #expect(expandedBits(imm8: 0x70, ftype: 0b11) == 0x3C00)
    }

    @Test func halfPrecisionSignBitOnly() {
        // imm8 = 0x80 — sign=1, all other bits zero.
        // sign = 1, b=0 ⇒ notB=1, cde=0, efgh=0.
        // exp = (1<<4) | (0<<2) | 0 = 16. mant = 0.
        // result = (1<<15) | (16<<10) | 0 = 0x8000 | 0x4000 = 0xC000.
        #expect(expandedBits(imm8: 0x80, ftype: 0b11) == 0xC000)
    }

    @Test func singlePrecisionAllOnesImm() {
        // imm8 = 0xFF: sign=1, b=1, cde=111, efgh=1111.
        // exp = (notB << 7) | (0b11111 << 2) | 0b111 = 0x7F.
        // mantissa = (0b1111 << 19) = 0x780000.
        // result = (1 << 31) | (0x7F << 23) | 0x780000 = 0xBFF80000.
        #expect(expandedBits(imm8: 0xFF, ftype: 0b00) == 0xBFF8_0000)
    }
}

/// Validates decodeAdvSIMDModifiedImmediate — ARM ARM AdvSIMDExpandImm
/// Returns the 64-bit replicated value and a kind
/// distinguishing integer-replicated from FP-immediate forms.
@Suite("SIMD/FP / decodeAdvSIMDModifiedImmediate")
struct DecodeAdvSIMDModifiedImmediateTests {
    @Test func cmode0000Op0IntegerByteShiftZero() {
        // cmode=0000 op=0: 32-bit MOVI, no shift; lane = byte; replicated.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0000, op: 0, abcdefgh: 0xAB,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_00AB_0000_00AB)
    }

    @Test func cmode0010IntegerByteShiftEight() {
        // cmode=0010 (cmode[3:1]=001) shift=8.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0010, op: 0, abcdefgh: 0xCD,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_CD00_0000_CD00)
    }

    @Test func cmode0001IsOrrIntegerForm() {
        // cmode=0001 op=0 — ORR-imm 32-bit. Still integer kind.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b0001, op: 0, abcdefgh: 0x10,
        )
        #expect(kind == .integer)
        #expect(value == 0x0000_0010_0000_0010)
    }

    @Test func cmode1000IsSixteenBitMovi() {
        // cmode=1000 op=0 — MOVI 16-bit, shift = cmode[1]*8 = 0.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1000, op: 0, abcdefgh: 0x12,
        )
        #expect(kind == .integer)
        // lane16 = 0x0012; lane32 = 0x0012_0012; replicated → 0x00120012_00120012.
        #expect(value == 0x0012_0012_0012_0012)
    }

    @Test func cmode1010IsSixteenBitMoviShift8() {
        // cmode=1010 op=0 — MOVI 16-bit, shift = cmode[1]*8 = 8.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1010, op: 0, abcdefgh: 0x34,
        )
        #expect(kind == .integer)
        // lane16 = 0x3400; lane32 = 0x3400_3400; rep → 0x34003400_34003400.
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
        // cmode=1100 op=0 — MOVI MSL; mslShift = 8 + 0*8 = 8;
        // onesBits = 0xFF (cmode[0]=0).
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1100, op: 0, abcdefgh: 0x05,
        )
        #expect(kind == .integer)
        // lane32 = (0x05 << 8) | 0xFF = 0x0000_05FF; replicated.
        #expect(value == 0x0000_05FF_0000_05FF)
    }

    @Test func cmode1101IsMoviMslShift16() {
        // cmode=1101 op=0 — MSL with cmode[0]=1 ⇒ mslShift=16; onesBits=0xFFFF.
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
        // cmode=1110 op=1 — MOVI 64-bit: each bit of imm8 becomes a byte
        // of all-1s or all-0s.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1110, op: 1, abcdefgh: 0b1010_0101,
        )
        #expect(kind == .integer)
        // bits: bit0=1 ⇒ byte0=0xFF; bit2=1 ⇒ byte2=0xFF;
        // bit5=1 ⇒ byte5=0xFF; bit7=1 ⇒ byte7=0xFF.
        // result LSB-first per byte (bit0=byte0=lowest):
        // byte0=FF byte1=00 byte2=FF byte3=00 byte4=00 byte5=FF byte6=00 byte7=FF
        // as UInt64 LE: 0xFF00FF000000FF00 with byte 7 = FF and byte 5 = FF
        // = 0xFF00_FF00_00FF_00FF
        #expect(value == 0xFF00_FF00_00FF_00FF)
    }

    @Test func cmode1111Op0IsFMovSingle() {
        // cmode=1111 op=0 — FMOV vector single. abcdefgh = 0x70 ⇒ 1.0.
        let (value, kind) = decodeAdvSIMDModifiedImmediate(
            cmode: 0b1111, op: 0, abcdefgh: 0x70,
        )
        #expect(kind == .floatSingle)
        // single 1.0 bits = 0x3F800000, replicated lower/upper:
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

/// Validates AdvSIMDImmediateKind — the discriminator returned by
/// decodeAdvSIMDModifiedImmediate to tell integer-replicated from FP
/// immediates.
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
        // .1q (PMULL destination) and .2h (FCVTN half-pair) shapes.
        #expect(VectorArrangement.q1.elementSize == .q)
        #expect(VectorArrangement.q1.laneCount == 1)
        #expect(VectorArrangement.h2.elementSize == .h)
        #expect(VectorArrangement.h2.laneCount == 2)
    }
}
