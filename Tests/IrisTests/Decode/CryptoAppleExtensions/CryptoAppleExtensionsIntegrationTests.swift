// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the crypto/Apple-extensions integration points with the
/// other family decoders and canonicalizers: crypto delegation from
/// `SIMDAndFPDecoder`, PAC / MTE-DPR delegation from
/// `DataProcessingRegisterDecoder`, MTE-DPI delegation from
/// `DataProcessingImmediateDecoder`, MTE-L/S delegation from
/// `LoadsAndStoresDecoder` via the bit-21 discriminator in
/// `case 0b011001`, and the family-range guard that routes the family's
/// mnemonics through `CryptoAppleExtensionsCanonicalizer` from every
/// other per-family canonicalizer.
@Suite("CryptoAppleExtensions / cross-family integration points")
struct CryptoAppleExtensionsIntegrationTests {
    @Test func simdAndFPDecoderDelegatesAESEToCrypto() {
        // 0x4E284820 = aese v0.16b, v1.16b — routes through
        // SIMDAndFPDecoder's crypto delegation (top of decode).
        let d = decode(0x4E28_4820, at: 0)
        #expect(d.mnemonic == .aese)
        #expect(d.category == .crypto)
    }

    @Test func simdAndFPDecoderFallsThroughForNonCryptoSIMD() {
        // Non-crypto SIMD encodings must not be intercepted by the
        // crypto delegation; they continue through the standard SIMD
        // dispatch with their original SIMD/FP mnemonic and category.
        // MOVI v0.4s, #4 = 0x4F00_0480 (vector modified-immediate).
        let d = decode(0x4F00_0480, at: 0)
        #expect(d.mnemonic == .movi)
        #expect(d.category == .simdAndFP)
    }

    @Test func simdFPCanonicalizerRoutesCryptoMnemonicsToCryptoCanonicalizer() {
        // SIMDAndFPDecoder produces an aese record; SIMDFPCanonicalizer's
        // family-range guard at the top of format() routes it to
        // CryptoAppleExtensionsCanonicalizer.
        let d = decode(0x4E28_4820, at: 0)
        #expect(d.text == "aese v0.16b, v1.16b")
    }

    @Test func dprDecoderDelegatesPACIAToPAC() {
        // PACIA x0, x1 = 0xDAC10020 — routes through DPR's top-of-method
        // PAC delegation (PointerAuthenticationDecode.decodeOneSource).
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(d.category == .pointerAuthentication)
    }

    @Test func dprDecoderDelegatesPACGAToPAC() {
        // PACGA x0, x1, x2 = 0x9AC23020 — routes through DPR's top-of-method
        // delegation to PointerAuthenticationDecode.decodeTwoSource.
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.mnemonic == .pacga)
        #expect(d.category == .pointerAuthentication)
    }

    @Test func dprDecoderDelegatesSUBPSToMTE() {
        // SUBPS has S=1 — the outer DPR's S=0 check would normally reject
        // this. The top-of-method MTE delegation runs BEFORE the S check,
        // so SUBPS reaches MemoryTaggingDecode.decodeDPR.
        let d = decode(0xBAC2_0020, at: 0)
        #expect(d.mnemonic == .subps)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func dprDecoderFallsThroughForNonDelegatedEncoding() {
        // RBIT x0, x1 = 0xDAC00020 — within DPR but not a delegated
        // mnemonic. The top-of-method delegation returns nil for each
        // (PAC / PACGA / MTE-DPR), and the standard DPR dispatch runs.
        let d = decode(0xDAC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
    }

    @Test func dprCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.text == "pacia x0, x1")
    }

    @Test func dpiDecoderDelegatesADDGToMTE() {
        // ADDG x0, x0, #0, #0 = 0x91800000 — routes through DPI's
        // op1=0b011 branch → MTE-DPI.
        let d = decode(0x9180_0000, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.category == .memoryTagging)
    }

    @Test func dpiDecoderEmitsUndefinedWhenMTEDPIRejects() {
        // Encoding with op1=011 but bit 22 = 1 (reserved) — DPI routes
        // to MTE-DPI which rejects via prefix mask, then DPI falls through
        // to UNDEFINED.
        let d = decode(0x91C3_0000, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func dpiCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0x9180_0000, at: 0)
        #expect(d.text == "addg x0, x0, #0, #0")
    }

    @Test func lsDecoderDelegatesMTEStoreToMTELS() {
        // STG x0, [x0] = 0xD9200800 — routes through L/S's
        // case 0b011001 → bit 21 = 1 → MemoryTaggingDecode.decodeLS.
        let d = decode(0xD920_0800, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.category == .memoryTagging)
    }

    @Test func lsDecoderFallsBackToLRCPC2WhenBit21Zero() {
        // LRCPC2 STLUR Wt, [Xn] = 0x9900_0000 (size=10 word, opc=00 store).
        // bits[29:24] = 0b011001, bit 21 = 0 → falls through to
        // LRCPC2Decode unchanged. Must produce the L/S mnemonic with
        // .release ordering, NOT delegated to MTE-LS.
        let d = decode(0x9900_0000, at: 0)
        #expect(d.mnemonic == .stlur)
        #expect(d.category == .loadsAndStores)
        #expect(d.text == "stlur w0, [x0]")
    }

    @Test func lsDecoderEmitsUndefinedWhenMTELSRejects() {
        // bit 21 = 1 but row prefix doesn't match (top byte not 0xD9):
        // L/S routes via case 0b011001 → MTE-LS rejects → UNDEFINED.
        let d = decode(0x9920_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func lsCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0xD920_0800, at: 0)
        #expect(d.text == "stg x0, [x0]")
    }
}
