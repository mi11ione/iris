// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the family's integration points.
@Suite("CryptoAppleExtensions / cross-family integration points")
struct CryptoAppleExtensionsIntegrationTests {
    @Test func simdAndFPDecoderDelegatesAESEToCrypto() {
        let d = decode(0x4E28_4820, at: 0)
        #expect(d.mnemonic == .aese)
        #expect(d.category == .crypto)
    }

    @Test func simdAndFPDecoderFallsThroughForNonCryptoSIMD() {
        let d = decode(0x4F00_0480, at: 0)
        #expect(d.mnemonic == .movi)
        #expect(d.category == .simdAndFP)
    }

    @Test func simdFPCanonicalizerRoutesCryptoMnemonicsToCryptoCanonicalizer() {
        let d = decode(0x4E28_4820, at: 0)
        #expect(d.text == "aese v0.16b, v1.16b")
    }

    @Test func dprDecoderDelegatesPACIAToPAC() {
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.mnemonic == .pacia)
        #expect(d.category == .pointerAuthentication)
    }

    @Test func dprDecoderDelegatesPACGAToPAC() {
        let d = decode(0x9AC2_3020, at: 0)
        #expect(d.mnemonic == .pacga)
        #expect(d.category == .pointerAuthentication)
    }

    @Test func dprDecoderDelegatesSUBPSToMTE() {
        let d = decode(0xBAC2_0020, at: 0)
        #expect(d.mnemonic == .subps)
        #expect(d.category == .memoryTagging)
        #expect(d.flagEffect == .nzcv)
    }

    @Test func dprDecoderFallsThroughForNonDelegatedEncoding() {
        let d = decode(0xDAC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
    }

    @Test func dprCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0xDAC1_0020, at: 0)
        #expect(d.text == "pacia x0, x1")
    }

    @Test func dpiDecoderDelegatesADDGToMTE() {
        let d = decode(0x9180_0000, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.category == .memoryTagging)
    }

    @Test func dpiDecoderDecodesCSSCMinMaxWhereBit22IsSet() {
        let d = decode(0x91C3_0000, at: 0)
        #expect(d.mnemonic == .smax)
        #expect(d.category == .dataProcessingImmediate)
        #expect(d.text == "smax x0, x0, #-64")
    }

    @Test func dpiCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0x9180_0000, at: 0)
        #expect(d.text == "addg x0, x0, #0, #0")
    }

    @Test func lsDecoderDelegatesMTEStoreToMTELS() {
        let d = decode(0xD920_0800, at: 0)
        #expect(d.mnemonic == .stg)
        #expect(d.category == .memoryTagging)
    }

    @Test func lsDecoderFallsBackToLRCPC2WhenBit21Zero() {
        let d = decode(0x9900_0000, at: 0)
        #expect(d.mnemonic == .stlur)
        #expect(d.category == .loadsAndStores)
        #expect(d.text == "stlur w0, [x0]")
    }

    @Test func lsDecoderEmitsUndefinedWhenMTELSRejects() {
        let d = decode(0x9920_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func lsCanonicalizerRoutes27MnemonicsToCryptoCanonicalizer() {
        let d = decode(0xD920_0800, at: 0)
        #expect(d.text == "stg x0, [x0]")
    }
}
