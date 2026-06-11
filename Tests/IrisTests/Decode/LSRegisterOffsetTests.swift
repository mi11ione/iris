// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L11 register-offset class — `[Rn, Rm, ext]`
/// addressing. Checks the option → extend-kind map, the S-bit shift
/// display rule (0xFF sentinel for "no #amount", collapse for LSL), the
/// Rm width per extend kind, and the reserved-option guard.
@Suite("L/S register-offset decode")
struct LSRegisterOffsetTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func uxtwExtendWithoutShiftUsesTheSentinel() {
        // 0x38204800 = strb w0, [x0, w0, uxtw] — S=0 → shift sentinel 0xFF.
        let d = decode(0x3820_4800)
        #expect(d.mnemonic == .strb)
        #expect(d.memoryAccess == .store)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .uxtw, shift: 0xFF)))
        // Store reads Rn + Rm + Rt.
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func lslOptionWithSZeroCollapsesToBareRegister() {
        // 0x38206800 = strb w0, [x0, x0] — option=011 (LSL), S=0.
        let d = decode(0x3820_6800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0))))
    }

    @Test func lslOptionWithSOneKeepsLslKeyword() {
        // 0x38207800 = strb w0, [x0, x0, lsl #0] — option=011, S=1.
        let d = decode(0x3820_7800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .lsl)))
    }

    @Test func sxtwUsesA32BitIndexRegister() {
        // 0x3820c800 = strb w0, [x0, w0, sxtw] — option=110.
        let d = decode(0x3820_C800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .sxtw, shift: 0xFF)))
    }

    @Test func sxtxUsesA64BitIndexAndDisplaysAmount() {
        // 0x3820f800 = strb w0, [x0, x0, sxtx #0] — option=111, S=1.
        let d = decode(0x3820_F800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .sxtx)))
    }

    @Test func shiftAmountTracksTheSizeFieldWhenSIsSet() {
        // 0xf8207800 = str x0, [x0, x0, lsl #3] — size=11 → shift 3.
        let d = decode(0xF820_7800)
        #expect(d.mnemonic == .str)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .lsl, shift: 3)))
    }

    @Test func wordLoadShiftAmountIsTwo() {
        // 0xb8605800 = ldr w0, [x0, w0, uxtw #2] — size=10 → shift 2.
        let d = decode(0xB860_5800)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .uxtw, shift: 2)))
    }

    @Test func prfmRegisterOffsetCarriesPrefetchOperand() {
        // 0xf8a04800 = prfm pldl1keep, [x0, w0, uxtw].
        let d = decode(0xF8A0_4800)
        #expect(d.mnemonic == .prfm)
        #expect(d.memoryAccess == .prefetch)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedExtendOptionReturnsUndefined() {
        // 0x38200800 — option=000 is reserved (only 010/011/110/111 valid).
        let d = decode(0x3820_0800)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveBaseIndexAndDestination() {
        // 0xb8635841 = ldr w1, [x2, w3, uxtw #2] — distinct Rt / Rn / Rm
        // so the base, the index and the destination are separable bits.
        let d = decode(0xB863_5841)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(2)), index: .w(3), extend: .uxtw, shift: 2)),
        ])
        // Load reads base x2 + index w3; writes destination w1.
        #expect(d.semanticReads.mask == (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == UInt64(1) << 1)
    }
}
