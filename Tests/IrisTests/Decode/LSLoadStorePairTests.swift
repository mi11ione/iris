// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L6 load/store-pair class — LDP / STP /
/// LDPSW / STGP / LDNP / STNP across the no-allocate, signed-offset,
/// post-indexed and pre-indexed forms. Checks the indexing → writeback
/// map, the imm7 × scale displacement, and the pair read/write masks.
@Suite("L/S load/store-pair decode")
struct LSLoadStorePairTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func storeNoAllocatePairWordForm() {
        // 0x28000000 = stnp w0, w0, [x0].
        let d = decode(0x2800_0000)
        #expect(d.mnemonic == .stnp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func loadNoAllocatePairDoublewordForm() {
        // 0xa8400000 = ldnp x0, x0, [x0].
        let d = decode(0xA840_0000)
        #expect(d.mnemonic == .ldnp)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func signedOffsetPairWordForm() {
        // 0x29400000 = ldp w0, w0, [x0].
        let d = decode(0x2940_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.memoryAccess == .load)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)))))
        // Load reads the base, writes both result registers.
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func signedOffsetScalesImm7ByEightForDoublewordPair() {
        // 0xa9410000 = ldp x0, x0, [x0, #16] — imm7=2, ×8 → +16.
        let d = decode(0xA941_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 16)))
    }

    @Test func preIndexedPairWritesBackBase() {
        // 0xa9c00000 = ldp x0, x0, [x0, #0]!.
        let d = decode(0xA9C0_0000)
        #expect(d.mnemonic == .ldp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
        // Writeback adds the base register to the write set.
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func postIndexedPairStoreWritesBackBaseOnly() {
        // 0x28800000 = stp w0, w0, [x0], #0.
        let d = decode(0x2880_0000)
        #expect(d.mnemonic == .stp)
        #expect(d.operands[2] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
        // A store with writeback writes only the base register.
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldpswSignExtendsIntoXtPair() {
        // 0x68c00000 = ldpsw x0, x0, [x0], #0 — opc=01, L=1.
        let d = decode(0x68C0_0000)
        #expect(d.mnemonic == .ldpsw)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.memoryAccess == .load)
    }

    @Test func stgpDecodesAtOpcOne() {
        // 0x68800000 = stgp x0, x0, [x0], #0 — opc=01, L=0.
        let d = decode(0x6880_0000)
        #expect(d.mnemonic == .stgp)
        #expect(d.memoryAccess == .store)
    }

    @Test func opcElevenNoAllocateDecodesSttnp() {
        // opc=11 in the no-allocate pair shell is STTNP (temporal-pair store),
        // not reserved — llvm-mc decodes 0xe8000000 as `sttnp x0, x0, [x0]`.
        #expect(decode(0xE800_0000).mnemonic == .sttnp)
    }

    @Test func opcElevenSignedOffsetDecodesSttp() {
        // opc=11, L=0 at signed-offset indexing is the FEAT_LSUI
        // unprivileged 64-bit store pair.
        let d = decode(0xE900_0861)
        #expect(d.mnemonic == .sttp)
        #expect(d.memoryAccess == .store)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.text == "sttp x1, x2, [x3]")
    }

    @Test func ldpswNoAllocateFormReservedReturnsUndefined() {
        // 0x68000000 — opc=01 with indexing=00 has no no-allocate form.
        let d = decode(0x6800_0000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheLoadPairMasks() {
        // 0xa8c10861 = ldp x1, x2, [x3], #16 — distinct Rt / Rt2 / Rn so
        // the two result registers, the base and the writeback base are
        // separable bits, not a single collapsed register-0 bit.
        let d = decode(0xA8C1_0861)
        #expect(d.mnemonic == .ldp)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)),
            .memory(MemoryOperand(base: .register(.x(3)), displacement: 16, writeback: .postIndex)),
        ])
        // Load reads base x3; writes Rt x1 + Rt2 x2 + the writeback base x3.
        #expect(d.semanticReads.mask == UInt64(1) << 3)
        #expect(d.semanticWrites.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
    }

    @Test func distinctRegistersProveTheStorePairMasks() {
        // 0x28000861 = stnp w1, w2, [x3] — a store reads both data
        // registers plus the base and writes nothing; distinct registers
        // prove all three reads are present.
        let d = decode(0x2800_0861)
        #expect(d.mnemonic == .stnp)
        #expect(Array(d.operands) == [
            .register(.w(1)), .register(.w(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites == .empty)
    }
}
