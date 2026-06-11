// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD load/store multiple-structures (LD1/LD2/LD3/LD4 and
/// ST1-4 with selem × rpt layouts and no-offset/post-index variants).
@Suite("SIMD/FP / AdvSIMD LD/ST multi-structure")
struct AdvSIMDLoadStoreMultipleStructuresTests {
    @Test func st4MultiStructure_8B_NoOffset() {
        // ST4 {V0.8B-V3.8B}, [X0]: opcode=0000, L=0, size=00, Q=0.
        let d = decode(0x0C00_0000)
        #expect(d.mnemonic == .st4)
        #expect(d.memoryAccess == .store)
    }

    @Test func ld4MultiStructure_8B_NoOffset() {
        // LD4: L=1. byte 1 bit 6 = 1 ⇒ byte 1 = 0100_0000 = 0x40.
        let d = decode(0x0C40_0000)
        #expect(d.mnemonic == .ld4)
        #expect(d.memoryAccess == .load)
    }

    @Test func st1MultiStructureFourRegs() {
        // ST1 {V0.8B-V3.8B}: opcode=0010, selem=1, rpt=4.
        let d = decode(0x0C00_2000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st3MultiStructure() {
        // ST3: opcode=0100, selem=3, rpt=1.
        let d = decode(0x0C00_4000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st1MultiStructureThreeRegs() {
        // ST1 {V0-V2}: opcode=0110, selem=1, rpt=3.
        let d = decode(0x0C00_6000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiStructureOneReg() {
        // ST1 {V0}: opcode=0111, selem=1, rpt=1.
        let d = decode(0x0C00_7000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st2MultiStructure() {
        // ST2: opcode=1000, selem=2, rpt=1.
        let d = decode(0x0C00_8000)
        #expect(d.mnemonic == .st2)
    }

    @Test func st1MultiStructureTwoRegs() {
        // ST1 {V0-V1}: opcode=1010, selem=1, rpt=2.
        let d = decode(0x0C00_A000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st4PostIndexedImmediate() {
        // Post-indexed is bit 23 within the op0=6 multi-structure shell
        // (top byte 0x0C): ST4 {v0..v3}, [x0], #32 = 0x0C9F_0000.
        let d = decode(0x0C9F_0000)
        #expect(d.mnemonic == .st4)
    }

    @Test func st4PostIndexedRegister() {
        // Same as above but Rm = X3 (not 11111).
        let d = decode(0x0C83_0000) // Rm=00011 = 3.
        #expect(d.mnemonic == .st4)
    }

    @Test func ld2MultiStructure() {
        // LD2: L=1, opcode=1000. byte 1 = 0100_0000 = 0x40. byte 2 = 1000_0000 = 0x80.
        let d = decode(0x0C40_8000)
        #expect(d.mnemonic == .ld2)
    }

    @Test func ld3MultiStructure() {
        // LD3: L=1, opcode=0100. byte 1 = 0x40. byte 2 = 0100_0000 = 0x40.
        let d = decode(0x0C40_4000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        // opcode=0001 reserved.
        let d = decode(0x0C00_1000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func ld2WithReservedSize_1D_QZeroIsUndefined() {
        // LD2 with size=11 (D-element) Q=0 (.1D) reserved.
        let d = decode(0x0C40_8C00)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD load/store single-structure (LD1/LD2/LD3/LD4 with
/// element subscript) and replicate (LDxR) forms.
@Suite("SIMD/FP / AdvSIMD LD/ST single-structure")
struct AdvSIMDLoadStoreSingleStructureTests {
    @Test func st1SingleStructureByteElement() {
        // ST1 {V0.B}[0], [X0]: opcode=000, R=0, L=0, S=0, size=00.
        // bits[29:24] = 001101 ⇒ top byte = 0000_1101 = 0x0D.
        let d = decode(0x0D00_0000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1SingleStructureByteElement() {
        // LD1 {V0.B}[0]: L=1. byte 1 bit 6 = 1.
        let d = decode(0x0D40_0000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func st2SingleStructureByte() {
        // ST2: opcode=000, R=1, L=0. byte 1 bit 5 = 1 ⇒ byte 1 = 0010_0000 = 0x20.
        let d = decode(0x0D20_0000)
        #expect(d.mnemonic == .st2)
    }

    @Test func st3SingleStructureByte() {
        // ST3: opcode=001, R=0, L=0. opcode bits[15:13] = 001 ⇒ bit 15 = 0, bit 14 = 0, bit 13 = 1.
        // byte 2 = 0010_0000 = 0x20.
        let d = decode(0x0D00_2000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st4SingleStructureByte() {
        // ST4: opcode=001, R=1, L=0. byte 1 bit 5 = 1 ⇒ byte 1 = 0x20.
        let d = decode(0x0D20_2000)
        #expect(d.mnemonic == .st4)
    }

    @Test func st1SingleStructureHalfword() {
        // ST1 {V0.H}[0]: opcode=010 (H-element), size=00 (size[0]=0).
        // byte 2: opcode bits[15:13] = 010 ⇒ 0100_0000 = 0x40.
        let d = decode(0x0D00_4000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1SingleStructureWord() {
        // ST1 {V0.S}[0]: opcode=100 (S/D-element), size=00 (size[0]=0 ⇒ S).
        // byte 2: 1000_0000 = 0x80.
        let d = decode(0x0D00_8000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1SingleStructureDoubleword() {
        // ST1 {V0.D}[0]: opcode=100, size=01 (size[0]=1 ⇒ D), S=0.
        // byte 2 = 1000_0000 = 0x80. byte 3 with size=01: bits 11..10 = 01 ⇒ byte 3 bit 2 = 1.
        // For Rn=0 Rt=0: byte 3 = 0000_01_00 = 0x04.
        let d = decode(0x0D00_8400)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1ReplicateByteElement() {
        // LD1R: opcode=110, L=1, R=0.
        // bits[15:13] = 110 ⇒ byte 2 = 1100_0000 = 0xC0.
        // L=1 ⇒ byte 1 bit 6 = 1.
        let d = decode(0x0D40_C000)
        #expect(d.mnemonic == .ld1r)
    }

    @Test func ld2ReplicateByteElement() {
        // LD2R: opcode=110, L=1, R=1. byte 1 = 0110_0000 = 0x60.
        let d = decode(0x0D60_C000)
        #expect(d.mnemonic == .ld2r)
    }

    @Test func ld3ReplicateByteElement() {
        // LD3R: opcode=111, L=1, R=0.
        let d = decode(0x0D40_E000)
        #expect(d.mnemonic == .ld3r)
    }

    @Test func ld4ReplicateByteElement() {
        let d = decode(0x0D60_E000)
        #expect(d.mnemonic == .ld4r)
    }

    @Test func replicateStoreIsUndefined() {
        // ST1R / ST2R etc. don't exist (store + replicate doesn't make sense).
        // L=0 with opcode 110 should be reserved.
        let d = decode(0x0D00_C000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func singleStructurePostIndexed() {
        // Post-indexed is bit 23 within the op0=6 single-structure shell
        // (top byte 0x0D): ST1 V0.B[0], [X0], #1 with Rm=11111.
        let d = decode(0x0D9F_0000)
        #expect(d.mnemonic == .st1)
    }

    @Test func reservedSizeForHalfwordReturnsUndefined() {
        // ST1 V0.H[0] with size[0] = 1 (invalid for H) reserved.
        // byte 3 bit 2 = 1 ⇒ byte 3 = 0x04.
        let d = decode(0x0D00_4400)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSDForDoublewordSEqualsOneReturnsUndefined() {
        // ST1 V0.D[0] with S=1 (invalid for D) reserved.
        let d = decode(0x0D00_9400)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates Scalar SIMD LDR-literal (PC-relative loads).
@Suite("SIMD/FP / Scalar SIMD LDR-literal")
struct ScalarSIMDLoadLiteralTests {
    @Test func ldrSingleLiteral() {
        // LDR S0, label: opc=00, V=1. bits[29:24] = 011100 ⇒ top byte = 0x1C.
        let d = decode(0x1C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.count == 2)
        // First operand is scalar S0.
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s)),
        ))
    }

    @Test func ldrDoubleLiteral() {
        // LDR D0, label: opc=01. byte 0 = 0101_1100 = 0x5C.
        let d = decode(0x5C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d)),
        ))
    }

    @Test func ldrQuadLiteral() {
        // LDR Q0, label: opc=10. byte 0 = 1001_1100 = 0x9C.
        let d = decode(0x9C00_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .scalar(size: .q)),
        ))
    }

    @Test func reservedOpcReturnsUndefined() {
        // opc=11 reserved.
        let d = decode(0xDC00_0000)
        #expect(d.mnemonic == .undefined)
    }

    @Test func memoryOperandUsesPCBase() {
        let d = decode(0x1C00_0000)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .pc)))
    }

    @Test func memoryAccessIsLoad() {
        let d = decode(0x1C00_0000)
        #expect(d.memoryAccess == .load)
    }
}

/// Validates Scalar SIMD LDP/STP/LDNP/STNP (V=1) — pair loads/stores
/// with no-allocate, signed-offset, pre-/post-indexed variants.
@Suite("SIMD/FP / Scalar SIMD LDP / STP")
struct ScalarSIMDLoadStorePairTests {
    @Test func stnpSinglePair() {
        // STNP S0, S1, [X0]: opc=00, indexing=00, L=0.
        // bits[29:24]=101100, byte 0 = 0010_1100 = 0x2C.
        // Decoder fields: opc = bits[31:30], indexing = bits[24:23],
        // L = bit 22, imm7 = bits[21:15], Rt2 = bits[14:10], Rn = bits[9:5],
        // Rt = bits[4:0]. For imm7=0, Rt2=1, Rn=0, Rt=0:
        // byte 1 (indexing[0], L, imm7[6:1]) = 0x00; byte 2 = imm7[0] +
        // Rt2(00001) + Rn[4:3] = 0_00001_00 = 0x04; byte 3 = 0x00.
        let d = decode(0x2C00_0400)
        #expect(d.mnemonic == .stnp)
    }

    @Test func ldnpDoublePair() {
        // LDNP D0, D1, [X0]: opc=01, indexing=00, L=1.
        // byte 0 = 0110_1100 = 0x6C. byte 1: bit 22 = L = 1 ⇒ 0100_0000 = 0x40.
        let d = decode(0x6C40_0400)
        #expect(d.mnemonic == .ldnp)
    }

    @Test func stnpQuadPair() {
        // STNP Q0, Q1, [X0]: opc=10, indexing=00, L=0.
        // byte 0 = 1010_1100 = 0xAC.
        let d = decode(0xAC00_0400)
        #expect(d.mnemonic == .stnp)
    }

    @Test func ldpSinglePostIndexed() {
        // LDP S0, S1, [X0], #0: indexing=01, L=1. byte 1: bit 23 = 1, bit 22 = 1 ⇒ 1100_0000 = 0xC0.
        // bits[29:24] = 101101 ⇒ top byte = 0010_1101 = 0x2D.
        let d = decode(0x2CC0_0400)
        #expect(d.mnemonic == .ldp)
    }

    @Test func stpDoubleSignedOffset() {
        // STP D0, D1, [X0, #0]: opc=01, indexing=10 (signed offset ⇒
        // bit 24 = 1, bit 23 = 0), L=0 ⇒ bits[29:24] = 101101, top byte 0x6D.
        let d = decode(0x6D00_0400)
        #expect(d.mnemonic == .stp)
    }

    @Test func ldpQuadPreIndexed() {
        // LDP Q0, Q1, [X0, #0]!: opc=10, V=1, pre-index (indexing in
        // bits[24:23] = 11), L=1, imm7=0 ⇒ top byte 0xAD, byte 1 0xC0.
        let d = decode(0xADC0_0400)
        #expect(d.mnemonic == .ldp)
    }

    @Test func opcElevenNoAllocateDecodesSttnp() {
        // opc=11 in the SIMD no-allocate pair shell is STTNP (Q-reg temporal
        // store) — llvm-mc decodes 0xec000400 as `sttnp q0, q1, [x0]`.
        let d = decode(0xEC00_0400)
        #expect(d.mnemonic == .sttnp)
    }
}

/// Validates Scalar SIMD LDR/STR (unsigned offset, V=1).
@Suite("SIMD/FP / Scalar SIMD LDR / STR unsigned offset")
struct ScalarSIMDLoadStoreUnsignedOffsetTests {
    @Test func strSingleUnsignedOffset() {
        // STR S0, [X0]: size=10 (S), opc=00 (store), V=1.
        // size = bits[31:30] = 10 and bits[29:24] = 111101 ⇒
        // top byte = 1011_1101 = 0xBD.
        let d = decode(0xBD00_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrSingleUnsignedOffset() {
        // LDR S0, [X0]: opc=01. byte 1 bits 23..22 = 01 ⇒ byte 1 = 0100_0000 = 0x40.
        let d = decode(0xBD40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrDoubleUnsignedOffset() {
        // LDR D0: size=11. top byte = 1111_1101 = 0xFD.
        let d = decode(0xFD40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrByteUnsignedOffset() {
        // LDR B0: size=00. top byte = 0011_1101 = 0x3D.
        let d = decode(0x3D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrHalfUnsignedOffset() {
        // LDR H0: size=01. top byte = 0111_1101 = 0x7D.
        let d = decode(0x7D40_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strQuadUnsignedOffset() {
        // STR Q0: size=00, opc=10. byte 1: bits 23..22 = 10 ⇒ 1000_0000 = 0x80.
        let d = decode(0x3D80_0000)
        #expect(d.mnemonic == .str)
    }

    @Test func ldrQuadUnsignedOffset() {
        // LDR Q0: size=00, opc=11. byte 1: bits 23..22 = 11 ⇒ 1100_0000 = 0xC0.
        let d = decode(0x3DC0_0000)
        #expect(d.mnemonic == .ldr)
    }

    @Test func reservedSizeOpcCombinationReturnsUndefined() {
        // size=01 opc=10 (Q-form impossible at H-element) reserved.
        let d = decode(0x7D80_0000)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates Scalar SIMD LDR/STR/LDUR/STUR (indexed forms: register
/// offset, unscaled imm9, pre-/post-index).
@Suite("SIMD/FP / Scalar SIMD LDR / STR indexed")
struct ScalarSIMDLoadStoreIndexedTests {
    @Test func sturSingleZeroOffset() {
        // STUR S0, [X0, #0]: size=10, opc=00 (store), bits[11:10]=00 (unscaled).
        // top byte = 1011_1100 = 0xBC.
        let d = decode(0xBC00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldurSingleZeroOffset() {
        let d = decode(0xBC40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func ldurDoubleZeroOffset() {
        // size=11.
        let d = decode(0xFC40_0000)
        #expect(d.mnemonic == .ldur)
    }

    @Test func sturByte() {
        let d = decode(0x3C00_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func sturQuad() {
        // STR Q with bits[11:10]=00 unscaled offset → STUR Q0.
        // size=00 opc=10 ⇒ Q form, store. top byte = 0011_1100 = 0x3C.
        // byte 1 bits 23..22 = 10 ⇒ 1000_0000 = 0x80.
        let d = decode(0x3C80_0000)
        #expect(d.mnemonic == .stur)
    }

    @Test func ldrPostIndexed() {
        // LDR S0, [X0], #0: bits[11:10] = 01.
        // byte 2 bit 2 = 1 ⇒ byte 2 = 0000_0100 = 0x04.
        let d = decode(0xBC40_0400)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrPreIndexed() {
        // bits[11:10] = 11.
        let d = decode(0xBC40_0C00)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffset() {
        // bits[11:10] = 10 with option=011 (UXTX/LSL), S=0.
        // top byte = 0xBC (size=10, V=1). byte 1 = opc(01) + bit 21 = 1
        // (register-offset class) + Rm(00001) = 0110_0001 = 0x61.
        // byte 2 = option(011) + S(0) + 10 + Rn-high = 0110_1000 = 0x68.
        let d = decode(0xBC61_6800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithUXTW() {
        // option=010 (UXTW).
        let d = decode(0xBC61_4800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithSXTW() {
        // option=110.
        let d = decode(0xBC61_C800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithSXTX() {
        // option=111.
        let d = decode(0xBC61_E800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrRegisterOffsetWithReservedOptionReturnsUndefined() {
        // option=000 reserved.
        let d = decode(0xBC61_0800)
        #expect(d.mnemonic == .undefined)
    }

    @Test func ldrRegisterOffsetSBitSetScalesShift() {
        // S=1 ⇒ shift = log2(elementBytes) = 2 for S-form.
        let d = decode(0xBC61_7800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func reservedSizeOpcCombinationReturnsUndefined() {
        // size=01 opc=10 reserved.
        let d = decode(0x7C80_0000)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates the FEAT_LSUI unprivileged SIMD pair forms (LDTP/STTP/
/// LDTNP/STTNP of Q registers) across all four indexing variants.
@Suite("SIMD/FP / FEAT_LSUI SIMD pair forms")
struct ScalarSIMDLSUIPairTests {
    @Test func unprivilegedPairsDecodeEveryIndexingVariant() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, text: String)] = [
            (0xEC40_0440, .ldtnp, "ldtnp q0, q1, [x2]"),
            (0xEC00_0440, .sttnp, "sttnp q0, q1, [x2]"),
            (0xECC1_0440, .ldtp, "ldtp q0, q1, [x2], #32"),
            (0xEC81_0440, .sttp, "sttp q0, q1, [x2], #32"),
            (0xED41_0440, .ldtp, "ldtp q0, q1, [x2, #32]"),
            (0xED00_0440, .sttp, "sttp q0, q1, [x2]"),
            (0xEDC1_0440, .ldtp, "ldtp q0, q1, [x2, #32]!"),
            (0xED81_0440, .sttp, "sttp q0, q1, [x2, #32]!"),
        ]
        for row in rows {
            let d = decode(row.word)
            #expect(d.mnemonic == row.mnemonic, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
            #expect(d.text == row.text)
        }
    }
}
