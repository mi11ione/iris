// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the FP move immediates FDUP and FCPY.
@Suite("SVE floating-point / FDUP and FCPY move immediates")
struct SVEFPMoveDecodeTests {
    private static let fdupHalf: UInt32 = 0x2579_C000

    private static func fdup(_ imm8: UInt8, sz: UInt32) -> UInt32 {
        ((fdupHalf & ~(UInt32(0b11) << 22)) | (sz << 22)) | (UInt32(imm8) << 5)
    }

    @Test func fdupRendersTheEightDecimalExpandedImmediate() {
        #expect(text(Self.fdup(0x00, sz: 0b01)) == "fmov z0.h, #2.00000000")
        #expect(text(Self.fdup(0x08, sz: 0b01)) == "fmov z0.h, #3.00000000")
        #expect(text(Self.fdup(0x70, sz: 0b01)) == "fmov z0.h, #1.00000000")
        #expect(text(Self.fdup(0x80, sz: 0b01)) == "fmov z0.h, #-2.00000000")
        #expect(text(Self.fdup(0x00, sz: 0b10)) == "fmov z0.s, #2.00000000")
        #expect(text(Self.fdup(0x00, sz: 0b11)) == "fmov z0.d, #2.00000000")
    }

    @Test func fdupIsAFreshWriteWithNoPredicate() {
        let d = decode(Self.fdup(0x00, sz: 0b01))
        #expect(d.mnemonic == .fmov)
        #expect(canonicalIndices(d.semanticReads) == [], "fdup reads no register")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableReads == .empty, "fdup has no governing predicate")
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func fdupImmediateSelectsADistinctConstantForEveryImm8() {
        let sizes: [(UInt32, ScalarSize, String)] = [
            (0b01, .h, "h"), (0b10, .s, "s"), (0b11, .d, "d"),
        ]
        for (sz, element, suffix) in sizes {
            var rendered: Set<String> = []
            for imm8raw in 0 ... 255 {
                let imm8 = UInt8(imm8raw)
                let label = "imm8 0x\(String(imm8, radix: 16)) size \(suffix)"
                let d = decode(Self.fdup(imm8, sz: sz))
                #expect(d.mnemonic == .fmov, "\(label)")
                let operands = Array(d.operands)
                #expect(operands.count == 2, "\(label)")
                #expect(operands.first
                    == .scalableVector(ScalableVectorRef(registerIndex: 0, element: element)), "\(label)")
                let text = text(Self.fdup(imm8, sz: sz))
                #expect(text.hasPrefix("fmov z0.\(suffix), #"), "\(label)")
                #expect(text.contains("."), "the expanded immediate is always a decimal")
                rendered.insert(text)
            }
            #expect(rendered.count == 256,
                    "size \(suffix): imm8 must select 256 distinct constants")
        }
    }

    private static let fcpyHalf: UInt32 = 0x0551_C000

    @Test func fcpyRendersAsMergingFmovAndReadsItsDestination() {
        let encoding = Self.fcpyHalf | (UInt32(0x08) << 5)
        let d = decode(encoding)
        #expect(d.mnemonic == .fmov)
        #expect(text(encoding) == "fmov z0.h, p1/m, #3.00000000")
        #expect(canonicalIndices(d.semanticReads) == [32], "fcpy is merging — it reads the destination")
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableReads.predicateMask == (1 << 1), "fcpy reads its governing predicate")
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func fcpyTakesEverySize() {
        let base = Self.fcpyHalf & ~(UInt32(0b11) << 22)
        #expect(text((base | (0b01 << 22)) | (UInt32(0x00) << 5)) == "fmov z0.h, p1/m, #2.00000000")
        #expect(text((base | (0b10 << 22)) | (UInt32(0x00) << 5)) == "fmov z0.s, p1/m, #2.00000000")
        #expect(text((base | (0b11 << 22)) | (UInt32(0x00) << 5)) == "fmov z0.d, p1/m, #2.00000000")
    }
}
