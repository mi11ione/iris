// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates InstructionRecord — the atomic 40-byte record the decoder
/// produces. Field preservation, equality, hashing, and the
/// load-bearing layout pin.
@Suite("InstructionRecord / memberwise init and equality")
struct InstructionRecordTests {
    @Test func memberwiseInitPreservesAllFields() {
        let record = InstructionRecord(
            address: 0x1_0000_8000,
            semanticReads: RegisterSet(mask: 0xAA),
            semanticWrites: RegisterSet(mask: 0x55),
            encoding: 0xDEAD_BEEF,
            operandStart: 7,
            mnemonic: .undefined,
            branchClass: .conditional,
            memoryAccess: .load,
            memoryOrdering: [.acquire],
            flagEffect: .nzcv,
            category: .branchesExceptionSystem,
            operandCount: 3,
        )
        #expect(record.address == 0x1_0000_8000)
        #expect(record.semanticReads.mask == 0xAA)
        #expect(record.semanticWrites.mask == 0x55)
        #expect(record.encoding == 0xDEAD_BEEF)
        #expect(record.operandStart == 7)
        #expect(record.mnemonic == .undefined)
        #expect(record.branchClass == .conditional)
        #expect(record.memoryAccess == .load)
        #expect(record.memoryOrdering == [.acquire])
        #expect(record.flagEffect == .nzcv)
        #expect(record.category == .branchesExceptionSystem)
        #expect(record.operandCount == 3)
    }

    @Test func equalRecordsHashEqual() {
        let a = makeRecord(address: 0x1000)
        let b = makeRecord(address: 0x1000)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func recordsWithDifferentAddressesDiffer() {
        let a = makeRecord(address: 0x1000)
        let b = makeRecord(address: 0x1004)
        #expect(a != b)
    }
}

/// Validates the InstructionRecord memory-layout pin — 40 bytes,
/// 8-byte alignment. This invariant is the packed-storage performance
/// architecture's contract (cache-friendly bulk streams, predictable
/// cost per million instructions); a regression here is a structural
/// break.
@Suite("InstructionRecord / memory-layout invariant")
struct InstructionRecordLayoutTests {
    @Test func sizeIsExactlyFortyBytes() {
        #expect(MemoryLayout<InstructionRecord>.size == 40)
    }

    @Test func alignmentIsEightBytes() {
        #expect(MemoryLayout<InstructionRecord>.alignment == 8)
    }

    @Test func strideMatchesSize() {
        // Natural alignment must produce stride == size with no
        // trailing padding for this layout.
        #expect(MemoryLayout<InstructionRecord>.stride == 40)
    }
}

private func makeRecord(address: UInt64) -> InstructionRecord {
    InstructionRecord(
        address: address,
        semanticReads: .empty,
        semanticWrites: .empty,
        encoding: 0,
        operandStart: 0,
        mnemonic: .undefined,
        branchClass: .none,
        memoryAccess: .none,
        memoryOrdering: [],
        flagEffect: .none,
        category: .undefined,
        operandCount: 0,
    )
}
