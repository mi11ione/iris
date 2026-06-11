// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates PrefetchOperation — the 5-bit composite operand for
/// `PRFM` / `PRFUM` encoding `(operation, target, policy)`.
@Suite("PrefetchOperation / composite-byte decomposition")
struct PrefetchOperationCompositeTests {
    @Test func rawValueIsMaskedToFiveBits() {
        let op = PrefetchOperation(rawValue: 0xFF)
        #expect(op.rawValue == 0b11111)
    }

    @Test func rawZeroDecodesToLoadDataKeepL1() {
        let op = PrefetchOperation(rawValue: 0)
        #expect(op.operation == .loadData)
        #expect(op.target == .l1)
        #expect(op.policy == .keep)
    }

    @Test func rawOneDecodesToLoadDataStreamL1() {
        let op = PrefetchOperation(rawValue: 0b00001)
        #expect(op.operation == .loadData)
        #expect(op.target == .l1)
        #expect(op.policy == .stream)
    }

    @Test func loadInstructionL2Keep() {
        let raw: UInt8 = (0b01 << 3) | (0b01 << 1) | 0b0
        let op = PrefetchOperation(rawValue: raw)
        #expect(op.operation == .loadInstruction)
        #expect(op.target == .l2)
        #expect(op.policy == .keep)
    }

    @Test func storeDataL3Stream() {
        let raw: UInt8 = (0b10 << 3) | (0b10 << 1) | 0b1
        let op = PrefetchOperation(rawValue: raw)
        #expect(op.operation == .storeData)
        #expect(op.target == .l3)
        #expect(op.policy == .stream)
    }

    @Test func reservedOperationBitsDecodeToReserved() {
        let raw: UInt8 = (0b11 << 3) | (0b00 << 1) | 0
        let op = PrefetchOperation(rawValue: raw)
        #expect(op.operation == .reserved)
    }

    @Test func operationEnumRawValuesStable() {
        #expect(PrefetchOperation.Operation.loadData.rawValue == 0b00)
        #expect(PrefetchOperation.Operation.loadInstruction.rawValue == 0b01)
        #expect(PrefetchOperation.Operation.storeData.rawValue == 0b10)
        #expect(PrefetchOperation.Operation.reserved.rawValue == 0b11)
    }

    @Test func targetEnumRawValuesStable() {
        #expect(PrefetchOperation.Target.l1.rawValue == 0b00)
        #expect(PrefetchOperation.Target.l2.rawValue == 0b01)
        #expect(PrefetchOperation.Target.l3.rawValue == 0b10)
    }

    @Test func policyEnumRawValuesStable() {
        #expect(PrefetchOperation.Policy.keep.rawValue == 0)
        #expect(PrefetchOperation.Policy.stream.rawValue == 1)
    }

    @Test func equalPrefetchOperationsHashEqual() {
        let a = PrefetchOperation(rawValue: 0b10110)
        let b = PrefetchOperation(rawValue: 0b10110)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}
