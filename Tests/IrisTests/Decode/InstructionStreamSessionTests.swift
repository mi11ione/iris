// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func makeRealStream() -> InstructionStream {
    let words: [UInt32] = [
        0xA9BF_7BFD,
        0x9100_03FD,
        0xD101_03FF,
        0x9000_0008,
        0x9104_0108,
        0xF940_0100,
        0x9400_0000,
        0x7100_001F,
        0x5400_0081,
        0xA8C1_7BFD,
        0x9101_03FF,
        0xD65F_03C0,
        0xD503_201F,
        0xDEAD_BEEF,
        0x0604_0200,
        0x0000_FFFF,
    ]
    var bytes: [UInt8] = []
    bytes.reserveCapacity(words.count * 4 + 2)
    for word in words {
        bytes.append(UInt8(word & 0xFF))
        bytes.append(UInt8((word >> 8) & 0xFF))
        bytes.append(UInt8((word >> 16) & 0xFF))
        bytes.append(UInt8((word >> 24) & 0xFF))
    }
    bytes.append(0x2A)
    bytes.append(0x00)
    return InstructionStream(
        bytes: bytes,
        at: 0x1_0000_4000,
        features: .arm64e,
        dataInCode: [DataInCodeSpan(offset: 52, length: 8, kind: .data)],
    )
}

private enum LookupSignature: Equatable {
    case absent
    case present(InstructionRecord, [Operand])
}

private func lookupSignature(_ borrowed: BorrowedInstruction?) -> LookupSignature {
    borrowed.map { .present($0.record, Array($0.operands)) } ?? .absent
}

private func lookupSignature(_ view: Instruction?) -> LookupSignature {
    view.map { .present($0.record, Array($0.operands)) } ?? .absent
}

/// The golden equality pin for the session tier.
@Suite("InstructionStream session / equality with the view path")
struct SessionViewEqualityTests {
    @Test func sessionElementsMatchViewElementsAtEveryIndex() {
        let stream = makeRealStream()
        #expect(stream.count == 17)
        let scalars = stream.withSession { session in
            [
                session.count == stream.count,
                session.baseAddress == stream.baseAddress,
                session.byteCount == stream.byteCount,
            ]
        }
        let perIndex = stream.withSession { session -> [Bool] in
            (0 ..< stream.count).map { index in
                let borrowed = session[index]
                let view = stream[index]
                return borrowed.record == stream.records[index]
                    && Array(borrowed.operands) == Array(view.operands)
            }
        }
        #expect(!scalars.contains(false))
        #expect(perIndex == Array(repeating: true, count: stream.count))
    }

    @Test func sessionIterationMatchesViewIterationInOrder() {
        let stream = makeRealStream()
        let viewEncodings = stream.map(\.encoding)
        let viewOperandCounts = stream.map(\.operands.count)
        let (sessionEncodings, sessionOperandCounts) = stream.withSession { session -> ([UInt32], [Int]) in
            var encodings: [UInt32] = []
            var counts: [Int] = []
            for borrowed in session {
                encodings.append(borrowed.record.encoding)
                counts.append(borrowed.operands.count)
            }
            return (encodings, counts)
        }
        #expect(sessionEncodings == viewEncodings)
        #expect(sessionOperandCounts == viewOperandCounts)
    }

    @Test func sessionLookupAgreesWithStreamLookupAtEveryWordAddress() {
        let stream = makeRealStream()
        let base = stream.baseAddress
        let agreement = stream.withSession { session -> [Bool] in
            var results: [Bool] = []
            var address = base
            while address < base &+ stream.byteCount &+ 8 {
                let fromSession = lookupSignature(session.instruction(at: address))
                let fromStream = lookupSignature(stream.instruction(at: address))
                results.append(fromSession == fromStream)
                address &+= 4
            }
            return results
        }
        #expect(!agreement.contains(false))
        #expect(agreement.count == 19)
    }

    @Test func sessionAddressSubscriptMirrorsInstructionAt() {
        let stream = makeRealStream()
        let base = stream.baseAddress
        let (hit, miss) = stream.withSession { session -> (Bool, Bool) in
            let hit = session[address: base &+ 8]?.record == session.instruction(at: base &+ 8)?.record
            let miss = session[address: base &+ 2] == nil && session.instruction(at: base &+ 2) == nil
            return (hit, miss)
        }
        #expect(hit)
        #expect(miss)
    }

    @Test func sessionContainingLookupAgreesWithStreamAtUnalignedAddresses() {
        let stream = makeRealStream()
        let base = stream.baseAddress
        let agreement = stream.withSession { session -> [Bool] in
            [UInt64(1), 2, 3, 5, 17, 50, 53, 65, 1000].map { offset in
                let fromSession = lookupSignature(session.instruction(containing: base &+ offset))
                let fromStream = lookupSignature(stream.instruction(containing: base &+ offset))
                return fromSession == fromStream
            }
        }
        #expect(!agreement.contains(false))
        #expect(agreement.count == 9)
    }

    @Test func sessionSeesDataMarkersAndUndefinedExactlyAsViews() {
        let stream = makeRealStream()
        let (markerCategory, markerOperands, undefinedCategory) = stream.withSession { session in
            (
                session[13].record.category,
                session[13].operands.count,
                session[15].record.category,
            )
        }
        #expect(markerCategory == .dataInCodeMarker)
        #expect(markerOperands == 0)
        #expect(undefinedCategory == stream[15].category)
    }
}

/// Validates the session's negative paths.
@Suite("InstructionStream session / negative pins and edges")
struct SessionEdgeTests {
    @Test func sessionLookupRejectsOutOfStreamAndUnalignedAddresses() {
        let stream = makeRealStream()
        let base = stream.baseAddress
        let end = base &+ stream.byteCount
        let results = stream.withSession { session -> [Bool] in
            [
                session.instruction(at: base &- 4) == nil,
                session.instruction(at: 0) == nil,
                session.instruction(at: base &+ 1) == nil,
                session.instruction(at: base &+ 2) == nil,
                session.instruction(at: base &+ 3) == nil,
                session.instruction(at: end) == nil,
                session.instruction(at: end &+ 4) == nil,
                session.instruction(containing: end) == nil,
                session.instruction(containing: base &- 1) == nil,
            ]
        }
        #expect(results == Array(repeating: true, count: 9))
    }

    @Test func sessionOverEmptyStreamIsEmpty() {
        let stream = InstructionStream(bytes: [] as [UInt8], at: 0x4000)
        let (count, isEmpty, lookup, containing, walked) = stream.withSession { session in
            (
                session.count,
                session.isEmpty,
                session.instruction(at: 0x4000) == nil,
                session.instruction(containing: 0x4000) == nil,
                Array(session).count,
            )
        }
        #expect(count == 0)
        #expect(isEmpty)
        #expect(lookup)
        #expect(containing)
        #expect(walked == 0)
    }

    @Test func sessionTruncatedTailElementHasNoOperands() {
        let stream = makeRealStream()
        let (category, tailBytes, operandCount, lookupAgrees) = stream.withSession { session -> (Category, Int, Int, Bool) in
            let tail = session[session.count - 1]
            let atTail = session.instruction(at: stream.baseAddress &+ 64)
            return (
                tail.record.category,
                tail.record.tailByteCount,
                tail.operands.count,
                atTail?.record == tail.record,
            )
        }
        #expect(category == .truncatedTail)
        #expect(tailBytes == 2)
        #expect(operandCount == 0)
        #expect(lookupAgrees)
    }

    @Test func sessionClampsHostileOperandIndicesToEmpty() {
        let hostileStart = InstructionRecord(
            address: 0x1000,
            semanticReads: .empty,
            semanticWrites: .empty,
            encoding: 0xD503_201F,
            operandStart: 999,
            mnemonic: .nop,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .branchesExceptionSystem,
            operandCount: 2,
        )
        let hostileCount = InstructionRecord(
            address: 0x1004,
            semanticReads: .empty,
            semanticWrites: .empty,
            encoding: 0xD503_201F,
            operandStart: 0,
            mnemonic: .nop,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .branchesExceptionSystem,
            operandCount: 200,
        )
        let stream = InstructionStream(
            baseAddress: 0x1000,
            byteCount: 8,
            features: [],
            records: [hostileStart, hostileCount],
            operands: [.register(RegisterRef.x(0))],
            diagnostics: [],
        )
        let (startClamped, countClamped) = stream.withSession { session in
            (session[0].operands.count, session[1].operands.count)
        }
        #expect(startClamped == 0)
        #expect(countClamped == 0)
        #expect(stream.operands(for: hostileStart).count == 0)
        #expect(stream.operands(for: hostileCount).count == 0)
    }

    @Test func sessionLookupRejectsIndicesBeyondHandBuiltRecords() {
        let record = InstructionRecord(
            address: 0x1000,
            semanticReads: .empty,
            semanticWrites: .empty,
            encoding: 0xD503_201F,
            operandStart: 0,
            mnemonic: .nop,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .branchesExceptionSystem,
            operandCount: 0,
        )
        let stream = InstructionStream(
            baseAddress: 0x1000,
            byteCount: 16,
            features: [],
            records: [record],
            operands: [],
            diagnostics: [],
        )
        let (atRejected, containingRejected, firstFound) = stream.withSession { session in
            (
                session.instruction(at: 0x1008) == nil,
                session.instruction(containing: 0x100D) == nil,
                session.instruction(at: 0x1000)?.record,
            )
        }
        #expect(atRejected)
        #expect(containingRejected)
        #expect(firstFound == record)
    }

    @Test func sessionLookupIsModularInWrappingStreams() {
        let words: [UInt32] = [0xD503_201F, 0xD503_201F, 0xD65F_03C0]
        var bytes: [UInt8] = []
        for word in words {
            bytes.append(UInt8(word & 0xFF))
            bytes.append(UInt8((word >> 8) & 0xFF))
            bytes.append(UInt8((word >> 16) & 0xFF))
            bytes.append(UInt8((word >> 24) & 0xFF))
        }
        let stream = InstructionStream(bytes: bytes, at: 0xFFFF_FFFF_FFFF_FFF8)
        let (wrappedRecord, viewRecord) = stream.withSession { session in
            (session.instruction(at: 0)?.record, stream.instruction(at: 0)?.record)
        }
        #expect(wrappedRecord == stream.records[2])
        #expect(wrappedRecord == viewRecord)
    }

    @Test func withSessionThreadsTheBodyResultOut() {
        let stream = makeRealStream()
        let viewCalls = stream.count(where: { $0.branchClass == .call })
        let sessionCalls = stream.withSession { session -> Int in
            var calls = 0
            for borrowed in session where borrowed.record.branchClass == .call {
                calls += 1
            }
            return calls
        }
        #expect(sessionCalls == viewCalls)
        #expect(sessionCalls == 1)
    }

    @Test func sessionPinnedBuffersMirrorStreamArrays() {
        let stream = makeRealStream()
        let (recordsMatch, operandsMatch) = stream.withSession { session in
            (
                Array(session.records) == stream.records,
                Array(session.operands) == stream.operands,
            )
        }
        #expect(recordsMatch)
        #expect(operandsMatch)
    }

    @Test func borrowedInstructionMemberwiseInitPairsRecordAndSlice() {
        let record = InstructionRecord(
            address: 0x2000,
            semanticReads: .empty,
            semanticWrites: RegisterSet.empty.inserting(RegisterRef.x(0)),
            encoding: 0xD280_0020,
            operandStart: 0,
            mnemonic: .mov,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operandCount: 2,
        )
        let operands: [Operand] = [.register(RegisterRef.x(0)), .unsignedImmediate(value: 1, width: 64)]
        let (encoding, count, first) = operands.withUnsafeBufferPointer { pinned -> (UInt32, Int, Operand?) in
            let borrowed = BorrowedInstruction(record: record, operands: pinned)
            return (borrowed.record.encoding, borrowed.operands.count, borrowed.operands.first)
        }
        #expect(encoding == 0xD280_0020)
        #expect(count == 2)
        #expect(first == .register(RegisterRef.x(0)))
    }
}
