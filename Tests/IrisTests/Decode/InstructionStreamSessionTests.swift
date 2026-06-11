// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Builds the shared real-content stream the equality suites pin
/// against: 12 llvm-mc-verified prologue words, a NOP, two words covered
/// by a data-in-code span, an undefined word, and a 2-byte truncated
/// tail, decoded with ARM64E features at a nonzero base.
private func makeRealStream() -> InstructionStream {
    let words: [UInt32] = [
        0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
        0x9100_03FD, // mov x29, sp
        0xD101_03FF, // sub sp, sp, #64
        0x9000_0008, // adrp x8, #0
        0x9104_0108, // add x8, x8, #256
        0xF940_0100, // ldr x0, [x8]
        0x9400_0000, // bl #0
        0x7100_001F, // cmp w0, #0
        0x5400_0081, // b.ne #16
        0xA8C1_7BFD, // ldp x29, x30, [sp], #16
        0x9101_03FF, // add sp, sp, #64
        0xD65F_03C0, // ret
        0xD503_201F, // nop (zero operands)
        0xDEAD_BEEF, // data-in-code span covers this word
        0x0604_0200, // and this word
        0x0000_FFFF, // udf #65535
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

/// Validates that every session access path agrees with the ergonomic
/// Instruction views over the same stream — the golden equality pin for
/// the closure-scoped session tier: identical records and identical
/// operand sequences at every index and every address, over a real
/// decoded buffer carrying defined words, a NOP, data-in-code markers,
/// an undefined word, and a truncated tail.
@Suite("InstructionStream session / equality with the view path")
struct SessionViewEqualityTests {
    @Test func sessionElementsMatchViewElementsAtEveryIndex() {
        let stream = makeRealStream()
        #expect(stream.count == 17)
        let allEqual = stream.withSession { session -> Bool in
            guard session.count == stream.count else { return false }
            guard session.baseAddress == stream.baseAddress else { return false }
            guard session.byteCount == stream.byteCount else { return false }
            for index in 0 ..< stream.count {
                let borrowed = session[index]
                let view = stream[index]
                guard borrowed.record == stream.records[index] else { return false }
                guard Array(borrowed.operands) == Array(view.operands) else { return false }
            }
            return true
        }
        #expect(allEqual)
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
        let agreement = stream.withSession { session -> Bool in
            var address = base
            while address < base &+ stream.byteCount &+ 8 {
                let fromSession = session.instruction(at: address)
                let fromStream = stream.instruction(at: address)
                switch (fromSession, fromStream) {
                case (nil, nil):
                    break
                case let (.some(borrowed), .some(view)):
                    guard borrowed.record == view.record else { return false }
                    guard Array(borrowed.operands) == Array(view.operands) else { return false }
                default:
                    return false
                }
                address &+= 4
            }
            return true
        }
        #expect(agreement)
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
        let agreement = stream.withSession { session -> Bool in
            for offset in [UInt64(1), 2, 3, 5, 17, 50, 53, 65] {
                let fromSession = session.instruction(containing: base &+ offset)
                let fromStream = stream.instruction(containing: base &+ offset)
                switch (fromSession, fromStream) {
                case (nil, nil):
                    break
                case let (.some(borrowed), .some(view)):
                    guard borrowed.record == view.record else { return false }
                    guard Array(borrowed.operands) == Array(view.operands) else { return false }
                default:
                    return false
                }
            }
            return true
        }
        #expect(agreement)
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

/// Validates the session tier's negative paths and edge contracts:
/// out-of-stream and unaligned lookups, the empty stream, the
/// truncated-tail element, hostile hand-built operand indices, modular
/// address wrap, and result threading out of the closure.
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
                session.reduce(0) { sum, _ in sum + 1 },
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
