// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func makeProjectionStream() -> InstructionStream {
    let words: [UInt32] = [
        0x1400_0002,
        0x9400_0001,
        0xD63F_0000,
        0xD61F_0000,
        0xD65F_03C0,
        0xD65F_0BFF,
        0xD400_0021,
        0x5400_0080,
        0x5400_0090,
        0xB400_0040,
        0x3600_0040,
        0x9A82_1020,
        0xFA42_0820,
        0x9A02_0020,
        0xB100_0841,
        0x1000_0080,
        0xB000_0000,
        0x5800_0040,
        0xD800_0040,
        0xF940_0021,
        0xF900_0020,
        0xF820_0041,
        0xC85F_7C20,
        0x8800_7C00,
        0xC8DF_FC20,
        0xF820_0400,
        0xDAC1_0020,
        0xD503_201F,
        0xDEAD_BEEF,
        0x0200_0000,
    ]
    var bytes: [UInt8] = []
    bytes.reserveCapacity(words.count * 4 + 3)
    for word in words {
        bytes.append(UInt8(word & 0xFF))
        bytes.append(UInt8((word >> 8) & 0xFF))
        bytes.append(UInt8((word >> 16) & 0xFF))
        bytes.append(UInt8((word >> 24) & 0xFF))
    }
    bytes.append(0x2A)
    bytes.append(0x00)
    bytes.append(0x00)
    return InstructionStream(
        bytes: bytes,
        at: 0x1_0000_8000,
        features: .arm64e,
        dataInCode: [DataInCodeSpan(offset: 112, length: 4, kind: .data)],
    )
}

private func projectionAgreement(
    _ borrowed: BorrowedInstruction,
    _ view: Instruction,
) -> [Bool] {
    [
        borrowed.address == view.address,
        borrowed.encoding == view.encoding,
        borrowed.mnemonic == view.mnemonic,
        borrowed.semanticReads == view.semanticReads,
        borrowed.semanticWrites == view.semanticWrites,
        borrowed.branchClass == view.branchClass,
        borrowed.memoryAccess == view.memoryAccess,
        borrowed.memoryOrdering == view.memoryOrdering,
        borrowed.flagEffect == view.flagEffect,
        borrowed.category == view.category,
        borrowed.isUndefined == view.isUndefined,
        Array(borrowed.operands) == Array(view.operands),
        borrowed.branchTarget == view.branchTarget,
        borrowed.pcRelativeTarget == view.pcRelativeTarget,
        borrowed.isCall == view.isCall,
        borrowed.isReturn == view.isReturn,
        borrowed.isConditional == view.isConditional,
        borrowed.readsMemory == view.readsMemory,
        borrowed.writesMemory == view.writesMemory,
        borrowed.isAtomic == view.isAtomic,
        borrowed.isExclusive == view.isExclusive,
        borrowed.readsFlags == view.readsFlags,
        borrowed.writesFlags == view.writesFlags,
        borrowed.usesPointerAuthentication == view.usesPointerAuthentication,
    ]
}

/// Validates that every ``BorrowedInstruction`` projection agrees with the
/// ``Instruction`` tier over the same stream.
@Suite("BorrowedInstruction / projection equivalence with the Instruction tier")
struct SessionProjectionEquivalenceTests {
    @Test func everyProjectionMatchesTheViewTierAtEveryIndex() {
        let stream = makeProjectionStream()
        #expect(stream.count == 31)
        let perInstruction = stream.withSession { session -> [Bool] in
            (0 ..< stream.count).map { index in
                !projectionAgreement(session[index], stream[index]).contains(false)
            }
        }
        #expect(perInstruction == Array(repeating: true, count: stream.count))
    }

    @Test func everyProjectionMatchesUnderSessionIterationOrder() {
        let stream = makeProjectionStream()
        let views = Array(stream)
        let perInstruction = stream.withSession { session -> [Bool] in
            var verdicts: [Bool] = []
            var index = 0
            for borrowed in session {
                verdicts.append(!projectionAgreement(borrowed, views[index]).contains(false))
                index += 1
            }
            return verdicts
        }
        #expect(perInstruction == Array(repeating: true, count: stream.count))
    }

    @Test func everyProjectionMatchesThroughAddressLookup() {
        let stream = makeProjectionStream()
        let base = stream.baseAddress
        let perWord = stream.withSession { session -> [Bool] in
            (0 ..< stream.count).map { index in
                let address = base &+ UInt64(index * 4)
                let agreed = session.instruction(at: address).flatMap { borrowed in
                    stream.instruction(at: address).map { view in
                        !projectionAgreement(borrowed, view).contains(false)
                    }
                }
                return agreed == true
            }
        }
        #expect(perWord == Array(repeating: true, count: stream.count))
    }
}

/// Coverage closure for the projection branches the equivalence sweep reaches
/// only through `Instruction`-tier delegation.
@Suite("BorrowedInstruction / projection branch coverage")
struct SessionProjectionBranchTests {
    @Test func branchTargetCoversEveryArmOnTheBorrowedTier() {
        let stream = makeProjectionStream()
        let results = stream.withSession { session -> [UInt64?] in
            [
                session[0].branchTarget,
                session[1].branchTarget,
                session[2].branchTarget,
                session[4].branchTarget,
                session[6].branchTarget,
                session[27].branchTarget,
            ]
        }
        #expect(results[0] != nil)
        #expect(results[1] != nil)
        #expect(results[2] == nil)
        #expect(results[3] == nil)
        #expect(results[4] == nil)
        #expect(results[5] == nil)
    }

    @Test func pcRelativeTargetCoversEveryArmOnTheBorrowedTier() {
        let stream = makeProjectionStream()
        #expect(stream.withSession { $0[15].branchTarget } == nil)
        let results = stream.withSession { session -> [UInt64?] in
            [
                session[15].pcRelativeTarget,
                session[16].pcRelativeTarget,
                session[17].pcRelativeTarget,
                session[18].pcRelativeTarget,
                session[19].pcRelativeTarget,
                session[27].pcRelativeTarget,
                session[0].pcRelativeTarget,
            ]
        }
        #expect(results[0] != nil)
        #expect(results[1] != nil)
        #expect(results[2] != nil)
        #expect(results[3] != nil)
        #expect(results[4] == nil)
        #expect(results[5] == nil)
        #expect(results[6] == nil)
    }

    @Test func predicatesCoverBothArmsOnTheBorrowedTier() {
        let stream = makeProjectionStream()
        let verdicts = stream.withSession { session -> [Bool] in
            [
                session[1].isCall && !session[0].isCall,
                session[4].isReturn && !session[0].isReturn,
                session[7].isConditional && !session[0].isConditional,
                session[11].isConditional && !session[13].isConditional,
                session[19].readsMemory && !session[20].readsMemory,
                session[20].writesMemory && !session[19].writesMemory,
                session[21].isAtomic && !session[22].isAtomic,
                session[22].isExclusive && !session[21].isExclusive,
                session[13].readsFlags && !session[14].readsFlags,
                session[14].writesFlags && !session[13].writesFlags,
                session[26].usesPointerAuthentication && !session[27].usesPointerAuthentication,
                session[29].isUndefined && !session[27].isUndefined,
            ]
        }
        #expect(verdicts == Array(repeating: true, count: 12))
    }

    @Test func conveniencesMirrorTheRecordOnTheBorrowedTier() {
        let stream = makeProjectionStream()
        let checks = stream.withSession { session -> [Bool] in
            let ldar = session[24]
            let marker = session[28]
            return [
                ldar.memoryOrdering.contains(.acquire),
                ldar.address == stream.baseAddress &+ UInt64(24 * 4),
                ldar.encoding == 0xC8DF_FC20,
                ldar.mnemonic == .ldar,
                ldar.semanticReads == stream.records[24].semanticReads,
                ldar.semanticWrites == stream.records[24].semanticWrites,
                ldar.branchClass == .none,
                marker.category == .dataInCodeMarker,
                marker.flagEffect == .none,
            ]
        }
        #expect(checks == Array(repeating: true, count: 9))
    }
}
