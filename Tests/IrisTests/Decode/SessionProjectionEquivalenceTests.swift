// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

// The proof that the session tier is a complete substitute for the
// Instruction tier on the semantic projection surface: over a real decoded
// stream, EVERY BorrowedInstruction projection equals the corresponding
// Instruction projection at every index. Because both tiers delegate to one
// shared implementation, this is what pins them against drift, if a future
// edit changes one tier's formula and not the other, an index here diverges.

/// A deterministic mixed buffer chosen to exercise every branch of every
/// projection on both tiers: direct/conditional/indirect/return/exception
/// control flow, ADR/ADRP/PC-literal address formation, ordinary and atomic
/// and exclusive memory, flag readers and writers, condition consumers, the
/// pointer-authentication forms, a data-in-code span, an undefined word, and
/// a truncated tail. Decoded with ARM64E features at a nonzero base so the
/// feature-gated PAC loads and the page math are live. Every encoding is an
/// llvm-mc-convention word (mnemonic noted inline).
private func makeProjectionStream() -> InstructionStream {
    let words: [UInt32] = [
        0x1400_0002, // b     #8                  direct, branchTarget
        0x9400_0001, // bl    #4                  call + label, branchTarget
        0xD63F_0000, // blr   x0                  call, indirect -> nil target
        0xD61F_0000, // br    x0                  indirect -> nil target
        0xD65F_03C0, // ret                       return -> nil target
        0xD65F_0BFF, // retaa                     return + PAC
        0xD400_0021, // svc   #1                  exception -> nil target
        0x5400_0080, // b.eq  #16                 conditional branch + target
        0x5400_0090, // bc.eq #16                 conditional branch + target
        0xB400_0040, // cbz   x0, #8              conditional + target
        0x3600_0040, // tbz   w0, #0, #8          conditional + target
        0x9A82_1020, // csel  x0, x1, x2, ne      condition consumer (no branch)
        0xFA42_0820, // ccmp  x1, x2, #0, eq      condition consumer + flags r/w
        0x9A02_0020, // adc   x0, x1, x2          reads C, writes none
        0xB100_0841, // adds  x1, x2, #2          writes flags, reads none
        0x1000_0080, // adr   x0, #16             pcRelativeTarget (label+adr)
        0xB000_0000, // adrp  x0, #+page          pcRelativeTarget (pageLabel)
        0x5800_0040, // ldr   x0, #8              PC-literal load -> pcRel target
        0xD800_0040, // prfm  ..., #8             PC-literal prefetch -> pcRel
        0xF940_0021, // ldr   x1, [x1]            ordinary load (reads memory)
        0xF900_0020, // str   x0, [x1]            ordinary store (writes memory)
        0xF820_0041, // ldadd x0, x1, [x2]        atomic RMW (reads+writes)
        0xC85F_7C20, // ldxr  x0, [x1]            exclusive load
        0x8800_7C00, // stxr  w0, w0, [x0]        exclusive store
        0xC8DF_FC20, // ldar  x0, [x1]            acquire ordering load
        0xF820_0400, // ldraa x0, [x0]            PAC load (arm64e-gated)
        0xDAC1_0020, // pacia x0, x1              standalone PAC
        0xD503_201F, // nop                       zero operands, no effects
        0xDEAD_BEEF, // covered by the data-in-code span (marker)
        0x0200_0000, // reserved/unallocated word -> UNDEFINED witness
    ]
    var bytes: [UInt8] = []
    bytes.reserveCapacity(words.count * 4 + 3)
    for word in words {
        bytes.append(UInt8(word & 0xFF))
        bytes.append(UInt8((word >> 8) & 0xFF))
        bytes.append(UInt8((word >> 16) & 0xFF))
        bytes.append(UInt8((word >> 24) & 0xFF))
    }
    // A 3-byte tail so the buffer length is not a multiple of 4.
    bytes.append(0x2A)
    bytes.append(0x00)
    bytes.append(0x00)
    // The span covers the word at index 28 (offset 28 * 4 = 112).
    return InstructionStream(
        bytes: bytes,
        at: 0x1_0000_8000,
        features: .arm64e,
        dataInCode: [DataInCodeSpan(offset: 112, length: 4, kind: .data)],
    )
}

/// Folds one instruction's entire projection surface into the list of
/// per-projection agreement verdicts between the borrowed view and the
/// stream view. Each entry is `borrowed.X == view.X` for one projection X,
/// evaluated unconditionally, so equivalence is asserted by checking the
/// whole vector is true with no per-projection mismatch arm that real input
/// never reaches. Operands are materialized on both sides so the comparison
/// is value-level.
private func projectionAgreement(
    _ borrowed: BorrowedInstruction,
    _ view: Instruction,
) -> [Bool] {
    [
        // Record-derived conveniences.
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
        // Resolved targets.
        borrowed.branchTarget == view.branchTarget,
        borrowed.pcRelativeTarget == view.pcRelativeTarget,
        // Semantic predicates.
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

@Suite("BorrowedInstruction / projection equivalence with the Instruction tier")
struct SessionProjectionEquivalenceTests {
    @Test func everyProjectionMatchesTheViewTierAtEveryIndex() {
        let stream = makeProjectionStream()
        #expect(stream.count == 31)
        // For every record, fold the full surface into one boolean: did the
        // borrowed view and the stream view agree on every projection. The
        // session yields the verdicts; the closure returns them so the
        // assertions run outside the pinning scope.
        let perInstruction = stream.withSession { session -> [Bool] in
            (0 ..< stream.count).map { index in
                !projectionAgreement(session[index], stream[index]).contains(false)
            }
        }
        #expect(perInstruction == Array(repeating: true, count: stream.count))
    }

    @Test func everyProjectionMatchesUnderSessionIterationOrder() {
        // The same equivalence reached through the retain-free iterator,
        // pairing each borrowed element with the stream view at its index.
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
        // Equivalence reached through the address lookup path, so the
        // projections are exercised on values produced by `instruction(at:)`
        // as well as by subscript and iteration.
        let stream = makeProjectionStream()
        let base = stream.baseAddress
        let perWord = stream.withSession { session -> [Bool] in
            (0 ..< stream.count).map { index in
                let address = base &+ UInt64(index * 4)
                guard let borrowed = session.instruction(at: address),
                      let view = stream.instruction(at: address)
                else { return false }
                return !projectionAgreement(borrowed, view).contains(false)
            }
        }
        #expect(perWord == Array(repeating: true, count: stream.count))
    }
}

/// Coverage closure for the projection branches the equivalence sweep
/// reaches only through `Instruction`-tier delegation: this suite drives the
/// branches DIRECTLY on `BorrowedInstruction` so each predicate's true and
/// false arm, and each nil / non-nil and each operand-case of the resolved
/// targets, is hit on the borrowed type itself.
@Suite("BorrowedInstruction / projection branch coverage")
struct SessionProjectionBranchTests {
    @Test func branchTargetCoversEveryArmOnTheBorrowedTier() {
        let stream = makeProjectionStream()
        let results = stream.withSession { session -> [UInt64?] in
            [
                session[0].branchTarget, //  direct B   -> resolves
                session[1].branchTarget, //  call BL    -> resolves
                session[2].branchTarget, //  call BLR   -> nil (no label)
                session[4].branchTarget, //  return RET -> nil (default arm)
                session[6].branchTarget, //  exception  -> nil (default arm)
                session[27].branchTarget, // nop        -> nil (default arm)
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
        let results = stream.withSession { session -> [UInt64?] in
            [
                session[15].branchTarget == nil ? session[15].pcRelativeTarget : nil, // adr  (label+adr arm)
                session[16].pcRelativeTarget, // adrp  (pageLabel arm)
                session[17].pcRelativeTarget, // ldr literal  (memory .pc arm)
                session[18].pcRelativeTarget, // prfm literal (memory .pc arm)
                session[19].pcRelativeTarget, // ldr [x1]   -> nil (memory non-pc base)
                session[27].pcRelativeTarget, // nop        -> nil (no matching operand)
                session[0].pcRelativeTarget, //  b          -> nil (label, not adr)
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
        // Drive each predicate's true and false arm directly on the borrowed
        // tier. Each row is (true-case index, false-case index) folded into
        // one verdict per predicate.
        let verdicts = stream.withSession { session -> [Bool] in
            [
                session[1].isCall && !session[0].isCall,
                session[4].isReturn && !session[0].isReturn,
                session[7].isConditional && !session[0].isConditional, //  branch arm
                session[11].isConditional && !session[13].isConditional, // condition-code arm vs adc
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
        // The record-derived conveniences read the same bytes the record
        // carries, including the acquire-ordering load and the data-marker.
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
