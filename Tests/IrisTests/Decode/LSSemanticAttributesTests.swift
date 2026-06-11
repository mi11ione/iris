// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

/// Memory-access classification derived from the mnemonic name by
/// hand-enumerated ARM-semantic sets — independent of the implementation's
/// raw-value-range arithmetic, so a range off-by-one cannot hide here.
private func independentAccess(forName name: String) -> MemoryAccess {
    let prefetch: Set<String> = ["prfm", "prfum"]
    let exclusiveLoad: Set<String> = [
        "ldxr", "ldxrb", "ldxrh", "ldxp", "ldaxr", "ldaxrb", "ldaxrh", "ldaxp",
    ]
    let exclusiveStore: Set<String> = [
        "stxr", "stxrb", "stxrh", "stxp", "stlxr", "stlxrb", "stlxrh", "stlxp",
    ]
    let load: Set<String> = [
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
        "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
        "ldp", "ldpsw", "ldnp",
        "ldar", "ldarb", "ldarh", "ldapr", "ldaprb", "ldaprh",
        "ldlar", "ldlarb", "ldlarh",
        "ldapur", "ldapurb", "ldapurh", "ldapursb", "ldapursh", "ldapursw",
        "ldraa", "ldrab",
        "ldtr", "ldtrb", "ldtrh", "ldtrsb", "ldtrsh", "ldtrsw",
    ]
    let store: Set<String> = [
        "str", "strb", "strh", "stur", "sturb", "sturh",
        "stp", "stgp", "stnp",
        "stlr", "stlrb", "stlrh", "stllr", "stllrb", "stllrh",
        "stlur", "stlurb", "stlurh",
        "sttr", "sttrb", "sttrh",
    ]
    if prefetch.contains(name) { return .prefetch }
    if exclusiveLoad.contains(name) { return .exclusiveLoad }
    if exclusiveStore.contains(name) { return .exclusiveStore }
    if load.contains(name) { return .load }
    if store.contains(name) { return .store }
    // Remainder = LSE RMW + LSE ST aliases + CAS family — all RMW atomic.
    return .atomic
}

/// Memory-ordering derived from the mnemonic name suffix — a string
/// algorithm independent of the implementation's raw-value modulo.
private func independentOrdering(forName name: String) -> MemoryOrdering {
    let acquireForms: Set<String> = [
        "ldar", "ldarb", "ldarh", "ldaxr", "ldaxrb", "ldaxrh", "ldaxp",
        "ldapr", "ldaprb", "ldaprh", "ldlar", "ldlarb", "ldlarh",
        "ldapur", "ldapurb", "ldapurh", "ldapursb", "ldapursh", "ldapursw",
    ]
    let releaseForms: Set<String> = [
        "stlr", "stlrb", "stlrh", "stlxr", "stlxrb", "stlxrh", "stlxp",
        "stllr", "stllrb", "stllrh", "stlur", "stlurb", "stlurh",
    ]
    if acquireForms.contains(name) { return [.acquire] }
    if releaseForms.contains(name) { return [.release] }
    // LSE / ST-alias / CAS — ordering lives in the suffix after the
    // family prefix and before any b/h size suffix. `casp` before `cas`.
    let families = [
        "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
        "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin",
        "swp", "casp", "cas",
    ]
    guard let family = families.first(where: { name.hasPrefix($0) }) else {
        return []
    }
    var token = String(name.dropFirst(family.count))
    if token.hasSuffix("b") || token.hasSuffix("h") { token = String(token.dropLast()) }
    switch token {
    case "a": return [.acquire]
    case "l": return [.release]
    case "al": return [.acquire, .release]
    default: return []
    }
}

/// Operand-shape derived from the mnemonic name — independent of the
/// implementation's raw-value-range bucketing.
private func independentShape(forName name: String) -> [LSOperandKind] {
    if name == "prfm" || name == "prfum" { return [.prefetchOperation, .memory] }
    if name == "stxp" || name == "stlxp" {
        return [.register, .register, .register, .memory]
    }
    if ["stxr", "stxrb", "stxrh", "stlxr", "stlxrb", "stlxrh"].contains(name) {
        return [.register, .register, .memory]
    }
    if ["ldxp", "ldaxp", "ldp", "stp", "ldpsw", "stgp", "ldnp", "stnp"].contains(name) {
        return [.register, .register, .memory]
    }
    if name.hasPrefix("casp") {
        return [.register, .register, .register, .register, .memory]
    }
    if name.hasPrefix("cas") { return [.register, .register, .memory] }
    let stFamilies = ["stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin"]
    if stFamilies.contains(where: { name.hasPrefix($0) }) { return [.register, .memory] }
    let lseFamilies = ["ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "swp"]
    if lseFamilies.contains(where: { name.hasPrefix($0) }) {
        return [.register, .register, .memory]
    }
    // Simple [Rt, memory]: plain loads/stores, exclusive single loads,
    // LDAPR, LDLAR/STLLR, LRCPC2, LDRAA/LDRAB, LDTR family.
    return [.register, .memory]
}

/// Validates the per-mnemonic semantic-attribute tables and the
/// `LSSemanticChecker.verify(draft:)` entry point — the
/// expected memory-access / ordering / operand-shape / read-write-mask
/// lookups and every `LSSemanticIssue` field-mismatch path.
@Suite("L/S semantic attributes + checker")
struct LSSemanticAttributesTests {
    @Test func flagEffectIsAlwaysNone() {
        // No L/S instruction writes PSTATE.NZCV.
        for m: Mnemonic in [.ldr, .str, .cas, .ldadd, .prfm, .stxr, .ldar] {
            #expect(LSSemanticAttributes.expectedFlagEffect(for: m) == .none)
        }
    }

    @Test func expectedMemoryAccessClassifiesEveryKind() {
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .ldr) == .load)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .str) == .store)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .ldxr) == .exclusiveLoad)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .stxr) == .exclusiveStore)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .prfm) == .prefetch)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .prfum) == .prefetch)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .ldadd) == .atomic)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .cas) == .atomic)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .caspal) == .atomic)
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .stadd) == .atomic)
    }

    @Test func expectedMemoryAccessIsNilForNonLoadStoreMnemonic() {
        #expect(LSSemanticAttributes.expectedMemoryAccess(for: .add) == nil)
        #expect(LSSemanticAttributes.expectedOperandShape(for: .add) == nil)
    }

    @Test func expectedMemoryOrderingForAcquireReleaseForms() {
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldar) == [.acquire])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldapr) == [.acquire])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldapur) == [.acquire])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .stlr) == [.release])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .stlur) == [.release])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldr) == [])
    }

    @Test func expectedMemoryOrderingFollowsTheLseSuffixCube() {
        // Plain / A / L / AL → [] / acquire / release / both.
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldadd) == [])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldadda) == [.acquire])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldaddl) == [.release])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .ldaddal) == [.acquire, .release])
    }

    @Test func expectedMemoryOrderingFollowsTheCasSuffixCube() {
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .cas) == [])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .casa) == [.acquire])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .casl) == [.release])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .casal) == [.acquire, .release])
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .caspal) == [.acquire, .release])
    }

    @Test func expectedMemoryOrderingIsNilForNonLoadStoreMnemonic() {
        #expect(LSSemanticAttributes.expectedMemoryOrdering(for: .add) == nil)
    }

    @Test func expectedOperandShapeForEveryShapeClass() {
        #expect(LSSemanticAttributes.expectedOperandShape(for: .ldr) == [.register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .ldp) == [.register, .register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .stxr) == [.register, .register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .stxp) == [.register, .register, .register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .prfm) == [.prefetchOperation, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .ldadd) == [.register, .register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .stadd) == [.register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .cas) == [.register, .register, .memory])
        #expect(LSSemanticAttributes.expectedOperandShape(for: .casp)
            == [.register, .register, .register, .register, .memory])
    }

    @Test func expectedOperandShapeIsNilForNonLoadStoreMnemonic() {
        #expect(LSSemanticAttributes.expectedOperandShape(for: .add) == nil)
    }

    @Test func expectedReadMaskForLoadIsBaseRegister() {
        // ldr x0, [x0] — reads the base register only.
        #expect(LSSemanticAttributes.expectedReadMask(for: decode(0xF940_0000)) == 0x1)
    }

    @Test func expectedReadMaskForStoreExclusiveExcludesStatusRegister() {
        // stxr w5, x1, [x2] — reads Rt + Rn, not the status register Rs.
        let d = decode(0xC805_7C41, at: 0)
        #expect(LSSemanticAttributes.expectedReadMask(for: d) == (UInt64(1) << 1) | (UInt64(1) << 2))
    }

    @Test func expectedWriteMaskForStoreExclusiveIsStatusRegister() {
        // stxr w5, x1, [x2] — writes only the status register Rs (w5).
        let d = decode(0xC805_7C41, at: 0)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == (UInt64(1) << 5))
    }

    @Test func expectedWriteMaskForPlainStoreIsZero() {
        // str w0, [x0] — a plain store with no writeback writes nothing.
        #expect(LSSemanticAttributes.expectedWriteMask(for: decode(0xB900_0000)) == 0)
    }

    @Test func expectedMasksForPrefetchAreBaseReadAndNoWrite() {
        let d = decode(0xF980_0000) // prfm pldl1keep, [x0]
        #expect(LSSemanticAttributes.expectedReadMask(for: d) == 0x1)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == 0)
    }

    @Test func expectedMasksForCasReadAllRegisters() {
        // cas w3, w4, [x5] — CAS reads Rs + Rt + Rn, writes Rs.
        let cas = decode(0x88A3_7CA4, at: 0)
        #expect(cas.mnemonic == .cas)
        #expect(LSSemanticAttributes.expectedReadMask(for: cas)
            == (UInt64(1) << 3) | (UInt64(1) << 4) | (UInt64(1) << 5))
        #expect(LSSemanticAttributes.expectedWriteMask(for: cas) == (UInt64(1) << 3))
    }

    @Test func expectedMasksForLseRmwReadRsAndBase() {
        // ldadd w3, w4, [x5] — RMW reads Rs + Rn, writes Rt.
        let d = decode(0xB823_00A4, at: 0)
        #expect(d.mnemonic == .ldadd)
        #expect(LSSemanticAttributes.expectedReadMask(for: d) == (UInt64(1) << 3) | (UInt64(1) << 5))
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == (UInt64(1) << 4))
    }

    @Test func expectedMasksForCaspWriteThePair() {
        // casp w0, w1, w2, w3, [x4].
        let d = decode(0x0820_7C82, at: 0)
        #expect(d.mnemonic == .casp)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == (UInt64(1) << 0) | (UInt64(1) << 1))
    }

    @Test func expectedMaskForLoadWithWritebackIncludesBase() {
        // ldraa x0, [x1, #0]! — pre-index load writes Rt + the base.
        let d = decode(0xF820_0C20, at: 0, features: .arm64e)
        #expect(d.mnemonic == .ldraa)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == (UInt64(1) << 0) | (UInt64(1) << 1))
    }

    @Test func expectedMasksAreNilForNonLoadStoreMnemonic() {
        let d = Instruction(address: 0, encoding: 0, mnemonic: .add, category: .loadsAndStores)
        #expect(LSSemanticAttributes.expectedReadMask(for: d) == nil)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == nil)
    }

    @Test func expectedMasksAreNilWhenNoMemoryOperandPresent() {
        // A draft missing its memory operand cannot have a derived mask.
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: .ldr,
            category: .loadsAndStores, operands: [.register(.x(0))],
        )
        #expect(LSSemanticAttributes.expectedReadMask(for: d) == nil)
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == nil)
    }

    @Test func verifyReturnsNilForACorrectlyDecodedRecord() {
        #expect(LSSemanticChecker.verify(decode(0xF940_0000)) == nil)
    }

    @Test func verifySkipsUndefinedRecords() {
        let d = Instruction(address: 0, encoding: 0xDEAD_BEEF, mnemonic: .undefined, category: .undefined)
        #expect(LSSemanticChecker.verify(d) == nil)
    }

    @Test func verifyFlagsWrongBranchClass() {
        let d = mutated(decode(0xF940_0000), branchClass: .direct)
        #expect(LSSemanticChecker.verify(d)?.field == "branchClass")
    }

    @Test func verifyFlagsWrongFlagEffect() {
        let d = mutated(decode(0xF940_0000), flagEffect: .nzcv)
        #expect(LSSemanticChecker.verify(d)?.field == "flagEffect")
    }

    @Test func verifyFlagsWrongCategory() {
        let d = mutated(decode(0xF940_0000), category: .dataProcessingRegister)
        #expect(LSSemanticChecker.verify(d)?.field == "category")
    }

    @Test func verifyFlagsWrongMemoryAccess() {
        let d = mutated(decode(0xF940_0000), memoryAccess: .store)
        #expect(LSSemanticChecker.verify(d)?.field == "memoryAccess")
    }

    @Test func verifyFlagsWrongMemoryOrdering() {
        let d = mutated(decode(0xF940_0000), memoryOrdering: .acquire)
        #expect(LSSemanticChecker.verify(d)?.field == "memoryOrdering")
    }

    @Test func verifyFlagsWrongOperandShape() {
        // ldr expects [.register, .memory].
        let d = mutated(decode(0xF940_0000), operands: [.register(.x(0))])
        #expect(LSSemanticChecker.verify(d)?.field == "operandShape")
    }

    @Test func verifyFlagsWrongSemanticReads() {
        let d = mutated(decode(0xF940_0000), semanticReads: .empty)
        #expect(LSSemanticChecker.verify(d)?.field == "semanticReads")
    }

    @Test func verifyFlagsWrongSemanticWrites() {
        let d = mutated(decode(0xF940_0000), semanticWrites: RegisterSet.empty.inserting(.x(9)))
        #expect(LSSemanticChecker.verify(d)?.field == "semanticWrites")
    }

    @Test func operandShapeMismatchHandlesUnexpectedOperandKinds() {
        // An operand kind L/S never produces (`.label`) collapses to the
        // catch-all bucket, surfacing as an operandShape mismatch.
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: .ldr,
            semanticReads: .empty, semanticWrites: .empty,
            branchClass: .none, memoryAccess: .load, memoryOrdering: [],
            flagEffect: .none, category: .loadsAndStores,
            operands: [.register(.x(0)), .label(byteOffset: 0)],
        )
        #expect(LSSemanticChecker.verify(d)?.field == "operandShape")
    }

    @Test func operandShapeMismatchHandlesImmediateOperands() {
        for op: Operand in [.immediate(value: 0, width: 12), .unsignedImmediate(value: 0, width: 12)] {
            let d = Instruction(
                address: 0, encoding: 0, mnemonic: .ldr,
                semanticReads: .empty, semanticWrites: .empty,
                branchClass: .none, memoryAccess: .load, memoryOrdering: [],
                flagEffect: .none, category: .loadsAndStores,
                operands: [.register(.x(0)), op],
            )
            #expect(LSSemanticChecker.verify(d)?.field == "operandShape")
        }
    }

    @Test func semanticIssueInitStoresEveryField() {
        let issue = LSSemanticIssue(field: "memoryAccess", actual: "store", expected: "load")
        #expect(issue.field == "memoryAccess")
        #expect(issue.actual == "store")
        #expect(issue.expected == "load")
    }

    @Test func expectedReadMaskIsNilWhenMemoryOperandMissingForEveryAccessKind() {
        // A draft missing its memory operand exercises the defensive guard
        // in `expectedReadMask` for every access classification — store,
        // exclusive-store, exclusive-load, atomic, and prefetch must each
        // degrade to `nil` rather than crash.
        let noMemory: [Operand] = [.register(.x(0))]
        for m: Mnemonic in [.str, .stxr, .ldxr, .cas, .ldadd, .prfm] {
            let d = Instruction(
                address: 0, encoding: 0, mnemonic: m,
                category: .loadsAndStores, operands: noMemory,
            )
            #expect(LSSemanticAttributes.expectedReadMask(for: d) == nil)
        }
    }

    @Test func expectedWriteMaskIsNilWhenMemoryOperandMissing() {
        // The store and exclusive-load write-mask derivations guard on the
        // presence of a memory operand.
        let noMemory: [Operand] = [.register(.x(0))]
        for m: Mnemonic in [.str, .ldxr] {
            let d = Instruction(
                address: 0, encoding: 0, mnemonic: m,
                category: .loadsAndStores, operands: noMemory,
            )
            #expect(LSSemanticAttributes.expectedWriteMask(for: d) == nil)
        }
    }

    @Test func storeWritebackToZeroBaseWritesNothing() {
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: .str,
            category: .loadsAndStores,
            operands: [
                .register(.w(0)),
                .memory(MemoryOperand(base: .register(.xzr()), writeback: .preIndex)),
            ],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: d) == 0)
    }

    @Test func expectedWriteMaskIsNilWhenRegisterOperandsMissing() {
        // Exclusive-store and the CAS family read operand[0]; an empty
        // operand list leaves no register to derive the write mask from.
        let stxrEmpty = Instruction(
            address: 0, encoding: 0, mnemonic: .stxr,
            category: .loadsAndStores, operands: [],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: stxrEmpty) == nil)

        let casEmpty = Instruction(
            address: 0, encoding: 0, mnemonic: .cas,
            category: .loadsAndStores, operands: [],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: casEmpty) == nil)

        // An LSE RMW base form writes operand[1]; a one-operand list is
        // too short to derive the write mask.
        let ldaddShort = Instruction(
            address: 0, encoding: 0, mnemonic: .ldadd,
            category: .loadsAndStores, operands: [.register(.x(0))],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: ldaddShort) == nil)
    }

    @Test func everyMnemonicMemoryAccessMatchesAnIndependentClassification() {
        // The implementation buckets LSE / ST-alias / CAS by raw-value
        // ranges; this asserts the result against a name-derived
        // classification for all 249 mnemonics, so the two independent
        // derivations must agree — a range boundary error cannot pass.
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(
                LSSemanticAttributes.expectedMemoryAccess(for: mnemonic) == independentAccess(forName: name),
                "\(name): memoryAccess mismatch vs independent classification",
            )
        }
    }

    @Test func verifyAgreesWithTheDecoderAcrossTheV9ExtensionFamilies() {
        // One decoded word per v9.x extension class — LSE128 pair atomics
        // (all four ordering slots), LSUI unprivileged atomics + ST-aliases
        // + exclusives + CAS/CASP, RCW read-check-write forms, MOPS
        // copy/set stages, LS64 64-byte transfers, RCPC3 ordered pairs,
        // GCS stores, and RPRFM. `verify` drives the access / ordering /
        // shape / read / write tables against the decoder's own output.
        let words: [UInt32] = [
            0x1922_1061, 0x19A2_1061, 0x1962_1061, 0x19E2_1061, // ldclrp/a/l/al
            0x1922_8061, // swpp
            0x1921_0462, 0x19A1_0462, 0x1961_0462, 0x19E1_0462, // ldtadd/a/l/al
            0x1921_8462, // swpt
            0x1921_047F, 0x1961_047F, // sttadd / sttaddl
            0x8901_0062, 0x8901_8062, // sttxr / stltxr
            0x895F_0062, 0x895F_8062, // ldtxr / ldatxr
            0xC981_0062, 0xC9C1_0062, 0xC981_8062, 0xC9C1_8062, // cast/casat/caslt/casalt
            0x4982_0080, 0x49C2_0080, 0x4982_8080, 0x49C2_8080, // caspt/caspat/casplt/caspalt
            0x3821_9062, 0x38A1_9062, 0x3861_9062, 0x38E1_9062, // rcwclr/a/l/al
            0x1921_0862, // rcwcas
            0x1922_0C80, // rcwcasp
            0x1922_9061, 0x5922_B061, // rcwclrp / rcwssetp
            0x1901_0440, 0x19C2_0420, // MOPS cpy / set stages
            0xF83F_D060, 0xF83F_9060, 0xF821_B060, 0xF821_A060, // ld64b/st64b/st64bv/st64bv0
            0xD942_1861, 0x9902_1861, // ldiapp / stilp
            0x9942_0861, 0x9902_0861, // ldiapp / stilp with writeback
            0xD91F_0C41, 0xD91F_1C41, // gcsstr / gcssttr
            0xF8A2_4838, // rprfm pldkeep
        ]
        for word in words {
            let d = decode(word)
            #expect(d.category == .loadsAndStores, "0x\(String(word, radix: 16))")
            let issue = LSSemanticChecker.verify(d)
            #expect(issue == nil, "0x\(String(word, radix: 16)) (\(d.mnemonic.name)): \(String(describing: issue))")
        }
    }

    @Test func v9ExtensionTablesAnswerForMaterializedRecordsWithoutOperands() {
        // The read/write tables guard on the operand list before indexing;
        // records without the expected operands fall to the nil arms.
        for m: Mnemonic in [.ldclrp, .ldtadd, .rcwclr, .st64bv] {
            let bare = Instruction(mnemonic: m, category: .loadsAndStores)
            #expect(LSSemanticAttributes.expectedReadMask(for: bare) == nil, "\(m.name)")
        }
        for m: Mnemonic in [.st64bv, .ldclrp, .ldtadd, .rcwclrp] {
            let bare = Instruction(mnemonic: m, category: .loadsAndStores)
            #expect(LSSemanticAttributes.expectedWriteMask(for: bare) == nil, "\(m.name)")
        }
        // The LSUI ST-aliases discard the loaded value — no write, with
        // or without operands.
        let alias = Instruction(mnemonic: .sttadd, category: .loadsAndStores)
        #expect(LSSemanticAttributes.expectedWriteMask(for: alias) == 0)
    }

    @Test func zeroRegisterDestinationsContributeNoWriteBits() {
        // The v9 write tables drop XZR/WZR destinations.
        let mem = Operand.memory(MemoryOperand(base: .register(.x(1))))
        let st64bv = Instruction(
            mnemonic: .st64bv, category: .loadsAndStores,
            operands: [.register(.xzr()), .register(.x(2)), mem],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: st64bv) == 0)
        let ldclrp = Instruction(
            mnemonic: .ldclrp, category: .loadsAndStores,
            operands: [.register(.xzr()), .register(.x(2)), mem],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: ldclrp) == 0)
        let ldtadd = Instruction(
            mnemonic: .ldtadd, category: .loadsAndStores,
            operands: [.register(.x(2)), .register(.wzr()), mem],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: ldtadd) == 0)
        let rcwclrp = Instruction(
            mnemonic: .rcwclrp, category: .loadsAndStores,
            operands: [.register(.xzr()), .register(.x(2)), mem],
        )
        #expect(LSSemanticAttributes.expectedWriteMask(for: rcwclrp) == 0)
    }

    @Test func everyMnemonicMemoryOrderingMatchesAnIndependentClassification() {
        // The implementation derives LSE / CAS ordering by raw-value
        // modulo; this checks every mnemonic against a suffix-string
        // derivation, pinning the range boundaries (swpalh, stadd,
        // stuminlh, casalh, caspal) the spot-checks alone leave loose.
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(
                LSSemanticAttributes.expectedMemoryOrdering(for: mnemonic) == independentOrdering(forName: name),
                "\(name): memoryOrdering mismatch vs independent classification",
            )
        }
    }

    @Test func everyMnemonicOperandShapeMatchesAnIndependentClassification() {
        for (mnemonic, _, name) in LSMnemonicConstantsTests.allLSMnemonics {
            #expect(
                LSSemanticAttributes.expectedOperandShape(for: mnemonic) == independentShape(forName: name),
                "\(name): operandShape mismatch vs independent classification",
            )
        }
    }
}
