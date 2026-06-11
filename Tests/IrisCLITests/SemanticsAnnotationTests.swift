// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates the `--semantics` annotation vocabulary: register lists at
/// architectural width, flag letters, memory-access and ordering names,
/// branch classes, and the all-empty case.
@Suite("Semantics annotations")
struct SemanticsAnnotationTests {
    /// Decode one word (arm64e features) and annotate it.
    func annotate(_ word: UInt32) -> String {
        SemanticsAnnotation.annotation(for: decode(word, features: .arm64e))
    }

    @Test func nopHasNoAnnotation() {
        #expect(annotate(0xD503_201F).isEmpty)
    }

    @Test func registerReadsAndWrites() {
        #expect(annotate(0x9100_0421) == "reads=x1 writes=x1") // add x1, x1, #1
        #expect(annotate(0xAA01_03E0) == "reads=x1 writes=x0") // mov x0, x1
    }

    @Test func stackPointerRendersAsSP() {
        #expect(annotate(0xD100_43FF) == "reads=sp writes=sp") // sub sp, sp, #16
    }

    @Test func zeroRegisterNeverAppears() {
        // cmp x0, #0 reads x0, writes xzr (discarded) and NZCV.
        #expect(annotate(0xF100_001F) == "reads=x0 flags=w:nzcv")
    }

    @Test func vectorRegistersUseVNames() {
        #expect(annotate(0x4E28_4820) == "reads=v0,v1 writes=v0") // aese v0.16b, v1.16b
    }

    @Test func memoryAccessVocabulary() {
        #expect(annotate(0xF940_0020).contains("mem=load")) // ldr x0, [x1]
        #expect(annotate(0xF900_0020).contains("mem=store")) // str x0, [x1]
        #expect(annotate(0xC85F_7C20).contains("mem=exclusive-load")) // ldxr x0, [x1]
        #expect(annotate(0xC800_7C41).contains("mem=exclusive-store")) // stxr w0, x1, [x2]
        #expect(annotate(0xF880_0020).contains("mem=prefetch")) // prfum
        #expect(annotate(0xC8E0_FC41).contains("mem=atomic")) // casal x0, x1, [x2]
    }

    @Test func orderingVocabulary() {
        #expect(annotate(0xC8DF_FC20).contains("order=acquire")) // ldar x0, [x1]
        #expect(annotate(0xC89F_FC20).contains("order=release")) // stlr x0, [x1]
        #expect(annotate(0xC8E0_FC41).contains("order=acquire-release")) // casal
        #expect(!annotate(0xF940_0020).contains("order=")) // plain ldr: relaxed
    }

    @Test func branchClassVocabulary() {
        #expect(annotate(0x1400_0001) == "branch=direct") // b #4
        #expect(annotate(0x9400_0001) == "writes=x30 branch=call") // bl #4
        #expect(annotate(0xD61F_0000) == "reads=x0 branch=indirect") // br x0
        #expect(annotate(0xD65F_03C0) == "reads=x30 branch=return") // ret
        #expect(annotate(0x5400_0040) == "flags=r:nzcv branch=conditional") // b.eq
        #expect(annotate(0xD400_0001) == "branch=exception") // svc #0
    }

    @Test func flagLetterVocabulary() {
        #expect(annotate(0xB100_0420) == "reads=x1 writes=x0 flags=w:nzcv") // adds x0, x1, #1
        #expect(annotate(0x9A01_0020) == "reads=x1 writes=x0 flags=r:c") // adc x0, x1, x1
        #expect(annotate(0xFA41_0800) == "reads=x0 flags=r:nzcv,w:nzcv") // ccmp x0, #1, #0, eq
    }

    @Test func conditionalSelectReadsFlags() {
        // csel x0, x1, x2, ne
        let annotation = annotate(0x9A82_1020)
        #expect(annotation == "reads=x1,x2 writes=x0 flags=r:nzcv")
    }

    @Test func registerListJoinsAscending() {
        // stp x29, x30, [sp, #-32]! reads x29,x30,sp writes sp.
        let annotation = annotate(0xA9BE_7BFD)
        #expect(annotation == "reads=x29,x30,sp writes=sp mem=store")
    }

    @Test func vocabularyHelpersCoverEveryCase() {
        #expect(SemanticsAnnotation.memoryName(.none) == nil)
        #expect(SemanticsAnnotation.memoryName(.load) == "load")
        #expect(SemanticsAnnotation.memoryName(.store) == "store")
        #expect(SemanticsAnnotation.memoryName(.atomic) == "atomic")
        #expect(SemanticsAnnotation.memoryName(.exclusiveLoad) == "exclusive-load")
        #expect(SemanticsAnnotation.memoryName(.exclusiveStore) == "exclusive-store")
        #expect(SemanticsAnnotation.memoryName(.prefetch) == "prefetch")
        #expect(SemanticsAnnotation.orderingName([]) == nil)
        #expect(SemanticsAnnotation.orderingName(.acquire) == "acquire")
        #expect(SemanticsAnnotation.orderingName(.release) == "release")
        #expect(SemanticsAnnotation.orderingName([.acquire, .release]) == "acquire-release")
        #expect(SemanticsAnnotation.branchName(.none) == nil)
        #expect(SemanticsAnnotation.branchName(.direct) == "direct")
        #expect(SemanticsAnnotation.branchName(.indirect) == "indirect")
        #expect(SemanticsAnnotation.branchName(.conditional) == "conditional")
        #expect(SemanticsAnnotation.branchName(.call) == "call")
        #expect(SemanticsAnnotation.branchName(.return) == "return")
        #expect(SemanticsAnnotation.branchName(.exception) == "exception")
    }

    @Test func flagsTokenHalves() {
        #expect(SemanticsAnnotation.flagsToken(FlagEffect([])) == "")
        #expect(SemanticsAnnotation.flagsToken(.readsC) == "r:c")
        #expect(SemanticsAnnotation.flagsToken([.writesN, .writesZ, .writesC, .writesV]) == "w:nzcv")
        #expect(SemanticsAnnotation.flagsToken([.readsN, .readsV, .writesZ]) == "r:nv,w:z")
    }
}
