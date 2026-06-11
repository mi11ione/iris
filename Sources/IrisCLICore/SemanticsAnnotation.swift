// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The `--semantics` per-line annotation: a compact, fixed-vocabulary
/// rendering of an instruction's semantic record.
///
/// Tokens appear in a fixed order, each only when non-empty, joined by
/// single spaces:
///
///     reads=x0,x1 writes=x2 flags=r:c,w:nzcv mem=load order=acquire branch=call
///
/// Vocabulary: register names are ``RegisterRef/name`` at architectural
/// width; flags letters are `n`/`z`/`c`/`v` with `r:`/`w:` halves;
/// `mem` is one of `load`, `store`, `atomic`, `exclusive-load`,
/// `exclusive-store`, `prefetch`; `order` is `acquire`, `release`, or
/// `acquire-release`; `branch` is one of `direct`, `indirect`,
/// `conditional`, `call`, `return`, `exception`. An instruction with no
/// semantic effects (a NOP) produces the empty string.
public enum SemanticsAnnotation {
    /// Render the annotation for one instruction; `""` when every
    /// component is empty.
    public static func annotation(for instruction: Instruction) -> String {
        var tokens: [String] = []
        let reads = registerList(instruction.semanticReads)
        if !reads.isEmpty {
            tokens.append("reads=\(reads)")
        }
        let writes = registerList(instruction.semanticWrites)
        if !writes.isEmpty {
            tokens.append("writes=\(writes)")
        }
        let flags = flagsToken(instruction.flagEffect)
        if !flags.isEmpty {
            tokens.append("flags=\(flags)")
        }
        if let memory = memoryName(instruction.memoryAccess) {
            tokens.append("mem=\(memory)")
        }
        if let order = orderingName(instruction.memoryOrdering) {
            tokens.append("order=\(order)")
        }
        if let branch = branchName(instruction.branchClass) {
            tokens.append("branch=\(branch)")
        }
        return tokens.joined(separator: " ")
    }

    /// Comma-joined architectural register names, ascending canonical index.
    public static func registerList(_ set: RegisterSet) -> String {
        set.map(\.name).joined(separator: ",")
    }

    /// `r:<letters>,w:<letters>` with absent halves omitted; `""` for no
    /// flag effect.
    public static func flagsToken(_ effect: FlagEffect) -> String {
        var halves: [String] = []
        let reads = flagLetters(effect.readFlags, reading: true)
        if !reads.isEmpty {
            halves.append("r:\(reads)")
        }
        let writes = flagLetters(effect.writtenFlags, reading: false)
        if !writes.isEmpty {
            halves.append("w:\(writes)")
        }
        return halves.joined(separator: ",")
    }

    /// `n`/`z`/`c`/`v` letters present in one half of a flag effect.
    static func flagLetters(_ effect: FlagEffect, reading: Bool) -> String {
        var letters = ""
        let n: FlagEffect = reading ? .readsN : .writesN
        let z: FlagEffect = reading ? .readsZ : .writesZ
        let c: FlagEffect = reading ? .readsC : .writesC
        let v: FlagEffect = reading ? .readsV : .writesV
        if effect.contains(n) { letters.append("n") }
        if effect.contains(z) { letters.append("z") }
        if effect.contains(c) { letters.append("c") }
        if effect.contains(v) { letters.append("v") }
        return letters
    }

    /// Fixed-vocabulary memory-access name; `nil` for `.none`.
    public static func memoryName(_ access: MemoryAccess) -> String? {
        switch access {
        case .none: nil
        case .load: "load"
        case .store: "store"
        case .atomic: "atomic"
        case .exclusiveLoad: "exclusive-load"
        case .exclusiveStore: "exclusive-store"
        case .prefetch: "prefetch"
        }
    }

    /// Fixed-vocabulary ordering name; `nil` for relaxed (empty) ordering.
    public static func orderingName(_ ordering: MemoryOrdering) -> String? {
        switch (ordering.contains(.acquire), ordering.contains(.release)) {
        case (false, false): nil
        case (true, false): "acquire"
        case (false, true): "release"
        case (true, true): "acquire-release"
        }
    }

    /// Fixed-vocabulary branch-class name; `nil` for `.none`.
    public static func branchName(_ branchClass: BranchClass) -> String? {
        switch branchClass {
        case .none: nil
        case .direct: "direct"
        case .indirect: "indirect"
        case .conditional: "conditional"
        case .call: "call"
        case .return: "return"
        case .exception: "exception"
        }
    }
}
