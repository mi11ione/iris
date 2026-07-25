// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Scalable text routing. A record with category `.sve` or `.sme` reaches
// here from the `DisassemblyText` router; this file re-derives the encoding
// region — the same dispatch the SVE/SME decoders use — and hands the
// instruction to that region's canonicalizer. A scalable-tier hole (a
// scalable category with mnemonic `.undefined`) renders as the `.long` data
// directive, matching the base UNDEFINED convention.

/// Routes an SVE-category instruction to its region canonicalizer, mirroring
/// ``SVEDecoder``'s dispatch over the same encoding predicates.
enum SVEDisassembly {
    @_effects(readonly)
    static func render(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined {
            return ".long 0x\(String(instruction.encoding, radix: 16))"
        }
        let e = instruction.encoding
        if isSVEPredicateControlEncoding(e) { return SVEPredicateControlCanonicalizer.format(instruction) }
        if isSVEIntegerEncoding(e) { return SVEIntegerCanonicalizer.format(instruction) }
        if isSVEFloatingPointEncoding(e) { return SVEFloatingPointCanonicalizer.format(instruction) }
        if isSVEPermuteMemoryCryptoEncoding(e) { return SVEPermuteMemoryCanonicalizer.format(instruction) }
        // The predicate-as-counter carve (WHILE→PN, PEXT, PSEL, FIRSTP/LASTP,
        // counter PTRUE/CNTP) decodes through SME2PredicateDecode and carries
        // SME2-range mnemonics, so its text comes from the SME2 canonicalizer.
        if isSVECounterPredicateEncoding(e) { return SME2Canonicalizer.format(instruction) }
        return ".long 0x\(String(e, radix: 16))"
    }
}

/// Routes an SME-category instruction to the SME-core or SME2 canonicalizer,
/// mirroring ``SMEDecoder``'s core/complement partition.
enum SMEDisassembly {
    @_effects(readonly)
    static func render(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined {
            return ".long 0x\(String(instruction.encoding, radix: 16))"
        }
        return isSMECoreEncoding(instruction.encoding)
            ? SMECanonicalizer.format(instruction)
            : SME2Canonicalizer.format(instruction)
    }
}
