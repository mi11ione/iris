// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Routes an SVE-category instruction to its region canonicalizer, mirroring
/// ``SVEDecoder``'s dispatch over the same encoding predicates.
enum SVEDisassembly {
    static func render(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined {
            putLong(instruction.encoding, into: &out)
            return
        }
        let e = instruction.encoding
        if isSVEPredicateControlEncoding(e) {
            SVEPredicateControlCanonicalizer.format(instruction, into: &out)
            return
        }
        if isSVEIntegerEncoding(e) {
            SVEIntegerCanonicalizer.format(instruction, into: &out)
            return
        }
        if isSVEFloatingPointEncoding(e) {
            SVEFloatingPointCanonicalizer.format(instruction, into: &out)
            return
        }
        if isSVEPermuteMemoryCryptoEncoding(e) {
            SVEPermuteMemoryCanonicalizer.format(instruction, into: &out)
            return
        }
        if isSVECounterPredicateEncoding(e) {
            SME2Canonicalizer.format(instruction, into: &out)
            return
        }
        putLong(e, into: &out)
    }

    /// The `.long 0x<hex>` data directive, matching the base UNDEFINED
    /// convention the text router uses for an unallocated word.
    static func putLong(_ encoding: UInt32, into out: inout TextBytes) {
        out.put(".long 0x")
        out.putHex(UInt64(encoding))
    }
}

/// Routes an SME-category instruction to the SME-core or SME2 canonicalizer,
/// mirroring ``SMEDecoder``'s core/complement partition.
enum SMEDisassembly {
    static func render(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined {
            SVEDisassembly.putLong(instruction.encoding, into: &out)
            return
        }
        if isSMECoreEncoding(instruction.encoding) {
            SMECanonicalizer.format(instruction, into: &out)
        } else {
            SME2Canonicalizer.format(instruction, into: &out)
        }
    }
}
