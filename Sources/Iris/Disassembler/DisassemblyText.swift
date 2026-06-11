// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The unified text path. `Instruction.text` routes here; the router
// owns the sentinel renderings (`.long` for undefined/data words,
// `.byte` for truncated tails) and dispatches decoded categories to the
// per-family canonicalizers. Also home of `normalizeDisassembly`, the
// public diff-normalization seam.

/// Internal text router: one rendering per record, total over every
/// category. Family categories dispatch to their canonicalizer; the
/// sentinel categories render directives.
enum DisassemblyText {
    static func render(_ instruction: Instruction) -> String {
        switch instruction.record.category {
        case .undefined, .dataInCodeMarker:
            // Raw word as a data directive — lowercase, unpadded hex,
            // matching the shipped AMX-unknown `.long` convention. The
            // data-marker's span kind lives on the stream's span list
            // and diagnostics, not in the per-word text.
            return ".long 0x\(String(instruction.record.encoding, radix: 16))"
        case .truncatedTail:
            // Exactly tailByteCount residual bytes, two-digit lowercase
            // hex each (the byte-directive convention). The packed
            // encoding holds at most 4 bytes; hand-built counts beyond
            // that clamp to what the word carries.
            let count = min(instruction.record.tailByteCount, 4)
            if count == 0 { return ".byte" }
            var parts: [String] = []
            parts.reserveCapacity(count)
            for k in 0 ..< count {
                let byte = UInt8(truncatingIfNeeded: instruction.record.encoding >> (8 * UInt32(k)))
                let hex = String(byte, radix: 16)
                parts.append(byte < 0x10 ? "0x0\(hex)" : "0x\(hex)")
            }
            return ".byte " + parts.joined(separator: ", ")
        case .dataProcessingImmediate:
            return DPICanonicalizer.format(instruction)
        case .branchesExceptionSystem:
            return BESCanonicalizer.format(instruction)
        case .dataProcessingRegister:
            return DPRCanonicalizer.format(instruction)
        case .loadsAndStores:
            return LSCanonicalizer.format(instruction)
        case .simdAndFP:
            return SIMDFPCanonicalizer.format(instruction)
        case .pointerAuthentication, .crypto, .amx, .memoryTagging:
            return CryptoAppleExtensionsCanonicalizer.format(instruction)
        }
    }
}

/// Normalize ARM disassembly text to a canonical form suitable for diffing
/// (lowercased, single space between tokens, ARM-style `;` comments stripped,
/// leading and trailing whitespace removed). Output is content-equal to
/// ``Instruction/text``'s convention, so both sides of an
/// `Iris vs other-tool` comparison reduce to the same form.
@inlinable
@_effects(readonly)
public func normalizeDisassembly(_ s: String) -> String {
    var t = s
    if let semi = t.firstIndex(of: ";") {
        t = String(t[..<semi])
    }
    t = t.lowercased()
    return t.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
}
