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
    /// The scratch size the returning entry point renders into.
    ///
    /// Every instruction in the decode corpora renders to at most 66 bytes,
    /// and 99.99% of them to 64 or fewer, so this is one cache line of
    /// stack for effectively the whole ISA. The dozen scalable
    /// multi-vector forms above it promote to the heap inside ``TextBytes``
    /// and render in full — the buffer never truncates.
    static let scratchCapacity = 64

    static func render(_ instruction: Instruction) -> String {
        withUnsafeTemporaryAllocation(of: UInt8.self, capacity: scratchCapacity) { scratch in
            var out = TextBytes(scratch: scratch.baseAddress!, capacity: scratch.count)
            renderBytes(instruction, into: &out)
            return out.makeString()
        }
    }

    /// Render straight into a UTF-8 buffer. Families that have a byte path
    /// write into `out` directly; the rest still build a `String` and are
    /// appended, so the path is adopted one family at a time.
    static func renderBytes(_ instruction: Instruction, into out: inout TextBytes) {
        switch instruction.record.category {
        case .undefined, .dataInCodeMarker:
            // Raw word as a data directive — lowercase, unpadded hex,
            // matching the shipped AMX-unknown `.long` convention. The
            // data-marker's span kind lives on the stream's span list
            // and diagnostics, not in the per-word text.
            out.put(".long 0x")
            out.putHex(UInt64(instruction.record.encoding))
        case .truncatedTail:
            // Exactly tailByteCount residual bytes, two-digit lowercase
            // hex each (the byte-directive convention). The packed
            // encoding holds at most 4 bytes; hand-built counts beyond
            // that clamp to what the word carries.
            let count = min(instruction.record.tailByteCount, 4)
            if count == 0 {
                out.put(".byte")
                return
            }
            out.put(".byte ")
            for k in 0 ..< count {
                if k > 0 { out.put(", ") }
                let byte = UInt8(truncatingIfNeeded: instruction.record.encoding >> (8 * UInt32(k)))
                out.put("0x")
                if byte < 0x10 { out.put(UInt8(ascii: "0")) }
                out.putHex(UInt64(byte))
            }
        case .dataProcessingImmediate:
            DPICanonicalizer.format(instruction, into: &out)
        case .branchesExceptionSystem:
            BESCanonicalizer.format(instruction, into: &out)
        case .dataProcessingRegister:
            DPRCanonicalizer.format(instruction, into: &out)
        case .loadsAndStores:
            LSCanonicalizer.format(instruction, into: &out)
        case .simdAndFP:
            SIMDFPCanonicalizer.format(instruction, into: &out)
        case .pointerAuthentication, .crypto, .amx, .memoryTagging:
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
        case .sve:
            SVEDisassembly.render(instruction, into: &out)
        case .sme:
            SMEDisassembly.render(instruction, into: &out)
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

public extension Instruction {
    /// Append this instruction's canonical text to `out`, with no
    /// intermediate `String`.
    ///
    /// ``text`` renders through the same path and then constructs a
    /// `String`; a caller assembling a larger document — a listing line,
    /// a whole section — wants the bytes appended to the buffer it is
    /// already building instead.
    func appendText(to out: inout TextBytes) {
        DisassemblyText.renderBytes(self, into: &out)
    }
}
