// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Internal text router.
enum DisassemblyText {
    /// The scratch size the returning entry point renders into.
    static let scratchCapacity = 64

    static func render(_ instruction: Instruction) -> String {
        withUnsafeTemporaryAllocation(of: UInt8.self, capacity: scratchCapacity) { scratch in
            var out = TextBytes(scratch: scratch.baseAddress!, capacity: scratch.count)
            renderBytes(instruction, into: &out)
            return out.makeString()
        }
    }

    /// Render straight into a UTF-8 buffer.
    static func renderBytes(_ instruction: Instruction, into out: inout TextBytes) {
        switch instruction.record.category {
        case .undefined, .dataInCodeMarker:
            out.put(".long 0x")
            out.putHex(UInt64(instruction.record.encoding))
        case .truncatedTail:
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
    /// Append this instruction's canonical text to `out`, with no intermediate
    /// `String`.
    ///
    /// ``text`` renders through the same path and then builds a `String`; a
    /// caller assembling a larger document wants the bytes appended directly.
    func appendText(to out: inout TextBytes) {
        DisassemblyText.renderBytes(self, into: &out)
    }
}
