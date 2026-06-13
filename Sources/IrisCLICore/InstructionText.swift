// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Presentation-layer text utilities over the library's canonical
// rendering. The library's `text` is the one true assembly form (its
// branch labels are relative `#offset`s, oracle-parity); the CLI
// composes absolute targets and per-operand fragments *from* it, never
// re-rendering instructions itself.

import Iris

/// Text helpers shared by the listing, JSON, and direct-decode paths.
public enum InstructionText {
    /// Lowercase hex with `0x` prefix.
    @inlinable
    public static func hex(_ value: UInt64) -> String {
        "0x" + String(value, radix: 16)
    }

    /// Lowercase hex of an instruction word, zero-padded to 8 digits.
    public static func word(_ value: UInt32) -> String {
        let s = String(value, radix: 16)
        return String(repeating: "0", count: 8 - s.count) + s
    }

    /// Lowercase hex of an address, zero-padded to at least `width` digits.
    public static func address(_ value: UInt64, width: Int) -> String {
        let s = String(value, radix: 16)
        guard s.count < width else { return s }
        return String(repeating: "0", count: width - s.count) + s
    }

    /// The mnemonic token of a rendered instruction: everything before
    /// the first space (the whole text for operand-less instructions).
    public static func mnemonicToken(of text: String) -> Substring {
        text.prefix { $0 != " " }
    }

    /// The canonical text with a direct branch's relative `#offset`
    /// label rewritten to its absolute target (`bl #0x40` at 0x1000 →
    /// `bl 0x1040`). Direct-branch encodings place the label last, so
    /// the rewrite replaces the text's final `#`-token; instructions
    /// without a resolved ``Instruction/branchTarget`` pass through
    /// unchanged.
    public static func absoluteBranchText(_ instruction: Instruction) -> String {
        guard let target = instruction.branchTarget else { return instruction.text }
        let text = instruction.text
        guard let hashIndex = text.lastIndex(of: "#") else { return text }
        return text[..<hashIndex] + hex(target)
    }

    /// A C string rendered for a listing comment: wrapped in double
    /// quotes, with the C-style escapes for the characters that would
    /// break a one-line comment (`\`, `"`, the whitespace controls) and
    /// `\x<hh>` for any other non-printing byte, then capped at
    /// `maxScalars` visible source characters with a trailing `…` when it
    /// runs longer. The same shape `otool`'s `"…"` annotation uses, so a
    /// listing reads like the disassemblers an analyst already knows.
    public static func quotedString(_ value: String, maxScalars: Int = 64) -> String {
        var out = "\""
        var emitted = 0
        for scalar in value.unicodeScalars {
            if emitted >= maxScalars {
                out += "…"
                break
            }
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case let s where s.value < 0x20 || s.value == 0x7F:
                let hex = String(s.value, radix: 16)
                out += "\\x" + (hex.count < 2 ? "0" + hex : hex)
            default:
                out.unicodeScalars.append(scalar)
            }
            emitted += 1
        }
        return out + "\""
    }

    /// Split a rendered instruction into per-operand fragments: the
    /// mnemonic token is dropped and the remainder is split on top-level
    /// commas, commas inside `[...]` (memory operands) and `{...}`
    /// (vector register lists) do not split. Derived from the canonical
    /// text, so the fragments can never drift from it.
    public static func operandFragments(of text: String) -> [String] {
        guard let spaceIndex = text.firstIndex(of: " ") else { return [] }
        let operandText = text[text.index(after: spaceIndex)...]
        var fragments: [String] = []
        var current = ""
        var depth = 0
        for character in operandText {
            switch character {
            case "[", "{":
                depth += 1
                current.append(character)
            case "]", "}":
                depth -= 1
                current.append(character)
            case "," where depth == 0:
                fragments.append(current)
                current = ""
            case " " where current.isEmpty:
                continue
            default:
                current.append(character)
            }
        }
        fragments.append(current)
        return fragments
    }
}
