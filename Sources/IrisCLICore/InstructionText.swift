// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Text helpers shared by the listing, JSON, and direct-decode paths.
public enum InstructionText {
    /// Lowercase hex with `0x` prefix.
    @inlinable
    public static func hex(_ value: UInt64) -> String {
        "0x" + String(value, radix: 16)
    }

    /// The mnemonic token of a rendered instruction.
    public static func mnemonicToken(of text: String) -> Substring {
        text.prefix { $0 != " " }
    }

    /// The canonical text with a direct branch's relative `#offset` label
    /// rewritten to its absolute target (`bl #0x40` at 0x1000 → `bl 0x1040`).
    public static func absoluteBranchText(_ instruction: Instruction) -> String {
        guard let target = instruction.branchTarget else { return instruction.text }
        let text = instruction.text
        guard let hashIndex = text.lastIndex(of: "#") else { return text }
        return text[..<hashIndex] + hex(target)
    }

    /// A C string rendered for a listing comment.
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

    /// Split a rendered instruction into per-operand fragments.
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
