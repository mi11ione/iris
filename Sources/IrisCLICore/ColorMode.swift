// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// `--color` policy: when the listing is allowed to emit ANSI escapes.
@frozen
public enum ColorMode: String, Sendable, Hashable, CaseIterable {
    /// Color when standard output is a terminal.
    case auto
    /// Color unconditionally.
    case always
    /// Plain text unconditionally.
    case never

    /// Resolve the policy against the actual output destination.
    @inlinable
    public func resolved(standardOutputIsTTY: Bool) -> Bool {
        switch self {
        case .auto: standardOutputIsTTY
        case .always: true
        case .never: false
        }
    }
}

/// The listing's ANSI palette, one method per role.
@frozen
public struct Palette: Sendable {
    /// Whether escapes are emitted.
    public let enabled: Bool

    @inlinable
    public init(enabled: Bool) {
        self.enabled = enabled
    }

    @usableFromInline
    func wrap(_ text: String, in code: String) -> String {
        guard enabled, !text.isEmpty else { return text }
        return "\u{1B}[\(code)m\(text)\u{1B}[0m"
    }

    /// Function labels and section headers.
    @inlinable
    public func label(_ text: String) -> String {
        wrap(text, in: "1")
    }

    /// Instruction mnemonics: cyan.
    @inlinable
    public func mnemonic(_ text: String) -> String {
        wrap(text, in: "36")
    }

    /// Data directives (`.long`, `.byte`).
    @inlinable
    public func data(_ text: String) -> String {
        wrap(text, in: "33")
    }

    /// Annotations (everything after `;`).
    @inlinable
    public func annotation(_ text: String) -> String {
        wrap(text, in: "90")
    }

    /// Address column: dim.
    @inlinable
    public func address(_ text: String) -> String {
        wrap(text, in: "2")
    }
}
