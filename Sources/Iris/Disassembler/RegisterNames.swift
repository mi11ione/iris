// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Register-operand text on the byte path.
//
// ``RegisterRef/name`` builds a `String`: an interpolation of the register
// index runs `DefaultStringInterpolation` plus the standard library's
// generic integer-to-ASCII radix conversion, then constructs a `String`
// that the byte path immediately copies out and throws away. A register
// operand appears about twice per instruction, so that was the largest
// remaining per-token cost in the text layer once the intermediates were
// gone.
//
// Nothing here builds a `String` at all. The prefix is a literal and the
// index goes through ``TextBytes/putDecimal(_:)``, which writes digits
// straight into the buffer, so a register name costs a store per byte.
//
// The ordinary `x0`–`x30` / `w0`–`w30` case is tested FIRST. `name` leads
// with five index-31 special cases, so every ordinary register was matched
// against all of them before reaching its own branch.

enum RegisterNames {
    /// Append `reg`'s canonical text. Byte-for-byte identical to
    /// ``RegisterRef/name``, which stays the published `String` form.
    @inline(__always)
    static func put(_ reg: RegisterRef, into out: inout TextBytes) {
        let index = reg.canonicalIndex
        if index < 31 {
            out.put(reg.width == .x64 ? "x" : "w")
            out.putDecimal(UInt64(index))
            return
        }
        if index == 31 {
            switch reg.role {
            case .stackPointer:
                out.put(reg.width == .x64 ? "sp" : "wsp")
            case .zeroRegister, .general:
                // A bare index-31 general register is the zero register in
                // every operand position the decoders emit.
                out.put(reg.width == .x64 ? "xzr" : "wzr")
            }
            return
        }
        if index < 64 {
            out.put(UInt8(ascii: "v"))
            out.putDecimal(UInt64(index &- 32))
            return
        }
        out.put(UInt8(ascii: "?"))
        out.putDecimal(UInt64(index))
    }
}

/// Append a mnemonic's canonical spelling. Takes the compile-time literal
/// where the raw value names one, and falls back to the `?<raw>` sentinel
/// otherwise — the same text ``Mnemonic/name`` produces.
@inline(__always)
func putMnemonic(_ m: Mnemonic, into out: inout TextBytes) {
    if let bytes = m.nameBytes {
        out.put(bytes)
        return
    }
    out.put(UInt8(ascii: "?"))
    out.putDecimal(UInt64(m.rawValue))
}
