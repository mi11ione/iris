// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum RegisterNames {
    /// Append `reg`'s canonical text.
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

/// Append a mnemonic's canonical spelling.
@inline(__always)
func putMnemonic(_ m: Mnemonic, into out: inout TextBytes) {
    if let bytes = m.nameBytes {
        out.put(bytes)
        return
    }
    out.put(UInt8(ascii: "?"))
    out.putDecimal(UInt64(m.rawValue))
}
