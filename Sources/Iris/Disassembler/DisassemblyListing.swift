// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical disassembly text for a whole ``InstructionStream``.
public enum DisassemblyListing {
    /// One line of canonical text per record, newline-terminated.
    ///
    /// Line *N* is record *N*, exactly what that record's ``Instruction/text``
    /// returns, so a listing and a per-instruction render can never disagree.
    /// Records whose text is empty contribute an empty line.
    public static func render(_ stream: InstructionStream) -> String {
        var out = TextBytes(capacity: Swift.max(256, stream.records.count &* 20))
        for index in 0 ..< stream.records.count {
            DisassemblyText.renderBytes(stream[index], into: &out)
            out.put(UInt8(ascii: "\n"))
        }
        return out.makeString()
    }
}
