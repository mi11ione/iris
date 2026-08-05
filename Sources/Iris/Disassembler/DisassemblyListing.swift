// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Whole-stream rendering: the entry point a disassembler actually wants.
//
// Every canonicalizer renders one record. A consumer producing a listing
// otherwise calls ``Instruction/text`` per instruction and joins the
// results, which pays a `String` construction — and, above the bytes Swift
// keeps inline, a heap allocation — for every record only to copy it into
// a larger buffer and throw it away. Rendering the whole stream through
// one reused UTF-8 buffer pays neither.

/// Canonical disassembly text for a whole ``InstructionStream``.
public enum DisassemblyListing {
    /// One line of canonical text per record, newline-terminated.
    ///
    /// Line *N* is record *N*: each line is exactly what that record's
    /// ``Instruction/text`` returns, so a listing and a per-instruction
    /// render can never disagree. Records whose text is empty contribute
    /// an empty line rather than being skipped.
    ///
    /// The buffer is sized from the corpus mean of roughly twenty bytes of
    /// text and newline per instruction, so a whole code section is
    /// normally rendered without a reallocation, and the per-record
    /// `String` the naive loop builds never exists.
    public static func render(_ stream: InstructionStream) -> String {
        var out = TextBytes(capacity: Swift.max(256, stream.records.count &* 20))
        for index in 0 ..< stream.records.count {
            DisassemblyText.renderBytes(stream[index], into: &out)
            out.put(UInt8(ascii: "\n"))
        }
        return out.makeString()
    }
}
