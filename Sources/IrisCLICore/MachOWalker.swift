// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The CLI's deliberately minimal Mach-O walker. Purpose-built for one
// consumer (the `iris` listing) and never public package API (Vision
// §4.8: the walker stays internal to the CLI; a Mach-O library is a
// different product). Parsing patterns and constants are copied-and-
// trimmed from Aperture's MachO/ tree (Header, FatHeaderParser,
// SliceSelection, SymbolTable, FunctionStartsAddresses,
// DataInCodeRegions), cut down to exactly the load commands the listing
// consumes. Every read is bounds-checked: regions are validated once
// against the slice, then read through guards that degrade (with a
// diagnostic, or via the same skip a by-design rejection takes) if a
// bounds proof ever regresses — no force-unwraps on the read path;
// malformed input degrades with a WalkerDiagnostic, never a crash.

import Iris

/// Walks a Mach-O file (thin or fat) into a ``WalkedBinary``.
public enum MachOWalker {
    // Magics, commands, and field constants (values from <mach-o/loader.h>,
    // <mach-o/fat.h>, <mach-o/nlist.h>; named as in Aperture's MachOConstants).
    static let magic64: UInt32 = 0xFEED_FACF
    static let cigam64: UInt32 = 0xCFFA_EDFE
    static let fatMagic: UInt32 = 0xCAFE_BABE
    static let fatCigam: UInt32 = 0xBEBA_FECA
    static let fatMagic64: UInt32 = 0xCAFE_BABF
    static let fatCigam64: UInt32 = 0xBFBA_FECA
    static let machHeader64Size = 32
    static let mhObject: UInt32 = 0x1
    static let lcSegment64: UInt32 = 0x19
    static let lcSymtab: UInt32 = 0x2
    static let lcDysymtab: UInt32 = 0xB
    static let lcFunctionStarts: UInt32 = 0x26
    static let lcDataInCode: UInt32 = 0x29
    static let segmentCommand64Size = 72
    static let section64Size = 80
    static let nlist64Size = 16
    static let dataInCodeEntrySize = 8
    static let sAttrPureInstructions: UInt32 = 0x8000_0000
    static let sAttrSomeInstructions: UInt32 = 0x0000_0400
    // section_64.flags low byte = section type. S_SYMBOL_STUBS marks the
    // `__stubs`/`__auth_stubs` slabs whose entries each forward to an
    // imported symbol via the indirect symbol table.
    static let sSymbolStubs: UInt8 = 0x8
    static let sZerofill: UInt8 = 0x1
    static let sGBZerofill: UInt8 = 0xC
    static let sThreadLocalZerofill: UInt8 = 0x12
    static let nStab: UInt8 = 0xE0
    static let nTypeMask: UInt8 = 0x0E
    static let nSect: UInt8 = 0xE
    static let nAbs: UInt8 = 0x2
    static let nExt: UInt8 = 0x01
    // Indirect-symbol-table sentinels: an entry equal to either (or their
    // union) names no symbol (a local/absolute pointer), so its stub slot
    // carries no import.
    static let indirectSymbolLocal: UInt32 = 0x8000_0000
    static let indirectSymbolAbs: UInt32 = 0x4000_0000

    /// Open `path`, select the requested (or best) slice, and walk it.
    public static func walk(path: String, arch: ArchSelection?) -> WalkOutcome {
        guard let file = MappedFile(path: path) else {
            return .unreadable(detail: "cannot open or map '\(path)'")
        }
        guard let magicRaw: UInt32 = file.read(at: 0) else {
            return .notMachO(detail: "'\(path)' is shorter than 4 bytes")
        }
        switch magicRaw {
        case fatMagic, fatCigam:
            return walkFat(file: file, swapped: magicRaw == fatCigam, is64: false, arch: arch)
        case fatMagic64, fatCigam64:
            return walkFat(file: file, swapped: magicRaw == fatCigam64, is64: true, arch: arch)
        case magic64, cigam64:
            return walkThin(file: file, swapped: magicRaw == cigam64, arch: arch)
        default:
            return .notMachO(detail: "'\(path)' has no Mach-O or fat magic (first word 0x\(hex32(magicRaw)))")
        }
    }

    /// One `fat_arch` record, decoded host-order, with its windowed view
    /// (`nil` when the declared byte range does not fit the file — the
    /// one source of truth for slice eligibility).
    struct FatSlice {
        let cputype: Int32
        let cpusubtype: Int32
        let offset: UInt64
        let size: UInt64
        let window: MappedFile?

        var name: String {
            ArchitectureName.name(cputype: cputype, cpusubtype: cpusubtype)
        }

        var selection: ArchSelection? {
            ArchitectureName.selection(cputype: cputype, cpusubtype: cpusubtype)
        }
    }

    /// Fat path: enumerate `fat_arch` records, select per policy, walk
    /// the chosen slice through the thin path.
    static func walkFat(file: MappedFile, swapped: Bool, is64: Bool, arch: ArchSelection?) -> WalkOutcome {
        guard let nfatRaw: UInt32 = file.read(at: 4) else {
            return .notMachO(detail: "fat header truncated (no nfat_arch)")
        }
        let nfat = swapped ? nfatRaw.byteSwapped : nfatRaw
        guard nfat > 0 else {
            return .notMachO(detail: "fat header declares zero architectures")
        }
        let archSize = is64 ? 32 : 20
        var diagnostics: [WalkerDiagnostic] = []
        var slices: [FatSlice] = []
        slices.reserveCapacity(Int(nfat))
        for i in 0 ..< Int(nfat) {
            let base = 8 + i * archSize
            guard let slice = readFatArch(file: file, at: base, swapped: swapped, is64: is64) else {
                return .notMachO(detail: "fat arch table truncated (entry \(i) of \(nfat) past end of file)")
            }
            if slice.window == nil {
                diagnostics.append(WalkerDiagnostic(
                    kind: .fatSliceOutOfBounds,
                    detail: "slice \(i) (\(slice.name)) [\(slice.offset), +\(slice.size)) exceeds file size \(file.size); excluded",
                ))
            }
            slices.append(slice)
        }

        guard let window = selectSlice(from: slices, arch: arch) else {
            // Distinguish "the architecture is not in the container" from
            // "the matching slice is declared but its bytes are out of
            // range" (a truncated fat) — the same nil selection, different
            // cause and different fix.
            let excludedMatch = slices.first { matchesSelection($0, arch: arch) && $0.window == nil }
            if let excludedMatch {
                return .notMachO(detail: "\(excludedMatch.name) slice's content [\(excludedMatch.offset), +\(excludedMatch.size)) is out of range for the \(file.size)-byte file (truncated fat binary)")
            }
            return .archUnavailable(requested: arch, available: slices.map(\.name))
        }
        guard let sliceMagic: UInt32 = window.file.read(at: 0) else {
            return .notMachO(detail: "selected \(window.name) slice is shorter than 4 bytes")
        }
        switch sliceMagic {
        case magic64, cigam64:
            return walkThin(
                file: window.file,
                swapped: sliceMagic == cigam64,
                arch: arch,
                leadingDiagnostics: diagnostics,
            )
        default:
            return .notMachO(detail: "selected \(window.name) slice is not a 64-bit Mach-O (first word 0x\(hex32(sliceMagic)))")
        }
    }

    /// Decode one `fat_arch` / `fat_arch_64` record; `nil` when the
    /// record itself is past the end of the file.
    static func readFatArch(file: MappedFile, at base: Int, swapped: Bool, is64: Bool) -> FatSlice? {
        guard let cputypeRaw: UInt32 = file.read(at: base),
              let cpusubtypeRaw: UInt32 = file.read(at: base + 4)
        else { return nil }
        let offset: UInt64
        let size: UInt64
        if is64 {
            guard let offsetRaw: UInt64 = file.read(at: base + 8),
                  let sizeRaw: UInt64 = file.read(at: base + 16)
            else { return nil }
            offset = swapped ? offsetRaw.byteSwapped : offsetRaw
            size = swapped ? sizeRaw.byteSwapped : sizeRaw
        } else {
            guard let offsetRaw: UInt32 = file.read(at: base + 8),
                  let sizeRaw: UInt32 = file.read(at: base + 12)
            else { return nil }
            offset = UInt64(swapped ? offsetRaw.byteSwapped : offsetRaw)
            size = UInt64(swapped ? sizeRaw.byteSwapped : sizeRaw)
        }
        // subFile is the eligibility decision: nil exactly when the
        // declared [offset, offset+size) range does not fit the file
        // (Int(exactly:) rejects ranges past Int.max before conversion).
        let window = Int(exactly: offset).flatMap { o in
            Int(exactly: size).flatMap { s in file.subFile(at: o, length: s) }
        }
        return FatSlice(
            cputype: Int32(bitPattern: swapped ? cputypeRaw.byteSwapped : cputypeRaw),
            cpusubtype: Int32(bitPattern: swapped ? cpusubtypeRaw.byteSwapped : cpusubtypeRaw),
            offset: offset,
            size: size,
            window: window,
        )
    }

    /// Selection policy over eligible (windowed) slices. Explicit `arch`
    /// matches strictly; the default prefers arm64e, then plain arm64,
    /// then any remaining ARM64-cputype slice (an unknown subtype decodes
    /// as base ISA, and its name reveals the oddity).
    static func selectSlice(from slices: [FatSlice], arch: ArchSelection?) -> (name: String, file: MappedFile)? {
        func first(where predicate: (FatSlice) -> Bool) -> (String, MappedFile)? {
            for slice in slices {
                guard let window = slice.window, predicate(slice) else { continue }
                return (slice.name, window)
            }
            return nil
        }
        if let arch {
            return first { $0.selection == arch }
        }
        return first { $0.selection == .arm64e }
            ?? first { $0.selection == .arm64 }
            ?? first { $0.cputype == ArchitectureName.cpuTypeARM64 }
    }

    /// Whether a slice satisfies the selection criteria regardless of
    /// whether its bytes fit — an explicit `arch` matches strictly, the
    /// default accepts any ARM64-cputype slice. Lets the caller tell a
    /// missing architecture apart from a present-but-truncated one.
    static func matchesSelection(_ slice: FatSlice, arch: ArchSelection?) -> Bool {
        if let arch { return slice.selection == arch }
        return slice.cputype == ArchitectureName.cpuTypeARM64
    }

    /// Thin path (also the selected-fat-slice path): parse the
    /// `mach_header_64`, check architecture, walk load commands.
    static func walkThin(
        file: MappedFile,
        swapped: Bool,
        arch: ArchSelection?,
        leadingDiagnostics: [WalkerDiagnostic] = [],
    ) -> WalkOutcome {
        // Header reads are in bounds once size >= 32; a read miss means
        // that proof regressed and degrades to the truncation outcome.
        guard file.size >= machHeader64Size,
              let cputypeRaw = u32(file, 4, swapped),
              let cpusubtypeRaw = u32(file, 8, swapped),
              let filetype = u32(file, 12, swapped),
              let ncmds = u32(file, 16, swapped),
              let sizeofcmds = u32(file, 20, swapped)
        else {
            return .notMachO(detail: "mach_header_64 truncated (slice is \(file.size) bytes, header needs \(machHeader64Size))")
        }
        let cputype = Int32(bitPattern: cputypeRaw)
        let cpusubtype = Int32(bitPattern: cpusubtypeRaw)

        let name = ArchitectureName.name(cputype: cputype, cpusubtype: cpusubtype)
        let selection = ArchitectureName.selection(cputype: cputype, cpusubtype: cpusubtype)
        if let arch {
            guard selection == arch else {
                return .archUnavailable(requested: arch, available: [name])
            }
        } else {
            guard cputype == ArchitectureName.cpuTypeARM64 else {
                return .archUnavailable(requested: nil, available: [name])
            }
        }
        let features: Features = selection == .arm64e ? .arm64e : []

        var diagnostics = leadingDiagnostics
        let commands = walkLoadCommands(
            file: file,
            swapped: swapped,
            ncmds: ncmds,
            sizeofcmds: sizeofcmds,
            diagnostics: &diagnostics,
        )

        var sections = collectCodeSections(file: file, segments: commands.segments, diagnostics: &diagnostics)
        rebaseDataInCode(
            file: file,
            command: commands.dataInCode,
            swapped: swapped,
            addressBased: filetype == mhObject,
            sections: &sections,
            diagnostics: &diagnostics,
        )
        let symbols = parseSymbols(file: file, command: commands.symtab, swapped: swapped, diagnostics: &diagnostics)
        let starts = parseFunctionStarts(
            file: file,
            command: commands.functionStarts,
            textBase: commands.textSegmentBase,
            diagnostics: &diagnostics,
        )
        let stubTargets = parseStubTargets(
            file: file,
            symtab: commands.symtab,
            dysymtab: commands.dysymtab,
            segments: commands.segments,
            swapped: swapped,
            diagnostics: &diagnostics,
        )

        return .binary(WalkedBinary(
            path: file.path,
            architecture: name,
            features: features,
            codeSections: sections,
            symbols: symbols,
            functionStarts: starts,
            stubTargets: stubTargets,
            diagnostics: diagnostics,
        ))
    }

    /// Read a host-order `UInt32` at a bounds-proven offset; `nil` only
    /// if the caller's proof regressed (the caller's guard degrades).
    @inline(__always)
    static func u32(_ file: MappedFile, _ offset: Int, _ swapped: Bool) -> UInt32? {
        let raw: UInt32? = file.read(at: offset)
        return raw.map { swapped ? $0.byteSwapped : $0 }
    }

    /// Read a host-order `UInt64` at a bounds-proven offset; `nil` only
    /// if the caller's proof regressed (the caller's guard degrades).
    @inline(__always)
    static func u64(_ file: MappedFile, _ offset: Int, _ swapped: Bool) -> UInt64? {
        let raw: UInt64? = file.read(at: offset)
        return raw.map { swapped ? $0.byteSwapped : $0 }
    }

    /// Raw `segment_command_64` extent plus decoded fields the walk needs.
    struct SegmentRecord {
        let commandStart: Int
        let commandSize: Int
        let segmentName: String
        let vmaddr: UInt64
        let nsects: UInt32
        let swapped: Bool
    }

    /// Decoded body fields of an `LC_SYMTAB` (four fields) or
    /// `linkedit_data_command` (two fields, trailing zeros).
    struct LinkeditRegion {
        let fieldA: UInt32
        let fieldB: UInt32
        let fieldC: UInt32
        let fieldD: UInt32

        init(fieldA: UInt32, fieldB: UInt32, fieldC: UInt32 = 0, fieldD: UInt32 = 0) {
            self.fieldA = fieldA
            self.fieldB = fieldB
            self.fieldC = fieldC
            self.fieldD = fieldD
        }
    }

    /// The load commands the listing consumes, collected in one walk.
    struct CollectedCommands {
        var segments: [SegmentRecord] = []
        var symtab: LinkeditRegion?
        var functionStarts: LinkeditRegion?
        var dataInCode: LinkeditRegion?
        /// `LC_DYSYMTAB`'s indirect-symbol-table window: `fieldA` =
        /// `indirectsymoff`, `fieldB` = `nindirectsyms` (the rest unused).
        var dysymtab: LinkeditRegion?
        var textSegmentBase: UInt64?
    }

    /// Walk `ncmds` load commands from byte 32, stopping (with a
    /// diagnostic) at the first command whose size is invalid or which
    /// runs past the declared region or the slice.
    static func walkLoadCommands(
        file: MappedFile,
        swapped: Bool,
        ncmds: UInt32,
        sizeofcmds: UInt32,
        diagnostics: inout [WalkerDiagnostic],
    ) -> CollectedCommands {
        var collected = CollectedCommands()
        var regionEnd = machHeader64Size + Int(sizeofcmds)
        if regionEnd > file.size {
            diagnostics.append(WalkerDiagnostic(
                kind: .loadCommandRegionTruncated,
                detail: "sizeofcmds \(sizeofcmds) extends to \(regionEnd) but the slice is \(file.size) bytes; walking the in-bounds prefix",
            ))
            regionEnd = file.size
        }
        var cursor = machHeader64Size
        for index in 0 ..< Int(ncmds) {
            // Reads are in bounds once cursor + 8 <= regionEnd <=
            // file.size; a read miss degrades to the same stop.
            guard cursor + 8 <= regionEnd,
                  let cmd = u32(file, cursor, swapped),
                  let cmdsizeRaw = u32(file, cursor + 4, swapped)
            else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "command \(index) of \(ncmds) starts past the load-command region; stopping",
                ))
                break
            }
            let cmdsize = Int(cmdsizeRaw)
            guard cmdsize >= 8, cursor + cmdsize <= regionEnd else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "command \(index) (cmd 0x\(String(cmd, radix: 16))) has cmdsize \(cmdsize) outside [8, region end]; stopping",
                ))
                break
            }
            record(
                cmd: cmd,
                at: cursor,
                size: cmdsize,
                file: file,
                swapped: swapped,
                into: &collected,
                diagnostics: &diagnostics,
            )
            cursor += cmdsize
        }
        return collected
    }

    /// Decode one load command into `collected` when it is one of the
    /// four the listing consumes; anything else is skipped by design
    /// (the walker is minimal, not a Mach-O library). All reads below
    /// are within `[start, start + size)`, which the caller proved is
    /// inside the slice.
    static func record(
        cmd: UInt32,
        at start: Int,
        size: Int,
        file: MappedFile,
        swapped: Bool,
        into collected: inout CollectedCommands,
        diagnostics: inout [WalkerDiagnostic],
    ) {
        switch cmd {
        case lcSegment64:
            guard size >= segmentCommand64Size,
                  let name = file.readFixedString(at: start + 8, length: 16),
                  let vmaddr = u64(file, start + 24, swapped),
                  let nsects = u32(file, start + 64, swapped)
            else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "LC_SEGMENT_64 at \(start) has cmdsize \(size), smaller than its 72-byte header; skipped",
                ))
                return
            }
            collected.segments.append(SegmentRecord(
                commandStart: start,
                commandSize: size,
                segmentName: name,
                vmaddr: vmaddr,
                nsects: nsects,
                swapped: swapped,
            ))
            if name == "__TEXT", collected.textSegmentBase == nil {
                collected.textSegmentBase = vmaddr
            }
        case lcSymtab:
            guard size >= 24,
                  let fieldA = u32(file, start + 8, swapped),
                  let fieldB = u32(file, start + 12, swapped),
                  let fieldC = u32(file, start + 16, swapped),
                  let fieldD = u32(file, start + 20, swapped)
            else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "LC_SYMTAB at \(start) has cmdsize \(size), smaller than its 24-byte struct; skipped",
                ))
                return
            }
            store(
                LinkeditRegion(fieldA: fieldA, fieldB: fieldB, fieldC: fieldC, fieldD: fieldD),
                into: &collected.symtab,
                commandName: "LC_SYMTAB",
                diagnostics: &diagnostics,
            )
        case lcDysymtab:
            // dysymtab_command: 18 UInt32 fields after (cmd, cmdsize).
            // The listing needs only indirectsymoff (+56) and
            // nindirectsyms (+60) for stub symbolication.
            guard size >= 80,
                  let indirectsymoff = u32(file, start + 56, swapped),
                  let nindirectsyms = u32(file, start + 60, swapped)
            else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "LC_DYSYMTAB at \(start) has cmdsize \(size), smaller than its 80-byte struct; skipped",
                ))
                return
            }
            store(
                LinkeditRegion(fieldA: indirectsymoff, fieldB: nindirectsyms),
                into: &collected.dysymtab,
                commandName: "LC_DYSYMTAB",
                diagnostics: &diagnostics,
            )
        case lcFunctionStarts, lcDataInCode:
            let commandName = cmd == lcFunctionStarts ? "LC_FUNCTION_STARTS" : "LC_DATA_IN_CODE"
            guard size >= 16,
                  let fieldA = u32(file, start + 8, swapped),
                  let fieldB = u32(file, start + 12, swapped)
            else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .loadCommandInvalid,
                    detail: "\(commandName) at \(start) has cmdsize \(size), smaller than its 16-byte struct; skipped",
                ))
                return
            }
            let region = LinkeditRegion(fieldA: fieldA, fieldB: fieldB)
            if cmd == lcFunctionStarts {
                store(region, into: &collected.functionStarts, commandName: commandName, diagnostics: &diagnostics)
            } else {
                store(region, into: &collected.dataInCode, commandName: commandName, diagnostics: &diagnostics)
            }
        default:
            return
        }
    }

    /// First-wins storage for expected-once commands, diagnosing extras.
    static func store(
        _ region: LinkeditRegion,
        into slot: inout LinkeditRegion?,
        commandName: String,
        diagnostics: inout [WalkerDiagnostic],
    ) {
        if slot == nil {
            slot = region
        } else {
            diagnostics.append(WalkerDiagnostic(
                kind: .duplicateLoadCommand,
                detail: "more than one \(commandName); using the first",
            ))
        }
    }

    /// Walk every segment's trailing `section_64` array and keep the
    /// executable, file-backed sections, clamped to the slice.
    static func collectCodeSections(
        file: MappedFile,
        segments: [SegmentRecord],
        diagnostics: inout [WalkerDiagnostic],
    ) -> [CodeSection] {
        var sections: [CodeSection] = []
        for segment in segments {
            let budget = (segment.commandSize - segmentCommand64Size) / section64Size
            var nsects = Int(segment.nsects)
            if nsects > budget {
                diagnostics.append(WalkerDiagnostic(
                    kind: .sectionTableTruncated,
                    detail: "segment \(segment.segmentName) declares \(nsects) sections but cmdsize fits \(budget); walking \(budget)",
                ))
                nsects = budget
            }
            for i in 0 ..< nsects {
                // Each section_64 lies inside the segment command's
                // validated extent: start + 72 + (i+1)*80 <= start + cmdsize.
                let base = segment.commandStart + segmentCommand64Size + i * section64Size
                appendIfCode(
                    file: file,
                    sectionBase: base,
                    swapped: segment.swapped,
                    into: &sections,
                    diagnostics: &diagnostics,
                )
            }
        }
        return sections
    }

    /// Decode one `section_64` (proven in bounds by the caller); append
    /// it when its attributes claim instructions and it has file-backed
    /// content, clamping a lying size to the bytes that exist.
    static func appendIfCode(
        file: MappedFile,
        sectionBase: Int,
        swapped: Bool,
        into sections: inout [CodeSection],
        diagnostics: inout [WalkerDiagnostic],
    ) {
        // Reads are inside the caller-proven section_64 extent; a read
        // miss degrades to the same skip a non-code section takes.
        guard let sectname = file.readFixedString(at: sectionBase, length: 16),
              let segname = file.readFixedString(at: sectionBase + 16, length: 16),
              let addr = u64(file, sectionBase + 32, swapped),
              let size = u64(file, sectionBase + 40, swapped),
              let offsetRaw = u32(file, sectionBase + 48, swapped),
              let flags = u32(file, sectionBase + 64, swapped),
              flags & (sAttrPureInstructions | sAttrSomeInstructions) != 0
        else { return }
        let offset = UInt64(offsetRaw)
        let type = UInt8(truncatingIfNeeded: flags)
        guard type != sZerofill, type != sGBZerofill, type != sThreadLocalZerofill else { return }
        let displayName = "\(segname),\(sectname)"
        guard size > 0 else {
            diagnostics.append(WalkerDiagnostic(
                kind: .sectionEmpty,
                detail: "code section \(displayName) declares zero bytes; skipped",
            ))
            return
        }
        let fileSize = UInt64(file.size)
        guard offset < fileSize else {
            diagnostics.append(WalkerDiagnostic(
                kind: .sectionContentOutOfBounds,
                detail: "code section \(displayName) starts at file offset \(offset), past the \(fileSize)-byte slice; skipped",
            ))
            return
        }
        var byteCount = size
        let (end, overflow) = offset.addingReportingOverflow(size)
        if overflow || end > fileSize {
            byteCount = fileSize - offset
            diagnostics.append(WalkerDiagnostic(
                kind: .sectionContentOutOfBounds,
                detail: "code section \(displayName) declares \(size) bytes at file offset \(offset) but the slice holds \(byteCount); clamped",
            ))
        }
        sections.append(CodeSection(
            segmentName: segname,
            sectionName: sectname,
            address: addr,
            fileOffset: offset,
            byteCount: byteCount,
            dataInCode: [],
            slice: file,
        ))
    }

    /// Decode `LC_DATA_IN_CODE` entries and rebase each into the buffer
    /// space of the code section containing it; entries outside every
    /// code section are dropped, straddling entries clamped — each with
    /// a diagnostic.
    ///
    /// Entry-offset semantics differ by filetype (verified against the
    /// fixture corpus): in linked images `data_in_code_entry.offset` is
    /// a file offset from the mach header; in `MH_OBJECT` files the
    /// assembler emits *section-address-space* offsets (there is no
    /// final file layout yet), so `addressBased` switches the rebase
    /// origin from `fileOffset` to `address`.
    static func rebaseDataInCode(
        file: MappedFile,
        command: LinkeditRegion?,
        swapped: Bool,
        addressBased: Bool,
        sections: inout [CodeSection],
        diagnostics: inout [WalkerDiagnostic],
    ) {
        guard let command else { return }
        let dataoff = Int(command.fieldA)
        let datasize = Int(command.fieldB)
        guard datasize > 0 else { return }
        guard dataoff + datasize <= file.size else {
            diagnostics.append(WalkerDiagnostic(
                kind: .dataInCodeRegionOutOfBounds,
                detail: "LC_DATA_IN_CODE region [\(dataoff), +\(datasize)) exceeds the \(file.size)-byte slice; ignored",
            ))
            return
        }
        let entryCount = datasize / dataInCodeEntrySize
        if datasize % dataInCodeEntrySize != 0 {
            diagnostics.append(WalkerDiagnostic(
                kind: .dataInCodeRegionTruncated,
                detail: "LC_DATA_IN_CODE datasize \(datasize) is not a multiple of 8; decoding \(entryCount) whole entries",
            ))
        }
        var spansPerSection: [[DataInCodeSpan]] = Array(repeating: [], count: sections.count)
        for i in 0 ..< entryCount {
            // Entry reads are in bounds (dataoff + entryCount*8 <=
            // dataoff + datasize <= file.size); a read miss degrades to
            // the same skip a zero-length entry takes.
            let base = dataoff + i * dataInCodeEntrySize
            guard let entryOffsetRaw = u32(file, base, swapped),
                  let lengthRaw: UInt16 = file.read(at: base + 4),
                  let kindRaw: UInt16 = file.read(at: base + 6),
                  (swapped ? lengthRaw.byteSwapped : lengthRaw) > 0
            else { continue }
            let entryOffset = UInt64(entryOffsetRaw)
            let entryLength = UInt64(swapped ? lengthRaw.byteSwapped : lengthRaw)
            let kind = DataInCodeSpan.Kind(rawValue: swapped ? kindRaw.byteSwapped : kindRaw)
            let entryEnd = entryOffset &+ entryLength

            var coveredBytes: UInt64 = 0
            for (index, section) in sections.enumerated() {
                let sectionStart = addressBased ? section.address : section.fileOffset
                let sectionEnd = sectionStart &+ section.byteCount
                let interStart = max(entryOffset, sectionStart)
                let interEnd = min(entryEnd, sectionEnd)
                guard interStart < interEnd else { continue }
                spansPerSection[index].append(DataInCodeSpan(
                    offset: interStart &- sectionStart,
                    length: interEnd &- interStart,
                    kind: kind,
                ))
                coveredBytes &+= interEnd &- interStart
            }
            if coveredBytes == 0 {
                diagnostics.append(WalkerDiagnostic(
                    kind: .dataInCodeEntryOutsideCode,
                    detail: "data-in-code entry \(i) [\(entryOffset), +\(entryLength)) lies in no code section; dropped",
                ))
            } else if coveredBytes < entryLength {
                diagnostics.append(WalkerDiagnostic(
                    kind: .dataInCodeEntryClamped,
                    detail: "data-in-code entry \(i) [\(entryOffset), +\(entryLength)) straddles a code-section boundary; kept \(coveredBytes) bytes",
                ))
            }
        }
        for index in sections.indices where !spansPerSection[index].isEmpty {
            let s = sections[index]
            sections[index] = CodeSection(
                segmentName: s.segmentName,
                sectionName: s.sectionName,
                address: s.address,
                fileOffset: s.fileOffset,
                byteCount: s.byteCount,
                dataInCode: spansPerSection[index],
                slice: s.slice,
            )
        }
    }

    /// Decode `LC_SYMTAB`'s `nlist_64` entries into a ``SymbolIndex``:
    /// non-stab, section-defined or absolute, named symbols only.
    /// External symbols are fed to the index ahead of locals so an
    /// address shared by both (e.g. `_main` and the assembler's `ltmp0`
    /// in an object file) labels as the external name.
    static func parseSymbols(
        file: MappedFile,
        command: LinkeditRegion?,
        swapped: Bool,
        diagnostics: inout [WalkerDiagnostic],
    ) -> SymbolIndex {
        guard let command else { return .empty }
        let symoff = Int(command.fieldA)
        let nsyms = Int(command.fieldB)
        let stroff = Int(command.fieldC)
        let strsize = Int(command.fieldD)
        guard nsyms > 0 else { return .empty }
        guard symoff + nsyms * nlist64Size <= file.size else {
            diagnostics.append(WalkerDiagnostic(
                kind: .symbolTableOutOfBounds,
                detail: "LC_SYMTAB symbols [\(symoff), +\(nsyms)·16) exceed the \(file.size)-byte slice; symbols unavailable",
            ))
            return .empty
        }
        guard stroff + strsize <= file.size else {
            diagnostics.append(WalkerDiagnostic(
                kind: .symbolTableOutOfBounds,
                detail: "LC_SYMTAB string table [\(stroff), +\(strsize)) exceeds the \(file.size)-byte slice; symbols unavailable",
            ))
            return .empty
        }

        var externalPairs: [(address: UInt64, name: String)] = []
        var localPairs: [(address: UInt64, name: String)] = []
        for i in 0 ..< nsyms {
            // Entry reads are in bounds (symoff + nsyms*16 <= file.size);
            // a read miss degrades to the same skip a stab entry takes.
            let base = symoff + i * nlist64Size
            guard let nStrx = u32(file, base, swapped),
                  let nType: UInt8 = file.read(at: base + 4),
                  let nValue = u64(file, base + 8, swapped),
                  nType & nStab == 0
            else { continue }
            let typeBits = nType & nTypeMask
            guard typeBits == nSect || typeBits == nAbs else { continue }
            guard nStrx != 0, Int(nStrx) < strsize else {
                if nStrx != 0 {
                    diagnostics.append(WalkerDiagnostic(
                        kind: .symbolNameOutOfBounds,
                        detail: "symbol \(i) n_strx \(nStrx) >= strsize \(strsize); symbol dropped",
                    ))
                }
                continue
            }
            guard let name = file.readCString(at: stroff + Int(nStrx), maxLength: strsize - Int(nStrx)) else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .symbolNameOutOfBounds,
                    detail: "symbol \(i) name at string-table offset \(nStrx) has no terminator; symbol dropped",
                ))
                continue
            }
            guard !name.isEmpty else { continue }
            if nType & nExt != 0 {
                externalPairs.append((nValue, name))
            } else {
                localPairs.append((nValue, name))
            }
        }
        return SymbolIndex(symbols: externalPairs + localPairs)
    }

    /// Resolve every `S_SYMBOL_STUBS` section's entries to their imported
    /// symbol names, keyed by stub VM address — the map the listing uses
    /// to annotate a branch to a stub as `; symbol stub for: _name`.
    ///
    /// A stub section's `reserved1` is its first entry's index into the
    /// indirect symbol table; entry N maps to indirect-symtab slot
    /// `reserved1 + N`, whose value is an index into `LC_SYMTAB`'s
    /// `nlist_64` array (the imported symbol, undefined in this image).
    /// Entries flagged LOCAL/ABS name no symbol and are skipped. Both the
    /// symtab and the indirect table are required; either absent yields an
    /// empty map (a fully-static binary has no stubs). Every read is
    /// bounds-guarded against the slice; a regressed proof drops the one
    /// entry, never crashes.
    static func parseStubTargets(
        file: MappedFile,
        symtab: LinkeditRegion?,
        dysymtab: LinkeditRegion?,
        segments: [SegmentRecord],
        swapped _: Bool,
        diagnostics: inout [WalkerDiagnostic],
    ) -> [UInt64: String] {
        guard let symtab, let dysymtab else { return [:] }
        let symoff = Int(symtab.fieldA)
        let nsyms = Int(symtab.fieldB)
        let stroff = Int(symtab.fieldC)
        let strsize = Int(symtab.fieldD)
        let indirectsymoff = Int(dysymtab.fieldA)
        let nindirectsyms = Int(dysymtab.fieldB)
        guard nindirectsyms > 0, nsyms > 0 else { return [:] }
        guard indirectsymoff + nindirectsyms * 4 <= file.size else {
            diagnostics.append(WalkerDiagnostic(
                kind: .indirectSymbolTableOutOfBounds,
                detail: "LC_DYSYMTAB indirect symbols [\(indirectsymoff), +\(nindirectsyms)·4) exceed the \(file.size)-byte slice; stub symbolication unavailable",
            ))
            return [:]
        }
        // The symtab/string-table bounds gate name lookups; if they don't
        // fit, parseSymbols already diagnosed it, so stay silent here.
        guard symoff + nsyms * nlist64Size <= file.size, stroff + strsize <= file.size else {
            return [:]
        }

        var stubTargets: [UInt64: String] = [:]
        for segment in segments {
            let budget = (segment.commandSize - segmentCommand64Size) / section64Size
            let nsects = min(Int(segment.nsects), budget)
            for i in 0 ..< max(nsects, 0) {
                let base = segment.commandStart + segmentCommand64Size + i * section64Size
                appendStubSection(
                    file: file,
                    sectionBase: base,
                    swapped: segment.swapped,
                    symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize,
                    indirectsymoff: indirectsymoff, nindirectsyms: nindirectsyms,
                    into: &stubTargets,
                )
            }
        }
        return stubTargets
    }

    /// Decode one `section_64` (proven in bounds by the caller); when it
    /// is an `S_SYMBOL_STUBS` section, resolve each entry to its imported
    /// name and record `stubAddress → name`.
    static func appendStubSection(
        file: MappedFile,
        sectionBase: Int,
        swapped: Bool,
        symoff: Int, nsyms: Int, stroff: Int, strsize: Int,
        indirectsymoff: Int, nindirectsyms: Int,
        into stubTargets: inout [UInt64: String],
    ) {
        // Reads lie inside the caller-proven section_64 extent; a miss
        // degrades to the skip a non-stub section takes.
        guard let addr = u64(file, sectionBase + 32, swapped),
              let size = u64(file, sectionBase + 40, swapped),
              let flags = u32(file, sectionBase + 64, swapped),
              let reserved1 = u32(file, sectionBase + 68, swapped),
              let reserved2 = u32(file, sectionBase + 72, swapped),
              UInt8(truncatingIfNeeded: flags) == sSymbolStubs
        else { return }
        let stride = UInt64(reserved2)
        // A zero stub size cannot enumerate entries; nothing to resolve.
        guard stride > 0, size > 0 else { return }
        let entryCount = Int(size / stride)
        let firstIndirect = Int(reserved1)
        for entry in 0 ..< entryCount {
            let indirectSlot = firstIndirect + entry
            guard indirectSlot < nindirectsyms else { break }
            // The slot read lies inside the caller-proven indirect table;
            // LOCAL/ABS slots and out-of-range indices name no symbol and
            // share this skip.
            guard let symbolIndexRaw = u32(file, indirectsymoff + indirectSlot * 4, swapped),
                  symbolIndexRaw & (indirectSymbolLocal | indirectSymbolAbs) == 0,
                  Int(symbolIndexRaw) < nsyms
            else { continue }
            let symbolIndex = Int(symbolIndexRaw)
            guard let name = symbolName(
                file: file, symoff: symoff, index: symbolIndex,
                stroff: stroff, strsize: strsize, swapped: swapped,
            ) else { continue }
            let stubAddress = addr &+ UInt64(entry) &* stride
            stubTargets[stubAddress] = name
        }
    }

    /// The string-table name of the `nlist_64` at `index`, or `nil` when
    /// the entry has no in-bounds, non-empty name. Used to resolve an
    /// indirect-symbol-table slot to its imported symbol.
    static func symbolName(
        file: MappedFile,
        symoff: Int,
        index: Int,
        stroff: Int,
        strsize: Int,
        swapped: Bool,
    ) -> String? {
        // symoff + nsyms*16 <= file.size and index < nsyms (caller-proven).
        let base = symoff + index * nlist64Size
        guard let nStrx = u32(file, base, swapped), nStrx != 0, Int(nStrx) < strsize else { return nil }
        guard let name = file.readCString(at: stroff + Int(nStrx), maxLength: strsize - Int(nStrx)),
              !name.isEmpty
        else { return nil }
        return name
    }

    /// Decode the `LC_FUNCTION_STARTS` ULEB128 delta chain into ascending
    /// VM addresses anchored at the `__TEXT` segment's vmaddr.
    static func parseFunctionStarts(
        file: MappedFile,
        command: LinkeditRegion?,
        textBase: UInt64?,
        diagnostics: inout [WalkerDiagnostic],
    ) -> [UInt64] {
        guard let command else { return [] }
        let dataoff = Int(command.fieldA)
        let datasize = Int(command.fieldB)
        guard datasize > 0 else { return [] }
        guard let textBase else {
            diagnostics.append(WalkerDiagnostic(
                kind: .functionStartsUnanchored,
                detail: "LC_FUNCTION_STARTS present but the slice has no __TEXT segment; ignored",
            ))
            return []
        }
        guard dataoff + datasize <= file.size else {
            diagnostics.append(WalkerDiagnostic(
                kind: .functionStartsOutOfBounds,
                detail: "LC_FUNCTION_STARTS region [\(dataoff), +\(datasize)) exceeds the \(file.size)-byte slice; ignored",
            ))
            return []
        }
        var addresses: [UInt64] = []
        var cumulative = textBase
        var cursor = 0
        while cursor < datasize {
            var delta: UInt64 = 0
            var shift: UInt64 = 0
            var terminated = false
            // Byte reads are in bounds (cursor < datasize and dataoff +
            // datasize <= file.size); a read miss exits the scan into
            // the mid-value arm below.
            while cursor < datasize, let byte: UInt8 = file.read(at: dataoff + cursor) {
                cursor += 1
                if shift >= 64 {
                    diagnostics.append(WalkerDiagnostic(
                        kind: .functionStartsMalformed,
                        detail: "ULEB128 value exceeds 64 bits; keeping the \(addresses.count) addresses decoded so far",
                    ))
                    return addresses
                }
                delta |= UInt64(byte & 0x7F) << shift
                if byte & 0x80 == 0 {
                    terminated = true
                    break
                }
                shift += 7
            }
            guard terminated else {
                diagnostics.append(WalkerDiagnostic(
                    kind: .functionStartsMalformed,
                    detail: "ULEB128 stream ends mid-value; keeping the \(addresses.count) addresses decoded so far",
                ))
                return addresses
            }
            if delta == 0 { return addresses }
            let (sum, overflow) = cumulative.addingReportingOverflow(delta)
            if overflow {
                diagnostics.append(WalkerDiagnostic(
                    kind: .functionStartsMalformed,
                    detail: "cumulative address overflows UInt64; keeping the \(addresses.count) addresses decoded so far",
                ))
                return addresses
            }
            cumulative = sum
            addresses.append(cumulative)
        }
        return addresses
    }

    /// Lowercase 8-digit hex of a 32-bit value.
    static func hex32(_ value: UInt32) -> String {
        let s = String(value, radix: 16)
        return String(repeating: "0", count: 8 - s.count) + s
    }
}
