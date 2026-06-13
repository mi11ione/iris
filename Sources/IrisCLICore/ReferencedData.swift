// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// What an address-forming instruction points at, resolved through the
/// binary's data sections and symbols. The listing renders it as a
/// trailing comment (`; "the string"`, `; _data_symbol`, `; __const`)
/// and `--json` carries the structured fields, exactly the way
/// ``BranchSymbolizer`` feeds both the listing's `; symbol` and the
/// `targetSymbol` JSON field.
///
/// Resolution has three tiers, in priority order: a C string when the
/// target lands in a cstring-bearing section, a data symbol when it lands
/// at (or past) a known symbol, then the bare section name. The same
/// `otool`/`llvm-objdump` "literal pool for: …" idea, scoped to the
/// binary's own loader data.
@frozen
public struct ReferencedData: Sendable, Equatable {
    /// The resolved C string at the target (already unescaped source
    /// bytes; the renderer escapes and truncates for display), present
    /// only when the target lands in a cstring-literal section.
    public let string: String?
    /// The data symbol the target resolves to: the name exactly at the
    /// target, or `name+0x<delta>` for a target past a symbol in the same
    /// section. Absent when no symbol names it.
    public let symbol: String?
    /// The containing section's display name (`__TEXT,__cstring`,
    /// `__DATA_CONST,__const`). Always present once a target resolves to
    /// any data section.
    public let section: String

    @inlinable
    public init(string: String?, symbol: String?, section: String) {
        self.string = string
        self.symbol = symbol
        self.section = section
    }
}

/// The printable-character hint for an immediate that falls in the
/// ASCII range. When a value-testing instruction compares a byte against
/// a constant in `0x20`...`0x7e`, the listing appends `; 'c'` and
/// `--json` can carry it, so a reader sees `cmp w0, #65 ; 'A'` instead of
/// reverse-engineering the codepoint. The reasoning two dogfooders did by
/// hand.
public enum CharLiteralHint {
    /// The value-testing comparison and bit-test mnemonics whose immediate
    /// is plausibly a character. Deliberately only the instructions whose
    /// purpose is testing a value against a constant, where a character
    /// reading is the clear intent (`cmp w0, #'A'`). Plain arithmetic and
    /// moves are excluded: a `sub #32` case-conversion or an `add #42`
    /// offset lands in the ASCII range but reads as a number, and
    /// annotating it as a character would be a plausible wrong answer.
    static func isCandidate(_ mnemonic: Mnemonic) -> Bool {
        switch mnemonic {
        case .cmp, .cmn, .ccmp, .ccmn, .tst:
            true
        default:
            false
        }
    }

    /// The printable ASCII character one of `instruction`'s immediates
    /// names, or `nil`. Only the candidate mnemonics are considered, and
    /// only an immediate in `0x20`...`0x7e` (printable, space through
    /// tilde) qualifies. The first qualifying immediate wins.
    ///
    /// An instruction that touches the stack pointer (`add sp, sp, #32`,
    /// `sub sp, sp, #16`) is frame management, never a character
    /// constant, so it is excluded, the space byte `0x20` on `sp` is the
    /// loudest false positive, and `otool`/`llvm-objdump` annotate none of
    /// these.
    public static func character(for instruction: Instruction) -> Character? {
        guard isCandidate(instruction.mnemonic), !touchesStackPointer(instruction) else { return nil }
        for operand in instruction.operands {
            let value: UInt64? = switch operand {
            case let .immediate(immediate, _):
                immediate >= 0 ? UInt64(immediate) : nil
            case let .unsignedImmediate(immediate, _):
                immediate
            default:
                nil
            }
            if let value, (0x20 ... 0x7E).contains(value) {
                return Character(UnicodeScalar(UInt8(value)))
            }
        }
        return nil
    }

    /// Whether any register operand of `instruction` is the stack pointer
    /// (`sp` / `wsp`), the marker of frame arithmetic the character hint
    /// must not annotate.
    static func touchesStackPointer(_ instruction: Instruction) -> Bool {
        for operand in instruction.operands {
            switch operand {
            case let .register(reg) where reg.isStackPointer:
                return true
            case let .shiftedRegister(reg, _, _) where reg.isStackPointer:
                return true
            case let .extendedRegister(reg, _, _) where reg.isStackPointer:
                return true
            default:
                continue
            }
        }
        return false
    }
}

/// Resolves an address-forming instruction's PC-relative target to a
/// ``ReferencedData``. Holds the binary's data sections and symbol index;
/// the renderers thread an instance and feed it each instruction together
/// with the one before it (the local `adrp`+`add`/`ldr` idiom needs the
/// pair). Bounded local-idiom recognition only, never value tracking.
@frozen
public struct ReferencedDataResolver: Sendable {
    /// Non-code, file-backed sections, for section attribution and string
    /// reads.
    public let dataSections: [DataSection]
    /// Defined symbols, address-indexed (for the data-symbol tier).
    public let symbols: SymbolIndex

    @inlinable
    public init(dataSections: [DataSection], symbols: SymbolIndex) {
        self.dataSections = dataSections
        self.symbols = symbols
    }

    /// The empty resolver (a binary with no data sections, or the
    /// direct-decode modes), which resolves nothing.
    public static let empty = ReferencedDataResolver(dataSections: [], symbols: .empty)

    /// The absolute data address `instruction` forms, considering both a
    /// single self-contained PC-relative instruction and the local
    /// `adrp xD, <page>` + `<op> xD, …, #<offset>` idiom completed by
    /// `preceding`.
    ///
    /// A single ADR / literal-load / literal-PRFM already carries its full
    /// target in ``Instruction/pcRelativeTarget``, so it returns that. An
    /// `adrp` alone forms only a page base, so it is NOT resolved on its
    /// own (its low bits are completed by the next instruction). When
    /// `instruction` completes a preceding `adrp` into the same register
    /// with an immediate offset, the page base and the offset combine to
    /// the final target.
    public func targetAddress(of instruction: Instruction, preceding: Instruction?) -> UInt64? {
        // The adrp+add / adrp+ldr idiom: the page base comes from the
        // preceding adrp's pcRelativeTarget, the low offset from this
        // instruction, both into the same destination register.
        if let preceding, preceding.mnemonic == .adrp,
           let page = preceding.pcRelativeTarget,
           let pageRegister = adrpDestination(preceding),
           let offset = lowOffsetCompleting(instruction, page: pageRegister)
        {
            return page &+ offset
        }
        // A self-contained PC-relative instruction (ADR / LDR-literal /
        // LDRSW-literal / PRFM-literal). A bare adrp is excluded, its
        // page base is not a referenced datum until an add/ldr completes
        // it, so annotating the page alone would point at the wrong place.
        if instruction.mnemonic != .adrp {
            return instruction.pcRelativeTarget
        }
        return nil
    }

    /// Resolve `instruction` (with the instruction before it) to a
    /// referenced datum, or `nil` when it forms no in-section data
    /// address. The page base / low-offset combination and the
    /// section/string/symbol lookup live here.
    public func resolve(_ instruction: Instruction, preceding: Instruction?) -> ReferencedData? {
        guard let target = targetAddress(of: instruction, preceding: preceding) else { return nil }
        return resolve(target: target)
    }

    /// Resolve a bare absolute target address to its section, string, and
    /// data symbol. Exposed for the idiom-free callers and tests.
    public func resolve(target: UInt64) -> ReferencedData? {
        guard let section = dataSections.first(where: { $0.containsAddress(target) }) else { return nil }
        let string = section.isCStringLiteral ? section.cString(at: target) : nil
        return ReferencedData(string: string, symbol: dataSymbol(at: target), section: section.displayName)
    }

    /// The destination register of an `adrp xD, <page>`: its single
    /// register operand (canonical index), the register the next
    /// instruction must read to complete the address. `nil` if the
    /// operand shape is not the expected one.
    func adrpDestination(_ adrp: Instruction) -> UInt8? {
        for operand in adrp.operands {
            if case let .register(reg) = operand { return reg.canonicalIndex }
        }
        return nil
    }

    /// The low byte-offset `instruction` adds to a page base held in
    /// register `page`, or `nil` when `instruction` is not the
    /// completing half of the idiom. Two completing shapes are
    /// recognized, matching what the compiler emits and what
    /// `otool`/`llvm-objdump` annotate:
    ///
    /// - `add xD, xS, #imm` where `xS == page`: the offset is `#imm`.
    /// - `ldr xD, [xS, #imm]` / `ldrsw …` where the base `xS == page`:
    ///   the offset is the displacement (the address the load reads from,
    ///   i.e. the GOT/pointer slot, which is the referenced datum).
    ///
    /// The destination register is unconstrained (the compiler reuses the
    /// page register `add x8, x8, #..` or moves to another `ldr x16,
    /// [x8]`), only the SOURCE/base must be the adrp's register.
    func lowOffsetCompleting(_ instruction: Instruction, page: UInt8) -> UInt64? {
        switch instruction.mnemonic {
        case .add:
            addImmediateOffset(instruction, base: page)
        case .ldr, .ldrsw:
            loadDisplacementOffset(instruction, base: page)
        default:
            nil
        }
    }

    /// For `add xD, xS, #imm` with `xS == base`: the non-negative
    /// immediate, or `nil` when the operand shape does not match (a
    /// register-form add, a different base, a shifted/negative immediate).
    func addImmediateOffset(_ instruction: Instruction, base: UInt8) -> UInt64? {
        // add xD, xS, #imm : [register(dst), register(src), immediate].
        // A shifted or extended-register add is not the idiom.
        guard instruction.operands.count == 3,
              case let .register(source) = instruction.operands[1],
              source.canonicalIndex == base
        else { return nil }
        switch instruction.operands[2] {
        case let .immediate(value, _):
            return value >= 0 ? UInt64(value) : nil
        case let .unsignedImmediate(value, _):
            return value
        default:
            return nil
        }
    }

    /// For `ldr xD, [xS, #imm]` (or `ldrsw`) with base `xS == base`: the
    /// non-negative displacement, or `nil` when the addressing mode is
    /// not a simple base-plus-immediate over `base` (register-offset,
    /// writeback, a different base, a literal load).
    func loadDisplacementOffset(_ instruction: Instruction, base: UInt8) -> UInt64? {
        guard let memory = memoryOperand(instruction),
              case let .register(reg) = memory.base,
              reg.canonicalIndex == base,
              memory.index == nil,
              memory.writeback == .none,
              memory.displacement >= 0
        else { return nil }
        return UInt64(memory.displacement)
    }

    /// The single memory operand of a load, or `nil` if it has none.
    func memoryOperand(_ instruction: Instruction) -> MemoryOperand? {
        for operand in instruction.operands {
            if case let .memory(memory) = operand { return memory }
        }
        return nil
    }

    /// The data symbol at `target`: the name exactly there, or the closest
    /// preceding symbol as `name+0x<delta>` when that symbol lies in the
    /// same data section as the target (a cross-section delta would
    /// fabricate locality, exactly as ``BranchSymbolizer`` guards branch
    /// resolution). `nil` when no symbol names it.
    func dataSymbol(at target: UInt64) -> String? {
        if let exact = symbols.name(at: target) {
            return exact
        }
        guard let nearest = symbols.nearest(atOrBefore: target) else { return nil }
        let sameSection = dataSections.contains { section in
            section.containsAddress(target) && section.containsAddress(nearest.address)
        }
        guard sameSection else { return nil }
        return nearest.name + "+0x" + String(target &- nearest.address, radix: 16)
    }
}
