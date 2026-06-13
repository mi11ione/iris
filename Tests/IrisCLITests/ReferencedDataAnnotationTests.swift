// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the referenced-data annotation: the string / data-symbol /
/// section comment an address-forming instruction earns in the listing,
/// the matching `referencedSection` / `referencedString` /
/// `referencedSymbol` JSON fields, and the printable-ASCII `charLiteral`
/// hint. Grounded on the `strings-arm64` fixture (real adrp+add cstring
/// idioms and char comparisons) and the locked goldens, plus unit checks
/// of the resolver and walker against the `otool`/`llvm-objdump` model.
@Suite("Referenced-data annotation")
struct ReferencedDataAnnotationTests {
    func object(_ line: some StringProtocol) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

    // MARK: Listing goldens

    @Test func stringsListingMatchesGolden() {
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stderr.isEmpty)
        #expect(normalizedToGolden(run.stdout) == golden("strings-arm64.listing.txt"))
    }

    @Test func adrpAddIdiomAnnotatesTheString() {
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        // The two __cstring adrp+add idioms read back the literal pool
        // strings, exactly as otool's `; literal pool for: "…"`.
        #expect(run.stdout.contains("add x8, x8, #1268 ; \"world\""))
        #expect(run.stdout.contains("add x0, x0, #1256 ; \"hello, %s!\\n\""))
    }

    @Test func gotLoadIdiomAnnotatesTheSection() {
        // The __stubs adrp+ldr forms a __got slot address; the ldr's base is
        // the adrp register and the displacement completes the target.
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("ldr x16, [x16] ; __DATA_CONST,__got"))
    }

    @Test func charComparisonsAnnotateTheCharacter() {
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("cmp w0, #65 ; 'A'"))
        #expect(run.stdout.contains("cmp w0, #122 ; 'z'"))
        #expect(run.stdout.contains("cmp w0, #32 ; ' '"))
    }

    @Test func stackPointerArithmeticGetsNoCharHint() {
        // `sub sp, sp, #32` / `add sp, sp, #32`: the #32 is the space byte,
        // but frame arithmetic is not a character, so no hint is appended.
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("sub sp, sp, #32\n"))
        #expect(run.stdout.contains("add sp, sp, #32\n"))
        #expect(!run.stdout.contains("sub sp, sp, #32 ;"))
    }

    @Test func bareAdrpStillShowsThePageHex() {
        // A bare adrp keeps its page-base hex comment (unchanged behavior);
        // the referenced-data annotation lands on the completing add, not
        // the adrp.
        let run = runCLI(["--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("adrp x8, #0 ; 0x100000000"))
    }

    // MARK: JSON

    @Test func jsonStreamMatchesGolden() {
        let run = runCLI(["--json", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("strings-arm64.ndjson"))
    }

    @Test func jsonCarriesReferencedFields() throws {
        let run = runCLI(["--json", cliFixturePath("strings-arm64")])
        let stringLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"referencedString\"") })
        let fields = try #require(object(stringLine))
        #expect(fields["referencedSection"] as? String == "__TEXT,__cstring")
        #expect(fields["referencedString"] as? String == "world" || fields["referencedString"] as? String == "hello, %s!\n")
    }

    @Test func jsonCarriesCharLiteral() throws {
        let run = runCLI(["--json", cliFixturePath("strings-arm64")])
        let charLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"charLiteral\":\"A\"") })
        let fields = try #require(object(charLine))
        #expect(fields["mnemonic"] as? String == "cmp")
        #expect(fields["charLiteral"] as? String == "A")
    }

    @Test func referencedFieldsKeepFixedKeyOrder() throws {
        // referencedSection / referencedString sit after targetSymbol and
        // before isData; the slot must precede isData on the line.
        let run = runCLI(["--json", cliFixturePath("strings-arm64")])
        let line = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"referencedString\"") })
        let section = try #require(line.range(of: "\"referencedSection\""))
        let string = try #require(line.range(of: "\"referencedString\""))
        let isData = try #require(line.range(of: "\"isData\""))
        #expect(section.lowerBound < string.lowerBound)
        #expect(string.lowerBound < isData.lowerBound)
    }

    @Test func defaultJSONIsPurelyAdditive() throws {
        // Every line that gains a referenced field still carries the
        // original schema fields unchanged; a consumer of the old schema
        // ignores the new keys.
        let run = runCLI(["--json", cliFixturePath("strings-arm64")])
        for line in run.stdout.split(separator: "\n") {
            let fields = try #require(object(line))
            #expect(fields["schemaVersion"] as? Int == 1)
            #expect(fields["address"] is String)
            #expect(fields["isData"] is Bool)
        }
    }

    // MARK: Resolver units

    @Test func resolverReadsStringSymbolAndSection() throws {
        let binary = try #require(walkedBinary(cliFixturePath("strings-arm64")))
        let resolver = binary.referencedDataResolver
        #expect(!resolver.dataSections.isEmpty)
        // The cstring section reads back a NUL-terminated string at any
        // address it contains.
        let cstring = try #require(resolver.dataSections.first { $0.isCStringLiteral })
        let resolved = resolver.resolve(target: cstring.address)
        #expect(resolved?.string != nil)
        #expect(resolved?.section == cstring.displayName)
    }

    @Test func resolverIgnoresATargetInNoDataSection() {
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        #expect(resolver.resolve(target: 0xDEAD) == nil)
        #expect(ReferencedDataResolver.empty.resolve(target: 0) == nil)
    }

    @Test func resolverCombinesAdrpAddIntoTheTarget() {
        // adrp x0, page=0x1000 then add x0, x0, #0x10 → target 0x1010,
        // resolved through a single synthetic data section.
        let section = syntheticCStringSection(address: 0x1000, bytes: Array("hi\u{0}".utf8))
        let resolver = ReferencedDataResolver(dataSections: [section], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(0)), .pageLabel(byteOffset: 0x1000)])
        let add = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingImmediate,
                              operands: [.register(.x(0)), .register(.x(0)), .unsignedImmediate(value: 0x10, width: 12)])
        #expect(resolver.targetAddress(of: add, preceding: adrp) == 0x1010)
        // The completing add may carry a (non-negative) signed immediate too.
        let signedAdd = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingImmediate,
                                    operands: [.register(.x(0)), .register(.x(0)), .immediate(value: 0x20, width: 12)])
        #expect(resolver.targetAddress(of: signedAdd, preceding: adrp) == 0x1020)
    }

    @Test func resolverRejectsAddOverADifferentRegister() {
        // add x1, x2, #0x10 does not complete an adrp into x0.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(0)), .pageLabel(byteOffset: 0x1000)])
        let add = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingImmediate,
                              operands: [.register(.x(1)), .register(.x(2)), .unsignedImmediate(value: 0x10, width: 12)])
        #expect(resolver.targetAddress(of: add, preceding: adrp) == nil)
    }

    @Test func resolverDoesNotResolveABareAdrp() {
        // A lone adrp forms only a page base, not a referenced datum.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(0)), .pageLabel(byteOffset: 0x1000)])
        #expect(resolver.targetAddress(of: adrp, preceding: nil) == nil)
    }

    @Test func resolverCombinesAdrpLdrIntoTheSlotAddress() {
        // adrp x16, 0x4000 then ldr x16, [x16, #8] → target 0x4008.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(16)), .pageLabel(byteOffset: 0x4000)])
        let ldr = Instruction(address: 0x4, mnemonic: .ldr, category: .loadsAndStores,
                              operands: [.register(.x(16)), .memory(MemoryOperand(base: .register(.x(16)), displacement: 8))])
        #expect(resolver.targetAddress(of: ldr, preceding: adrp) == 0x4008)
    }

    @Test func resolverRejectsRegisterOffsetLoadAsIdiomCompletion() {
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(16)), .pageLabel(byteOffset: 0x4000)])
        // register-offset addressing is not the simple base+imm idiom, so it
        // does not complete the adrp into a page+offset target.
        let indexed = Instruction(address: 0x4, mnemonic: .ldr, category: .loadsAndStores,
                                  operands: [.register(.x(0)), .memory(MemoryOperand(base: .register(.x(16)), index: .x(1)))])
        #expect(resolver.targetAddress(of: indexed, preceding: adrp) == nil)
    }

    @Test func literalLoadResolvesToItsOwnPCRelativeTarget() {
        // A PC-literal load is self-contained: it carries its own
        // pcRelativeTarget regardless of any preceding adrp, so it resolves
        // to address + displacement, not the idiom combination.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let literal = Instruction(address: 0x4, mnemonic: .ldr, category: .loadsAndStores,
                                  operands: [.register(.x(0)), .memory(MemoryOperand(base: .pc, displacement: 8))])
        #expect(resolver.targetAddress(of: literal, preceding: nil) == 0xC)
    }

    @Test func resolverDataSymbolUsesOffsetFormInSection() {
        // A symbol mid-section resolves a later target as name+0x<delta>
        // (observed through the public resolve(target:)). The section is
        // not a cstring one, so string is nil and symbol is the witness.
        let section = syntheticDataSection(address: 0x2000, byteCount: 0x40)
        let symbols = SymbolIndex(symbols: [(0x2000, "_table")])
        let resolver = ReferencedDataResolver(dataSections: [section], symbols: symbols)
        #expect(resolver.resolve(target: 0x2000)?.symbol == "_table")
        #expect(resolver.resolve(target: 0x2010)?.symbol == "_table+0x10")
        #expect(resolver.resolve(target: 0x2010)?.string == nil)
        // A symbol in a different section is not borrowed for locality.
        let far = ReferencedDataResolver(
            dataSections: [section], symbols: SymbolIndex(symbols: [(0x100, "_elsewhere")]),
        )
        #expect(far.resolve(target: 0x2010)?.symbol == nil)
        #expect(far.resolve(target: 0x2010)?.section == "__DATA,__const")
    }

    // MARK: data-symbol tier end to end

    @Test func adrToNamedDatumAnnotatesTheSymbolInListingAndJSON() throws {
        // adr x0, #256 -> 0x1100, where _datum lives in __DATA,__const.
        // The non-cstring section reads no string, so the symbol is the
        // annotation in both the listing and the JSON.
        let bytes = dataSymbolReferenceBinary()
        let listing = withTemporaryFile(bytes: bytes) { path in
            runCLI(["--color", "never", path]).stdout
        }
        // The canonical text keeps adr's relative form; the datum is the
        // appended annotation.
        #expect(listing.contains("adr x0, #256 ; _datum"))
        let json = withTemporaryFile(bytes: bytes) { path in
            runCLI(["--json", path]).stdout
        }
        let line = try #require(json.split(separator: "\n").first { $0.contains("\"mnemonic\":\"adr\"") })
        let fields = try #require(object(line))
        #expect(fields["referencedSection"] as? String == "__DATA,__const")
        #expect(fields["referencedSymbol"] as? String == "_datum")
        #expect(fields["referencedString"] == nil)
    }

    @Test func slimStreamAlsoCarriesReferencedSymbol() throws {
        let bytes = dataSymbolReferenceBinary()
        let json = withTemporaryFile(bytes: bytes) { path in
            runCLI(["--json", "--slim", path]).stdout
        }
        let line = try #require(json.split(separator: "\n").first { $0.contains("\"mnemonic\":\"adr\"") })
        #expect(object(line)?["referencedSymbol"] as? String == "_datum")
    }

    @Test func walkerClampsALyingDataSectionSize() throws {
        // A __const size far past the file is clamped to the bytes that
        // exist, and the section is still collected (the read just sees
        // the real bytes).
        let bytes = dataSymbolReferenceBinary(sectionSize: 0x0000_0FFF_FFFF_0000)
        let binary = try #require(walkedBinary(bytes: bytes))
        let const = try #require(binary.dataSections.first { $0.sectionName == "__const" })
        #expect(const.byteCount < 0x0000_0FFF_FFFF_0000)
        #expect(const.containsAddress(0x1100))
    }

    // MARK: resolver nil branches

    @Test func resolverHandlesADegenerateAdrpWithoutARegister() {
        // A pageLabel-only adrp (no register operand) cannot anchor the
        // idiom: adrpDestination is nil, so the completing add does not
        // resolve through it.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.pageLabel(byteOffset: 0x1000)])
        let add = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingImmediate,
                              operands: [.register(.x(0)), .register(.x(0)), .unsignedImmediate(value: 0x10, width: 12)])
        #expect(resolver.targetAddress(of: add, preceding: adrp) == nil)
    }

    @Test func resolverIgnoresANonCompletingMnemonicAfterAdrp() {
        // A mov after the adrp is neither add nor ldr, so it does not
        // complete the idiom (the lowOffsetCompleting default arm).
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(0)), .pageLabel(byteOffset: 0x1000)])
        let mov = Instruction(address: 0x4, mnemonic: .mov, category: .dataProcessingRegister,
                              operands: [.register(.x(1)), .register(.x(0))])
        #expect(resolver.targetAddress(of: mov, preceding: adrp) == nil)
    }

    @Test func resolverRejectsNegativeAndNonImmediateAddCompletions() {
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(0)), .pageLabel(byteOffset: 0x1000)])
        // a negative signed immediate is not a forward page offset.
        let negative = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingImmediate,
                                   operands: [.register(.x(0)), .register(.x(0)), .immediate(value: -16, width: 12)])
        #expect(resolver.targetAddress(of: negative, preceding: adrp) == nil)
        // a shifted-register third operand is not the immediate idiom.
        let shifted = Instruction(address: 0x4, mnemonic: .add, category: .dataProcessingRegister,
                                  operands: [.register(.x(0)), .register(.x(0)), .shiftedRegister(reg: .x(1), shift: .lsl, amount: 2)])
        #expect(resolver.targetAddress(of: shifted, preceding: adrp) == nil)
    }

    @Test func resolverRejectsALdrWithNoMemoryOperand() {
        // A degenerate ldr carrying only register operands has no memory
        // operand, so it cannot complete the idiom.
        let resolver = ReferencedDataResolver(dataSections: [], symbols: .empty)
        let adrp = Instruction(address: 0x0, mnemonic: .adrp, category: .dataProcessingImmediate,
                               operands: [.register(.x(16)), .pageLabel(byteOffset: 0x4000)])
        let ldr = Instruction(address: 0x4, mnemonic: .ldr, category: .loadsAndStores,
                              operands: [.register(.x(0)), .register(.x(16))])
        #expect(resolver.targetAddress(of: ldr, preceding: adrp) == nil)
    }

    // MARK: char-literal units

    @Test func charLiteralHintIsOnlyTheValueTestingMnemonics() {
        // The hint fires for the comparison and bit-test mnemonics, where
        // testing a byte against a character is the clear intent.
        for mnemonic in [Mnemonic.cmp, .cmn, .ccmp, .ccmn, .tst] {
            let inst = Instruction(address: 0, mnemonic: mnemonic, category: .dataProcessingImmediate,
                                   operands: [.register(.w(0)), .unsignedImmediate(value: 0x41, width: 12)])
            #expect(CharLiteralHint.character(for: inst) == "A", "expected hint for \(mnemonic.name)")
        }
        // Plain arithmetic, moves, and loads are not candidates: a `#65`
        // that is an offset or a loaded constant reads as a number.
        for mnemonic in [Mnemonic.add, .sub, .mov, .movz, .orr, .ldr] {
            let inst = Instruction(address: 0, mnemonic: mnemonic, category: .dataProcessingImmediate,
                                   operands: [.register(.w(0)), .unsignedImmediate(value: 0x41, width: 12)])
            #expect(CharLiteralHint.character(for: inst) == nil, "expected no hint for \(mnemonic.name)")
        }
    }

    @Test func charLiteralHintBoundsAreInclusivePrintable() {
        func hint(_ value: UInt64) -> Character? {
            CharLiteralHint.character(for: Instruction(
                address: 0, mnemonic: .cmp, category: .dataProcessingImmediate,
                operands: [.register(.w(0)), .unsignedImmediate(value: value, width: 12)],
            ))
        }
        #expect(hint(0x1F) == nil) // just below space
        #expect(hint(0x20) == " ") // space (inclusive low)
        #expect(hint(0x7E) == "~") // tilde (inclusive high)
        #expect(hint(0x7F) == nil) // DEL, just above
        #expect(hint(0x100) == nil) // far out of range
    }

    @Test func charLiteralHintTakesSignedImmediatesToo() {
        // A signed immediate in range hints; a negative one does not.
        let positive = Instruction(address: 0, mnemonic: .cmp, category: .dataProcessingImmediate,
                                   operands: [.register(.w(0)), .immediate(value: 0x41, width: 12)])
        #expect(CharLiteralHint.character(for: positive) == "A")
        let negative = Instruction(address: 0, mnemonic: .cmp, category: .dataProcessingImmediate,
                                   operands: [.register(.w(0)), .immediate(value: -1, width: 12)])
        #expect(CharLiteralHint.character(for: negative) == nil)
    }

    @Test func charLiteralHintSkipsStackPointerForms() {
        // A candidate mnemonic touching sp is frame management, not a
        // character test, so the hint suppresses. sp via plain, shifted, and
        // extended register operands all suppress.
        let plain = Instruction(address: 0, mnemonic: .cmp, category: .dataProcessingImmediate,
                                operands: [.register(.sp()), .unsignedImmediate(value: 0x20, width: 12)])
        #expect(CharLiteralHint.character(for: plain) == nil)
        let shifted = Instruction(address: 0, mnemonic: .cmn, category: .dataProcessingImmediate,
                                  operands: [.register(.w(0)), .shiftedRegister(reg: .sp(), shift: .lsl, amount: 0), .unsignedImmediate(value: 0x20, width: 12)])
        #expect(CharLiteralHint.character(for: shifted) == nil)
        let extended = Instruction(address: 0, mnemonic: .cmn, category: .dataProcessingImmediate,
                                   operands: [.register(.w(0)), .extendedRegister(reg: .sp(), extend: .uxtw, shift: 0), .unsignedImmediate(value: 0x20, width: 12)])
        #expect(CharLiteralHint.character(for: extended) == nil)
    }

    @Test func quotedStringEscapesAndTruncates() {
        #expect(InstructionText.quotedString("plain") == "\"plain\"")
        #expect(InstructionText.quotedString("a\"b\\c") == "\"a\\\"b\\\\c\"")
        #expect(InstructionText.quotedString("tab\there") == "\"tab\\there\"")
        #expect(InstructionText.quotedString("nl\nret\r") == "\"nl\\nret\\r\"")
        // A control byte and DEL render as \x<hh>.
        #expect(InstructionText.quotedString("\u{1}\u{7F}") == "\"\\x01\\x7f\"")
        // Truncation caps the visible scalars and appends an ellipsis.
        let long = String(repeating: "x", count: 100)
        let capped = InstructionText.quotedString(long, maxScalars: 8)
        #expect(capped == "\"xxxxxxxx…\"")
    }

    // MARK: helpers

    /// A standalone cstring `DataSection` over `bytes` at `address`,
    /// backed by a temporary file so its zero-copy reads exercise the real
    /// mapped path.
    func syntheticCStringSection(address: UInt64, bytes: [UInt8]) -> DataSection {
        // Wrap the bytes as the sole content of a minimal Mach-O so the
        // walker yields a DataSection over them; simpler to drive the
        // resolver through a real walk than synthesize a MappedFile.
        let walked = stringSectionBinary(address: address, bytes: bytes)
        return walked.dataSections.first { $0.address == address }!
    }

    /// A non-cstring `__DATA,__const` section of `byteCount` zero bytes at
    /// `address` (for the data-symbol tier, where no string is read).
    func syntheticDataSection(address: UInt64, byteCount: Int) -> DataSection {
        let walked = dataSectionBinary(
            segname: "__DATA", sectname: "__const",
            address: address, bytes: [UInt8](repeating: 0, count: byteCount), sectionFlags: 0,
        )
        return walked.dataSections.first { $0.address == address }!
    }
}
