// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Golden encodings, operand shapes, register semantics and branch classes for
/// every FEAT_PAuth_LR form: the two PC-relative immediate slabs, the ten
/// data-processing one-source register forms and the register-form returns.
@Suite("BES / FEAT_PAuth_LR — immediate, register and return forms")
struct BESPAuthLRTests {
    private static let immediateReturns: [(UInt32, Mnemonic, String)] = [
        (0x5500_001F, .retaasppc, "retaasppc #0"),
        (0x5500_003F, .retaasppc, "retaasppc #-4"),
        (0x551F_FFFF, .retaasppc, "retaasppc #-262140"),
        (0x550A_D1FF, .retaasppc, "retaasppc #-88636"),
        (0x5520_001F, .retabsppc, "retabsppc #0"),
        (0x5520_003F, .retabsppc, "retabsppc #-4"),
        (0x553F_FFFF, .retabsppc, "retabsppc #-262140"),
        (0x552A_D1FF, .retabsppc, "retabsppc #-88636"),
    ]

    private static let immediateAuths: [(UInt32, Mnemonic, String)] = [
        (0xF380_001F, .autiasppc, "autiasppc #0"),
        (0xF380_003F, .autiasppc, "autiasppc #-4"),
        (0xF39F_FFFF, .autiasppc, "autiasppc #-262140"),
        (0xF38A_D1FF, .autiasppc, "autiasppc #-88636"),
        (0xF3A0_001F, .autibsppc, "autibsppc #0"),
        (0xF3A0_003F, .autibsppc, "autibsppc #-4"),
        (0xF3BF_FFFF, .autibsppc, "autibsppc #-262140"),
        (0xF3AA_D1FF, .autibsppc, "autibsppc #-88636"),
    ]

    private static let oneSourceForms: [(UInt32, Mnemonic, String)] = [
        (0xDAC1_83FE, .pacnbiasppc, "pacnbiasppc"),
        (0xDAC1_87FE, .pacnbibsppc, "pacnbibsppc"),
        (0xDAC1_8BFE, .pacia171615, "pacia171615"),
        (0xDAC1_8FFE, .pacib171615, "pacib171615"),
        (0xDAC1_93FE, .autiasppcr, "autiasppcr xzr"),
        (0xDAC1_90BE, .autiasppcr, "autiasppcr x5"),
        (0xDAC1_97FE, .autibsppcr, "autibsppcr xzr"),
        (0xDAC1_94BE, .autibsppcr, "autibsppcr x5"),
        (0xDAC1_A3FE, .paciasppc, "paciasppc"),
        (0xDAC1_A7FE, .pacibsppc, "pacibsppc"),
        (0xDAC1_BBFE, .autia171615, "autia171615"),
        (0xDAC1_BFFE, .autib171615, "autib171615"),
    ]

    @Test func immediateReturnsDecodeRenderAndClassify() {
        for (word, mnemonic, text) in Self.immediateReturns {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.branchClass == .return)
            #expect(d.category == .branchesExceptionSystem)
            #expect(d.semanticReads == RegisterSet.empty.inserting(.x(30)).inserting(.sp()))
            #expect(d.semanticWrites.mask == 0)
            #expect(BESSemanticChecker.verify(d) == nil)
        }
    }

    @Test func immediateReturnsRejectReservedFields() {
        #expect(decode(0x5500_0000, at: 0).isUndefined)
        #expect(decode(0x5500_001E, at: 0).isUndefined)
        #expect(decode(0x5540_001F, at: 0).isUndefined)
        #expect(decode(0x5580_001F, at: 0).isUndefined)
    }

    @Test func immediateAuthsDecodeRenderAndCarrySemantics() {
        for (word, mnemonic, text) in Self.immediateAuths {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.branchClass == .none)
            #expect(d.category == .pointerAuthentication)
            #expect(d.semanticReads == RegisterSet.empty.inserting(.x(30)).inserting(.sp()))
            #expect(d.semanticWrites == RegisterSet.empty.inserting(.x(30)))
            #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
        }
    }

    @Test func immediateAuthsRejectReservedFields() {
        #expect(decode(0xF380_0000, at: 0).isUndefined)
        #expect(decode(0xF380_001E, at: 0).isUndefined)
        #expect(decode(0xF3C0_001F, at: 0).isUndefined)
    }

    @Test func oneSourceFormsDecodeRenderAndClassify() {
        for (word, mnemonic, text) in Self.oneSourceForms {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.category == .pointerAuthentication)
            #expect(d.branchClass == .none)
            #expect(CryptoAppleExtensionsSemanticChecker.verify(d) == nil)
        }
    }

    @Test func oneSourceFormsCarryExactRegisterSemantics() {
        let stackModifier = decode(0xDAC1_A3FE, at: 0)
        #expect(stackModifier.semanticReads == RegisterSet.empty.inserting(.x(30)).inserting(.sp()))
        #expect(stackModifier.semanticWrites == RegisterSet.empty.inserting(.x(30)))
        let triple = decode(0xDAC1_8BFE, at: 0)
        #expect(triple.semanticReads
            == RegisterSet.empty.inserting(.x(15)).inserting(.x(16)).inserting(.x(17)))
        #expect(triple.semanticWrites == RegisterSet.empty.inserting(.x(17)))
        let registerModifier = decode(0xDAC1_90BE, at: 0)
        #expect(registerModifier.semanticReads
            == RegisterSet.empty.inserting(.x(30)).inserting(.x(5)))
        #expect(registerModifier.semanticWrites == RegisterSet.empty.inserting(.x(30)))
        #expect(decode(0xDAC1_93FE, at: 0).semanticReads == RegisterSet.empty.inserting(.x(30)))
    }

    @Test func oneSourceFormsRequireTheLinkRegisterDestination() {
        for word: UInt32 in [0xDAC1_83FF, 0xDAC1_83E0, 0xDAC1_A3FF, 0xDAC1_8BE5] {
            #expect(decode(word, at: 0).isUndefined, "0x\(String(word, radix: 16))")
        }
        #expect(decode(0xDAC1_A0BE, at: 0).isUndefined)
        #expect(decode(0xDAC1_B3FE, at: 0).isUndefined)
        #expect(decode(0xDAC1_C3FE, at: 0).isUndefined)
    }

    @Test func registerFormReturnsTakeTheirModifierFromOp4() {
        let rows: [(UInt32, Mnemonic, String, UInt8)] = [
            (0xD65F_0BE0, .retaasppcr, "retaasppcr x0", 0),
            (0xD65F_0BE5, .retaasppcr, "retaasppcr x5", 5),
            (0xD65F_0FE0, .retabsppcr, "retabsppcr x0", 0),
            (0xD65F_0FE5, .retabsppcr, "retabsppcr x5", 5),
            (0xD65F_0BFE, .retaasppcr, "retaasppcr x30", 30),
        ]
        for (word, mnemonic, text, modifier) in rows {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.branchClass == .return)
            #expect(d.semanticReads
                == RegisterSet.empty.inserting(.x(30)).inserting(.x(modifier)))
            #expect(BESSemanticChecker.verify(d) == nil)
        }
    }

    @Test func op4EqualToThirtyOneStaysTheUnmodifiedReturn() {
        #expect(decode(0xD65F_0BFF, at: 0).mnemonic == .retaa)
        #expect(decode(0xD65F_0FFF, at: 0).mnemonic == .retab)
        #expect(decode(0xD65F_0BC0, at: 0).isUndefined)
        #expect(decode(0xD61F_0BE0, at: 0).isUndefined)
        #expect(decode(0xD69F_0BE0, at: 0).isUndefined)
    }
}
