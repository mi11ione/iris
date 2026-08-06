// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension Mnemonic {
    /// SVE FSUBR — reversed floating-point subtract.
    static let fsubr = Mnemonic(rawValue: 16627)
    /// SVE FDIVR — reversed floating-point divide.
    static let fdivr = Mnemonic(rawValue: 16628)
    /// SVE FADDA — strictly-ordered sequential floating-point add reduction.
    static let fadda = Mnemonic(rawValue: 16629)
    /// SVE FADDV — recursive floating-point add reduction.
    static let faddv = Mnemonic(rawValue: 16630)
    /// SVE2p1 FADDQV — quadword floating-point add reduction.
    static let faddqv = Mnemonic(rawValue: 16631)
    /// SVE2p1 FMAXQV — quadword floating-point maximum reduction.
    static let fmaxqv = Mnemonic(rawValue: 16632)
    /// SVE2p1 FMINQV — quadword floating-point minimum reduction.
    static let fminqv = Mnemonic(rawValue: 16633)
    /// SVE2p1 FMAXNMQV — quadword floating-point maximum-number reduction.
    static let fmaxnmqv = Mnemonic(rawValue: 16634)
    /// SVE2p1 FMINNMQV — quadword floating-point minimum-number reduction.
    static let fminnmqv = Mnemonic(rawValue: 16635)
    /// SVE FCMNE — floating-point compare not-equal to predicate.
    static let fcmne = Mnemonic(rawValue: 16636)
    /// SVE FCMUO — floating-point compare unordered to predicate.
    static let fcmuo = Mnemonic(rawValue: 16637)
    /// SVE2 FCVTLT — floating-point up-convert from odd (top) elements.
    static let fcvtlt = Mnemonic(rawValue: 16638)
    /// SVE2 FCVTNT — floating-point down-convert into odd (top) elements.
    static let fcvtnt = Mnemonic(rawValue: 16639)
    /// SVE2 FCVTX — double-to-single convert with round-to-odd.
    static let fcvtx = Mnemonic(rawValue: 16640)
    /// SVE2 FCVTXNT — round-to-odd down-convert into odd (top) elements.
    static let fcvtxnt = Mnemonic(rawValue: 16641)
    /// SVE2 FLOGB — floating-point base-two logarithm as integer.
    static let flogb = Mnemonic(rawValue: 16642)
    /// SVE FEXPA — floating-point exponential accelerator.
    static let fexpa = Mnemonic(rawValue: 16643)
    /// SVE FTSSEL — floating-point trigonometric select coefficient.
    static let ftssel = Mnemonic(rawValue: 16644)
    /// SVE FTSMUL — floating-point trigonometric starting-value multiply.
    static let ftsmul = Mnemonic(rawValue: 16645)
    /// SVE FTMAD — floating-point trigonometric multiply-add coefficient.
    static let ftmad = Mnemonic(rawValue: 16646)
    /// SVE FMAD — floating-point multiply-add, multiplicand destructive.
    static let fmad = Mnemonic(rawValue: 16647)
    /// SVE FMSB — floating-point multiply-subtract, multiplicand destructive.
    static let fmsb = Mnemonic(rawValue: 16648)
    /// SVE FNMAD — negated floating-point multiply-add, multiplicand destructive.
    static let fnmad = Mnemonic(rawValue: 16649)
    /// SVE FNMLA — negated floating-point multiply-accumulate.
    static let fnmla = Mnemonic(rawValue: 16650)
    /// SVE FNMLS — negated floating-point multiply-subtract-accumulate.
    static let fnmls = Mnemonic(rawValue: 16651)
    /// SVE FNMSB — negated floating-point multiply-subtract, multiplicand destructive.
    static let fnmsb = Mnemonic(rawValue: 16652)
    /// SVE2p1 FCLAMP — floating-point clamp to range.
    static let fclamp = Mnemonic(rawValue: 16653)
    /// FMMLA — floating-point matrix multiply-accumulate (SVE and the NEON
    /// FEAT_F16MM form decodes).
    static let fmmla = Mnemonic(rawValue: 16654)
    /// SVE2 FMLSLB — floating-point multiply-subtract long from bottom elements.
    static let fmlslb = Mnemonic(rawValue: 16655)
    /// SVE2 FMLSLT — floating-point multiply-subtract long from top elements.
    static let fmlslt = Mnemonic(rawValue: 16656)
    /// SVE B16B16 BFADD — bfloat16 add.
    static let bfadd = Mnemonic(rawValue: 16657)
    /// SVE B16B16 BFSUB — bfloat16 subtract.
    static let bfsub = Mnemonic(rawValue: 16658)
    /// SVE B16B16 BFMUL — bfloat16 multiply.
    static let bfmul = Mnemonic(rawValue: 16659)
    /// SVE B16B16 BFMAX — bfloat16 maximum.
    static let bfmax = Mnemonic(rawValue: 16660)
    /// SVE B16B16 BFMIN — bfloat16 minimum.
    static let bfmin = Mnemonic(rawValue: 16661)
    /// SVE B16B16 BFMAXNM — bfloat16 maximum number.
    static let bfmaxnm = Mnemonic(rawValue: 16662)
    /// SVE B16B16 BFMINNM — bfloat16 minimum number.
    static let bfminnm = Mnemonic(rawValue: 16663)
    /// SVE B16B16 BFMLA — bfloat16 multiply-accumulate.
    static let bfmla = Mnemonic(rawValue: 16664)
    /// SVE B16B16 BFMLS — bfloat16 multiply-subtract-accumulate.
    static let bfmls = Mnemonic(rawValue: 16665)
    /// SVE2p1 BFMLSLB — bfloat16 multiply-subtract long from bottom elements.
    static let bfmlslb = Mnemonic(rawValue: 16666)
    /// SVE2p1 BFMLSLT — bfloat16 multiply-subtract long from top elements.
    static let bfmlslt = Mnemonic(rawValue: 16667)
    /// SVE B16B16 BFCLAMP — bfloat16 clamp to range.
    static let bfclamp = Mnemonic(rawValue: 16668)
    /// SVE BFSCALE — bfloat16 scale by integer power of two.
    static let bfscale = Mnemonic(rawValue: 16669)
    /// SVE2 BFCVTNT — single-to-bfloat16 down-convert into odd (top) elements.
    static let bfcvtnt = Mnemonic(rawValue: 16670)
    /// FP8 F1CVT — 8-bit floating-point convert, first-half input.
    static let f1cvt = Mnemonic(rawValue: 16671)
    /// FP8 F1CVTLT — 8-bit floating-point convert, first-half odd input.
    static let f1cvtlt = Mnemonic(rawValue: 16672)
    /// FP8 F2CVT — 8-bit floating-point convert, second-half input.
    static let f2cvt = Mnemonic(rawValue: 16673)
    /// FP8 F2CVTLT — 8-bit floating-point convert, second-half odd input.
    static let f2cvtlt = Mnemonic(rawValue: 16674)
    /// FP8 BF1CVT — 8-bit to bfloat16 convert, first-half input.
    static let bf1cvt = Mnemonic(rawValue: 16675)
    /// FP8 BF1CVTLT — 8-bit to bfloat16 convert, first-half odd input.
    static let bf1cvtlt = Mnemonic(rawValue: 16676)
    /// FP8 BF2CVT — 8-bit to bfloat16 convert, second-half input.
    static let bf2cvt = Mnemonic(rawValue: 16677)
    /// FP8 BF2CVTLT — 8-bit to bfloat16 convert, second-half odd input.
    static let bf2cvtlt = Mnemonic(rawValue: 16678)
    /// FP8 FCVTNB — down-convert a vector pair into even (bottom) bytes.
    static let fcvtnb = Mnemonic(rawValue: 16679)
    /// SVE2p2 FCVTZSN — signed down-convert of a vector pair.
    static let fcvtzsn = Mnemonic(rawValue: 16680)
    /// SVE2p2 FCVTZUN — unsigned down-convert of a vector pair.
    static let fcvtzun = Mnemonic(rawValue: 16681)
    /// FP8 SCVTFLT — signed 8-bit up-convert from odd bytes.
    static let scvtflt = Mnemonic(rawValue: 16682)
    /// FP8 UCVTFLT — unsigned 8-bit up-convert from odd bytes.
    static let ucvtflt = Mnemonic(rawValue: 16683)
}
