// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension Mnemonic {
    /// SME `ZERO` — zero a set of `ZA` tiles (or the whole array).
    static let zero = Mnemonic(rawValue: 28672)

    /// SME `ADDHA` — add horizontally into each `ZA` tile row.
    static let addha = Mnemonic(rawValue: 28673)
    /// SME `ADDVA` — add vertically into each `ZA` tile column.
    static let addva = Mnemonic(rawValue: 28674)

    /// SME `FMOPA` — floating-point outer product, accumulating into `ZA`.
    static let fmopa = Mnemonic(rawValue: 28675)
    /// SME `FMOPS` — floating-point outer product, subtracting from `ZA`.
    static let fmops = Mnemonic(rawValue: 28676)
    /// SME `BFMOPA` — BFloat16 outer product, accumulating into `ZA`.
    static let bfmopa = Mnemonic(rawValue: 28677)
    /// SME `BFMOPS` — BFloat16 outer product, subtracting from `ZA`.
    static let bfmops = Mnemonic(rawValue: 28678)

    /// SME `SMOPA` — signed integer outer product, accumulating into `ZA`.
    static let smopa = Mnemonic(rawValue: 28679)
    /// SME `SMOPS` — signed integer outer product, subtracting from `ZA`.
    static let smops = Mnemonic(rawValue: 28680)
    /// SME `SUMOPA` — signed-by-unsigned outer product, accumulating.
    static let sumopa = Mnemonic(rawValue: 28681)
    /// SME `SUMOPS` — signed-by-unsigned outer product, subtracting.
    static let sumops = Mnemonic(rawValue: 28682)
    /// SME `USMOPA` — unsigned-by-signed outer product, accumulating.
    static let usmopa = Mnemonic(rawValue: 28683)
    /// SME `USMOPS` — unsigned-by-signed outer product, subtracting.
    static let usmops = Mnemonic(rawValue: 28684)
    /// SME `UMOPA` — unsigned integer outer product, accumulating into `ZA`.
    static let umopa = Mnemonic(rawValue: 28685)
    /// SME `UMOPS` — unsigned integer outer product, subtracting from `ZA`.
    static let umops = Mnemonic(rawValue: 28686)

    /// SME `BMOPA` — binary (`Z.S`-by-`Z.S`) outer product, accumulating
    /// (FEAT_SME2; the former FEAT_SME_BI32I32).
    static let bmopa = Mnemonic(rawValue: 28687)
    /// SME `BMOPS` — binary outer product, subtracting from `ZA`.
    static let bmops = Mnemonic(rawValue: 28688)
}
