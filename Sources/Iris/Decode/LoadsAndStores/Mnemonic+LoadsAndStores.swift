// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic constants for the Loads & Stores family. Raw
// values 2048..2296 within the family's reserved 2048..4095 slab. 249 mnemonics
// covering every L/S instruction llvm-mc emits at
// -mattr=+v8.7a,+lse,+lor,+rcpc,+rcpc-immo,+pauth,+mte,+ssbs,+xs,+spe.
//
// llvm-mc emits a distinct mnemonic for each LSE atomic / CAS family
// (operation × size × ordering) combination; the operand register width
// further disambiguates 32-bit vs 64-bit forms within the same name.
// L/S mirrors that convention exactly so canonicalizer text parity holds.

public extension Mnemonic {
    // MARK: - Standard load/store integer (2048..2056)

    static let ldr = Mnemonic(rawValue: 2048)
    static let str = Mnemonic(rawValue: 2049)
    static let ldrb = Mnemonic(rawValue: 2050)
    static let strb = Mnemonic(rawValue: 2051)
    static let ldrh = Mnemonic(rawValue: 2052)
    static let strh = Mnemonic(rawValue: 2053)
    static let ldrsb = Mnemonic(rawValue: 2054)
    static let ldrsh = Mnemonic(rawValue: 2055)
    static let ldrsw = Mnemonic(rawValue: 2056)

    // MARK: - Unscaled-immediate load/store (LDUR family) + PRFUM (2057..2066)

    static let ldur = Mnemonic(rawValue: 2057)
    static let stur = Mnemonic(rawValue: 2058)
    static let ldurb = Mnemonic(rawValue: 2059)
    static let sturb = Mnemonic(rawValue: 2060)
    static let ldurh = Mnemonic(rawValue: 2061)
    static let sturh = Mnemonic(rawValue: 2062)
    static let ldursb = Mnemonic(rawValue: 2063)
    static let ldursh = Mnemonic(rawValue: 2064)
    static let ldursw = Mnemonic(rawValue: 2065)
    static let prfum = Mnemonic(rawValue: 2066)

    // MARK: - Load/store register pair (2067..2072)

    static let ldp = Mnemonic(rawValue: 2067)
    static let stp = Mnemonic(rawValue: 2068)
    static let ldpsw = Mnemonic(rawValue: 2069)
    static let stgp = Mnemonic(rawValue: 2070)
    static let ldnp = Mnemonic(rawValue: 2071)
    static let stnp = Mnemonic(rawValue: 2072)

    // MARK: - Load/store exclusive register + pair (2073..2088)

    static let ldxr = Mnemonic(rawValue: 2073)
    static let stxr = Mnemonic(rawValue: 2074)
    static let ldxrb = Mnemonic(rawValue: 2075)
    static let stxrb = Mnemonic(rawValue: 2076)
    static let ldxrh = Mnemonic(rawValue: 2077)
    static let stxrh = Mnemonic(rawValue: 2078)
    static let ldxp = Mnemonic(rawValue: 2079)
    static let stxp = Mnemonic(rawValue: 2080)
    static let ldaxr = Mnemonic(rawValue: 2081)
    static let stlxr = Mnemonic(rawValue: 2082)
    static let ldaxrb = Mnemonic(rawValue: 2083)
    static let stlxrb = Mnemonic(rawValue: 2084)
    static let ldaxrh = Mnemonic(rawValue: 2085)
    static let stlxrh = Mnemonic(rawValue: 2086)
    static let ldaxp = Mnemonic(rawValue: 2087)
    static let stlxp = Mnemonic(rawValue: 2088)

    // MARK: - Load-acquire / store-release (2089..2094)

    static let ldar = Mnemonic(rawValue: 2089)
    static let stlr = Mnemonic(rawValue: 2090)
    static let ldarb = Mnemonic(rawValue: 2091)
    static let stlrb = Mnemonic(rawValue: 2092)
    static let ldarh = Mnemonic(rawValue: 2093)
    static let stlrh = Mnemonic(rawValue: 2094)

    // MARK: - LRCPC (Armv8.3 — LDAPR family) (2095..2097)

    static let ldapr = Mnemonic(rawValue: 2095)
    static let ldaprb = Mnemonic(rawValue: 2096)
    static let ldaprh = Mnemonic(rawValue: 2097)

    // MARK: - LOR (FEAT_LOR — LDLAR / STLLR family) (2098..2103)

    static let ldlar = Mnemonic(rawValue: 2098)
    static let ldlarb = Mnemonic(rawValue: 2099)
    static let ldlarh = Mnemonic(rawValue: 2100)
    static let stllr = Mnemonic(rawValue: 2101)
    static let stllrb = Mnemonic(rawValue: 2102)
    static let stllrh = Mnemonic(rawValue: 2103)

    // MARK: - LRCPC2 (Armv8.4 unscaled-imm load-acquire / store-release) (2104..2112)

    static let ldapur = Mnemonic(rawValue: 2104)
    static let ldapurb = Mnemonic(rawValue: 2105)
    static let ldapurh = Mnemonic(rawValue: 2106)
    static let ldapursb = Mnemonic(rawValue: 2107)
    static let ldapursh = Mnemonic(rawValue: 2108)
    static let ldapursw = Mnemonic(rawValue: 2109)
    static let stlur = Mnemonic(rawValue: 2110)
    static let stlurb = Mnemonic(rawValue: 2111)
    static let stlurh = Mnemonic(rawValue: 2112)

    // MARK: - LSE atomics — RMW operations (Armv8.1) (2113..2220)

    // 9 ops × 4 orderings × 3 size-suffixes (no-suffix / B / H) = 108 mnemonics.
    // The 32-bit vs 64-bit width is encoded in the operand register Wt vs Xt
    // for the no-suffix variants; B suffix = 8-bit, H suffix = 16-bit.

    // LDADD family — 2113..2124
    static let ldadd = Mnemonic(rawValue: 2113)
    static let ldadda = Mnemonic(rawValue: 2114)
    static let ldaddl = Mnemonic(rawValue: 2115)
    static let ldaddal = Mnemonic(rawValue: 2116)
    static let ldaddb = Mnemonic(rawValue: 2117)
    static let ldaddab = Mnemonic(rawValue: 2118)
    static let ldaddlb = Mnemonic(rawValue: 2119)
    static let ldaddalb = Mnemonic(rawValue: 2120)
    static let ldaddh = Mnemonic(rawValue: 2121)
    static let ldaddah = Mnemonic(rawValue: 2122)
    static let ldaddlh = Mnemonic(rawValue: 2123)
    static let ldaddalh = Mnemonic(rawValue: 2124)

    // LDCLR family — 2125..2136
    static let ldclr = Mnemonic(rawValue: 2125)
    static let ldclra = Mnemonic(rawValue: 2126)
    static let ldclrl = Mnemonic(rawValue: 2127)
    static let ldclral = Mnemonic(rawValue: 2128)
    static let ldclrb = Mnemonic(rawValue: 2129)
    static let ldclrab = Mnemonic(rawValue: 2130)
    static let ldclrlb = Mnemonic(rawValue: 2131)
    static let ldclralb = Mnemonic(rawValue: 2132)
    static let ldclrh = Mnemonic(rawValue: 2133)
    static let ldclrah = Mnemonic(rawValue: 2134)
    static let ldclrlh = Mnemonic(rawValue: 2135)
    static let ldclralh = Mnemonic(rawValue: 2136)

    // LDEOR family — 2137..2148
    static let ldeor = Mnemonic(rawValue: 2137)
    static let ldeora = Mnemonic(rawValue: 2138)
    static let ldeorl = Mnemonic(rawValue: 2139)
    static let ldeoral = Mnemonic(rawValue: 2140)
    static let ldeorb = Mnemonic(rawValue: 2141)
    static let ldeorab = Mnemonic(rawValue: 2142)
    static let ldeorlb = Mnemonic(rawValue: 2143)
    static let ldeoralb = Mnemonic(rawValue: 2144)
    static let ldeorh = Mnemonic(rawValue: 2145)
    static let ldeorah = Mnemonic(rawValue: 2146)
    static let ldeorlh = Mnemonic(rawValue: 2147)
    static let ldeoralh = Mnemonic(rawValue: 2148)

    // LDSET family — 2149..2160
    static let ldset = Mnemonic(rawValue: 2149)
    static let ldseta = Mnemonic(rawValue: 2150)
    static let ldsetl = Mnemonic(rawValue: 2151)
    static let ldsetal = Mnemonic(rawValue: 2152)
    static let ldsetb = Mnemonic(rawValue: 2153)
    static let ldsetab = Mnemonic(rawValue: 2154)
    static let ldsetlb = Mnemonic(rawValue: 2155)
    static let ldsetalb = Mnemonic(rawValue: 2156)
    static let ldseth = Mnemonic(rawValue: 2157)
    static let ldsetah = Mnemonic(rawValue: 2158)
    static let ldsetlh = Mnemonic(rawValue: 2159)
    static let ldsetalh = Mnemonic(rawValue: 2160)

    // LDSMAX family — 2161..2172
    static let ldsmax = Mnemonic(rawValue: 2161)
    static let ldsmaxa = Mnemonic(rawValue: 2162)
    static let ldsmaxl = Mnemonic(rawValue: 2163)
    static let ldsmaxal = Mnemonic(rawValue: 2164)
    static let ldsmaxb = Mnemonic(rawValue: 2165)
    static let ldsmaxab = Mnemonic(rawValue: 2166)
    static let ldsmaxlb = Mnemonic(rawValue: 2167)
    static let ldsmaxalb = Mnemonic(rawValue: 2168)
    static let ldsmaxh = Mnemonic(rawValue: 2169)
    static let ldsmaxah = Mnemonic(rawValue: 2170)
    static let ldsmaxlh = Mnemonic(rawValue: 2171)
    static let ldsmaxalh = Mnemonic(rawValue: 2172)

    // LDSMIN family — 2173..2184
    static let ldsmin = Mnemonic(rawValue: 2173)
    static let ldsmina = Mnemonic(rawValue: 2174)
    static let ldsminl = Mnemonic(rawValue: 2175)
    static let ldsminal = Mnemonic(rawValue: 2176)
    static let ldsminb = Mnemonic(rawValue: 2177)
    static let ldsminab = Mnemonic(rawValue: 2178)
    static let ldsminlb = Mnemonic(rawValue: 2179)
    static let ldsminalb = Mnemonic(rawValue: 2180)
    static let ldsminh = Mnemonic(rawValue: 2181)
    static let ldsminah = Mnemonic(rawValue: 2182)
    static let ldsminlh = Mnemonic(rawValue: 2183)
    static let ldsminalh = Mnemonic(rawValue: 2184)

    // LDUMAX family — 2185..2196
    static let ldumax = Mnemonic(rawValue: 2185)
    static let ldumaxa = Mnemonic(rawValue: 2186)
    static let ldumaxl = Mnemonic(rawValue: 2187)
    static let ldumaxal = Mnemonic(rawValue: 2188)
    static let ldumaxb = Mnemonic(rawValue: 2189)
    static let ldumaxab = Mnemonic(rawValue: 2190)
    static let ldumaxlb = Mnemonic(rawValue: 2191)
    static let ldumaxalb = Mnemonic(rawValue: 2192)
    static let ldumaxh = Mnemonic(rawValue: 2193)
    static let ldumaxah = Mnemonic(rawValue: 2194)
    static let ldumaxlh = Mnemonic(rawValue: 2195)
    static let ldumaxalh = Mnemonic(rawValue: 2196)

    // LDUMIN family — 2197..2208
    static let ldumin = Mnemonic(rawValue: 2197)
    static let ldumina = Mnemonic(rawValue: 2198)
    static let lduminl = Mnemonic(rawValue: 2199)
    static let lduminal = Mnemonic(rawValue: 2200)
    static let lduminb = Mnemonic(rawValue: 2201)
    static let lduminab = Mnemonic(rawValue: 2202)
    static let lduminlb = Mnemonic(rawValue: 2203)
    static let lduminalb = Mnemonic(rawValue: 2204)
    static let lduminh = Mnemonic(rawValue: 2205)
    static let lduminah = Mnemonic(rawValue: 2206)
    static let lduminlh = Mnemonic(rawValue: 2207)
    static let lduminalh = Mnemonic(rawValue: 2208)

    // SWP family — 2209..2220
    static let swp = Mnemonic(rawValue: 2209)
    static let swpa = Mnemonic(rawValue: 2210)
    static let swpl = Mnemonic(rawValue: 2211)
    static let swpal = Mnemonic(rawValue: 2212)
    static let swpb = Mnemonic(rawValue: 2213)
    static let swpab = Mnemonic(rawValue: 2214)
    static let swplb = Mnemonic(rawValue: 2215)
    static let swpalb = Mnemonic(rawValue: 2216)
    static let swph = Mnemonic(rawValue: 2217)
    static let swpah = Mnemonic(rawValue: 2218)
    static let swplh = Mnemonic(rawValue: 2219)
    static let swpalh = Mnemonic(rawValue: 2220)

    // MARK: - LSE store-aliases (Rt=ZR collapses to ST* form) (2221..2268)

    // An LSE RMW collapses to its ST* alias only when Rt=ZR AND the acquire
    // bit A=0 — llvm-mc keeps the LD* form for the A=1 (acquire /
    // acquire-release) orderings, so STADDA / STADDAL and the like are not
    // ARM64 mnemonics. 8 RMW ops (no SWP) × 2 A=0 orderings (plain, release)
    // × 3 size-suffixes = 48 mnemonics.

    // STADD family — 2221..2226
    static let stadd = Mnemonic(rawValue: 2221)
    static let staddl = Mnemonic(rawValue: 2222)
    static let staddb = Mnemonic(rawValue: 2223)
    static let staddlb = Mnemonic(rawValue: 2224)
    static let staddh = Mnemonic(rawValue: 2225)
    static let staddlh = Mnemonic(rawValue: 2226)

    // STCLR family — 2227..2232
    static let stclr = Mnemonic(rawValue: 2227)
    static let stclrl = Mnemonic(rawValue: 2228)
    static let stclrb = Mnemonic(rawValue: 2229)
    static let stclrlb = Mnemonic(rawValue: 2230)
    static let stclrh = Mnemonic(rawValue: 2231)
    static let stclrlh = Mnemonic(rawValue: 2232)

    // STEOR family — 2233..2238
    static let steor = Mnemonic(rawValue: 2233)
    static let steorl = Mnemonic(rawValue: 2234)
    static let steorb = Mnemonic(rawValue: 2235)
    static let steorlb = Mnemonic(rawValue: 2236)
    static let steorh = Mnemonic(rawValue: 2237)
    static let steorlh = Mnemonic(rawValue: 2238)

    // STSET family — 2239..2244
    static let stset = Mnemonic(rawValue: 2239)
    static let stsetl = Mnemonic(rawValue: 2240)
    static let stsetb = Mnemonic(rawValue: 2241)
    static let stsetlb = Mnemonic(rawValue: 2242)
    static let stseth = Mnemonic(rawValue: 2243)
    static let stsetlh = Mnemonic(rawValue: 2244)

    // STSMAX family — 2245..2250
    static let stsmax = Mnemonic(rawValue: 2245)
    static let stsmaxl = Mnemonic(rawValue: 2246)
    static let stsmaxb = Mnemonic(rawValue: 2247)
    static let stsmaxlb = Mnemonic(rawValue: 2248)
    static let stsmaxh = Mnemonic(rawValue: 2249)
    static let stsmaxlh = Mnemonic(rawValue: 2250)

    // STSMIN family — 2251..2256
    static let stsmin = Mnemonic(rawValue: 2251)
    static let stsminl = Mnemonic(rawValue: 2252)
    static let stsminb = Mnemonic(rawValue: 2253)
    static let stsminlb = Mnemonic(rawValue: 2254)
    static let stsminh = Mnemonic(rawValue: 2255)
    static let stsminlh = Mnemonic(rawValue: 2256)

    // STUMAX family — 2257..2262
    static let stumax = Mnemonic(rawValue: 2257)
    static let stumaxl = Mnemonic(rawValue: 2258)
    static let stumaxb = Mnemonic(rawValue: 2259)
    static let stumaxlb = Mnemonic(rawValue: 2260)
    static let stumaxh = Mnemonic(rawValue: 2261)
    static let stumaxlh = Mnemonic(rawValue: 2262)

    // STUMIN family — 2263..2268
    static let stumin = Mnemonic(rawValue: 2263)
    static let stuminl = Mnemonic(rawValue: 2264)
    static let stuminb = Mnemonic(rawValue: 2265)
    static let stuminlb = Mnemonic(rawValue: 2266)
    static let stuminh = Mnemonic(rawValue: 2267)
    static let stuminlh = Mnemonic(rawValue: 2268)

    // MARK: - Compare-and-swap (CAS) family (2269..2284)

    static let cas = Mnemonic(rawValue: 2269)
    static let casa = Mnemonic(rawValue: 2270)
    static let casl = Mnemonic(rawValue: 2271)
    static let casal = Mnemonic(rawValue: 2272)
    static let casb = Mnemonic(rawValue: 2273)
    static let casab = Mnemonic(rawValue: 2274)
    static let caslb = Mnemonic(rawValue: 2275)
    static let casalb = Mnemonic(rawValue: 2276)
    static let cash = Mnemonic(rawValue: 2277)
    static let casah = Mnemonic(rawValue: 2278)
    static let caslh = Mnemonic(rawValue: 2279)
    static let casalh = Mnemonic(rawValue: 2280)
    static let casp = Mnemonic(rawValue: 2281)
    static let caspa = Mnemonic(rawValue: 2282)
    static let caspl = Mnemonic(rawValue: 2283)
    static let caspal = Mnemonic(rawValue: 2284)

    // MARK: - Prefetch (2285)

    static let prfm = Mnemonic(rawValue: 2285)
    // prfum is already declared above (2066) alongside the LDUR family.

    // MARK: - ARM64E PAC authenticated loads (2286..2287)

    static let ldraa = Mnemonic(rawValue: 2286)
    static let ldrab = Mnemonic(rawValue: 2287)

    // MARK: - Unprivileged load/store (LDTR family) (2288..2296)

    static let ldtr = Mnemonic(rawValue: 2288)
    static let sttr = Mnemonic(rawValue: 2289)
    static let ldtrb = Mnemonic(rawValue: 2290)
    static let sttrb = Mnemonic(rawValue: 2291)
    static let ldtrh = Mnemonic(rawValue: 2292)
    static let sttrh = Mnemonic(rawValue: 2293)
    static let ldtrsb = Mnemonic(rawValue: 2294)
    static let ldtrsh = Mnemonic(rawValue: 2295)
    static let ldtrsw = Mnemonic(rawValue: 2296)

    // FEAT_LSUI (unprivileged load/store).
    static let ldtp = Mnemonic(rawValue: 2297)
    static let sttp = Mnemonic(rawValue: 2298)
    static let ldtnp = Mnemonic(rawValue: 2299)
    static let sttnp = Mnemonic(rawValue: 2300)

    // FEAT_LSUI unprivileged exclusive + compare-and-swap.
    static let sttxr = Mnemonic(rawValue: 2301)
    static let stltxr = Mnemonic(rawValue: 2302)
    static let ldtxr = Mnemonic(rawValue: 2303)
    static let ldatxr = Mnemonic(rawValue: 2304)
    static let cast = Mnemonic(rawValue: 2305)
    static let casat = Mnemonic(rawValue: 2306)
    static let caslt = Mnemonic(rawValue: 2307)
    static let casalt = Mnemonic(rawValue: 2308)
    static let caspt = Mnemonic(rawValue: 2309)
    static let caspat = Mnemonic(rawValue: 2310)
    static let casplt = Mnemonic(rawValue: 2311)
    static let caspalt = Mnemonic(rawValue: 2312)

    // MARK: - FEAT_RPRES range prefetch (2313)

    static let rprfm = Mnemonic(rawValue: 2313)

    // MARK: - FEAT_LS64 accelerator load/store (2314..2317)

    static let ld64b = Mnemonic(rawValue: 2314)
    static let st64b = Mnemonic(rawValue: 2315)
    static let st64bv = Mnemonic(rawValue: 2316)
    static let st64bv0 = Mnemonic(rawValue: 2317)

    // MARK: - FEAT_LSE128 128-bit atomics (2318..2329)

    static let swpp = Mnemonic(rawValue: 2318)
    static let swppa = Mnemonic(rawValue: 2319)
    static let swppl = Mnemonic(rawValue: 2320)
    static let swppal = Mnemonic(rawValue: 2321)
    static let ldclrp = Mnemonic(rawValue: 2322)
    static let ldclrpa = Mnemonic(rawValue: 2323)
    static let ldclrpl = Mnemonic(rawValue: 2324)
    static let ldclrpal = Mnemonic(rawValue: 2325)
    static let ldsetp = Mnemonic(rawValue: 2326)
    static let ldsetpa = Mnemonic(rawValue: 2327)
    static let ldsetpl = Mnemonic(rawValue: 2328)
    static let ldsetpal = Mnemonic(rawValue: 2329)

    // MARK: - FEAT_MOPS memory copy (2330..2425)

    // CPYF (forward-only) then CPY (bidirectional), each P/M/E stage ×
    // 16 option combos (bits15:14 nontemporal, bits13:12 read/write).
    static let cpyfp = Mnemonic(rawValue: 2330)
    static let cpyfpwt = Mnemonic(rawValue: 2331)
    static let cpyfprt = Mnemonic(rawValue: 2332)
    static let cpyfpt = Mnemonic(rawValue: 2333)
    static let cpyfpwn = Mnemonic(rawValue: 2334)
    static let cpyfpwtwn = Mnemonic(rawValue: 2335)
    static let cpyfprtwn = Mnemonic(rawValue: 2336)
    static let cpyfptwn = Mnemonic(rawValue: 2337)
    static let cpyfprn = Mnemonic(rawValue: 2338)
    static let cpyfpwtrn = Mnemonic(rawValue: 2339)
    static let cpyfprtrn = Mnemonic(rawValue: 2340)
    static let cpyfptrn = Mnemonic(rawValue: 2341)
    static let cpyfpn = Mnemonic(rawValue: 2342)
    static let cpyfpwtn = Mnemonic(rawValue: 2343)
    static let cpyfprtn = Mnemonic(rawValue: 2344)
    static let cpyfptn = Mnemonic(rawValue: 2345)
    static let cpyfm = Mnemonic(rawValue: 2346)
    static let cpyfmwt = Mnemonic(rawValue: 2347)
    static let cpyfmrt = Mnemonic(rawValue: 2348)
    static let cpyfmt = Mnemonic(rawValue: 2349)
    static let cpyfmwn = Mnemonic(rawValue: 2350)
    static let cpyfmwtwn = Mnemonic(rawValue: 2351)
    static let cpyfmrtwn = Mnemonic(rawValue: 2352)
    static let cpyfmtwn = Mnemonic(rawValue: 2353)
    static let cpyfmrn = Mnemonic(rawValue: 2354)
    static let cpyfmwtrn = Mnemonic(rawValue: 2355)
    static let cpyfmrtrn = Mnemonic(rawValue: 2356)
    static let cpyfmtrn = Mnemonic(rawValue: 2357)
    static let cpyfmn = Mnemonic(rawValue: 2358)
    static let cpyfmwtn = Mnemonic(rawValue: 2359)
    static let cpyfmrtn = Mnemonic(rawValue: 2360)
    static let cpyfmtn = Mnemonic(rawValue: 2361)
    static let cpyfe = Mnemonic(rawValue: 2362)
    static let cpyfewt = Mnemonic(rawValue: 2363)
    static let cpyfert = Mnemonic(rawValue: 2364)
    static let cpyfet = Mnemonic(rawValue: 2365)
    static let cpyfewn = Mnemonic(rawValue: 2366)
    static let cpyfewtwn = Mnemonic(rawValue: 2367)
    static let cpyfertwn = Mnemonic(rawValue: 2368)
    static let cpyfetwn = Mnemonic(rawValue: 2369)
    static let cpyfern = Mnemonic(rawValue: 2370)
    static let cpyfewtrn = Mnemonic(rawValue: 2371)
    static let cpyfertrn = Mnemonic(rawValue: 2372)
    static let cpyfetrn = Mnemonic(rawValue: 2373)
    static let cpyfen = Mnemonic(rawValue: 2374)
    static let cpyfewtn = Mnemonic(rawValue: 2375)
    static let cpyfertn = Mnemonic(rawValue: 2376)
    static let cpyfetn = Mnemonic(rawValue: 2377)
    static let cpyp = Mnemonic(rawValue: 2378)
    static let cpypwt = Mnemonic(rawValue: 2379)
    static let cpyprt = Mnemonic(rawValue: 2380)
    static let cpypt = Mnemonic(rawValue: 2381)
    static let cpypwn = Mnemonic(rawValue: 2382)
    static let cpypwtwn = Mnemonic(rawValue: 2383)
    static let cpyprtwn = Mnemonic(rawValue: 2384)
    static let cpyptwn = Mnemonic(rawValue: 2385)
    static let cpyprn = Mnemonic(rawValue: 2386)
    static let cpypwtrn = Mnemonic(rawValue: 2387)
    static let cpyprtrn = Mnemonic(rawValue: 2388)
    static let cpyptrn = Mnemonic(rawValue: 2389)
    static let cpypn = Mnemonic(rawValue: 2390)
    static let cpypwtn = Mnemonic(rawValue: 2391)
    static let cpyprtn = Mnemonic(rawValue: 2392)
    static let cpyptn = Mnemonic(rawValue: 2393)
    static let cpym = Mnemonic(rawValue: 2394)
    static let cpymwt = Mnemonic(rawValue: 2395)
    static let cpymrt = Mnemonic(rawValue: 2396)
    static let cpymt = Mnemonic(rawValue: 2397)
    static let cpymwn = Mnemonic(rawValue: 2398)
    static let cpymwtwn = Mnemonic(rawValue: 2399)
    static let cpymrtwn = Mnemonic(rawValue: 2400)
    static let cpymtwn = Mnemonic(rawValue: 2401)
    static let cpymrn = Mnemonic(rawValue: 2402)
    static let cpymwtrn = Mnemonic(rawValue: 2403)
    static let cpymrtrn = Mnemonic(rawValue: 2404)
    static let cpymtrn = Mnemonic(rawValue: 2405)
    static let cpymn = Mnemonic(rawValue: 2406)
    static let cpymwtn = Mnemonic(rawValue: 2407)
    static let cpymrtn = Mnemonic(rawValue: 2408)
    static let cpymtn = Mnemonic(rawValue: 2409)
    static let cpye = Mnemonic(rawValue: 2410)
    static let cpyewt = Mnemonic(rawValue: 2411)
    static let cpyert = Mnemonic(rawValue: 2412)
    static let cpyet = Mnemonic(rawValue: 2413)
    static let cpyewn = Mnemonic(rawValue: 2414)
    static let cpyewtwn = Mnemonic(rawValue: 2415)
    static let cpyertwn = Mnemonic(rawValue: 2416)
    static let cpyetwn = Mnemonic(rawValue: 2417)
    static let cpyern = Mnemonic(rawValue: 2418)
    static let cpyewtrn = Mnemonic(rawValue: 2419)
    static let cpyertrn = Mnemonic(rawValue: 2420)
    static let cpyetrn = Mnemonic(rawValue: 2421)
    static let cpyen = Mnemonic(rawValue: 2422)
    static let cpyewtn = Mnemonic(rawValue: 2423)
    static let cpyertn = Mnemonic(rawValue: 2424)
    static let cpyetn = Mnemonic(rawValue: 2425)

    // MARK: - FEAT_MOPS memory set (2426..2449)

    // SET (memory set) then SETG (set with tag), each P/M/E stage × 4
    // option combos (bit13 nontemporal, bit12 unprivileged).
    static let setp = Mnemonic(rawValue: 2426)
    static let setpt = Mnemonic(rawValue: 2427)
    static let setpn = Mnemonic(rawValue: 2428)
    static let setptn = Mnemonic(rawValue: 2429)
    static let setm = Mnemonic(rawValue: 2430)
    static let setmt = Mnemonic(rawValue: 2431)
    static let setmn = Mnemonic(rawValue: 2432)
    static let setmtn = Mnemonic(rawValue: 2433)
    static let sete = Mnemonic(rawValue: 2434)
    static let setet = Mnemonic(rawValue: 2435)
    static let seten = Mnemonic(rawValue: 2436)
    static let setetn = Mnemonic(rawValue: 2437)
    static let setgp = Mnemonic(rawValue: 2438)
    static let setgpt = Mnemonic(rawValue: 2439)
    static let setgpn = Mnemonic(rawValue: 2440)
    static let setgptn = Mnemonic(rawValue: 2441)
    static let setgm = Mnemonic(rawValue: 2442)
    static let setgmt = Mnemonic(rawValue: 2443)
    static let setgmn = Mnemonic(rawValue: 2444)
    static let setgmtn = Mnemonic(rawValue: 2445)
    static let setge = Mnemonic(rawValue: 2446)
    static let setget = Mnemonic(rawValue: 2447)
    static let setgen = Mnemonic(rawValue: 2448)
    static let setgetn = Mnemonic(rawValue: 2449)

    // MARK: - FEAT_LSUI unprivileged atomics (2450..2465)

    // ldtadd/ldtclr/ldtset/swpt, each × {plain,L,A,AL}; size in operand width.
    static let ldtadd = Mnemonic(rawValue: 2450)
    static let ldtaddl = Mnemonic(rawValue: 2451)
    static let ldtadda = Mnemonic(rawValue: 2452)
    static let ldtaddal = Mnemonic(rawValue: 2453)
    static let ldtclr = Mnemonic(rawValue: 2454)
    static let ldtclrl = Mnemonic(rawValue: 2455)
    static let ldtclra = Mnemonic(rawValue: 2456)
    static let ldtclral = Mnemonic(rawValue: 2457)
    static let ldtset = Mnemonic(rawValue: 2458)
    static let ldtsetl = Mnemonic(rawValue: 2459)
    static let ldtseta = Mnemonic(rawValue: 2460)
    static let ldtsetal = Mnemonic(rawValue: 2461)
    static let swpt = Mnemonic(rawValue: 2462)
    static let swptl = Mnemonic(rawValue: 2463)
    static let swpta = Mnemonic(rawValue: 2464)
    static let swptal = Mnemonic(rawValue: 2465)

    // MARK: - FEAT_THE RCW (Read-Check-Write) atomics (2466..2529)

    // Non-pair clr/swp/set (2466..2489): rcw* (32-bit check) + rcws*
    // (64-bit check), each × {plain,L,A,AL}; size in operand width.
    static let rcwclr = Mnemonic(rawValue: 2466)
    static let rcwclrl = Mnemonic(rawValue: 2467)
    static let rcwclra = Mnemonic(rawValue: 2468)
    static let rcwclral = Mnemonic(rawValue: 2469)
    static let rcwswp = Mnemonic(rawValue: 2470)
    static let rcwswpl = Mnemonic(rawValue: 2471)
    static let rcwswpa = Mnemonic(rawValue: 2472)
    static let rcwswpal = Mnemonic(rawValue: 2473)
    static let rcwset = Mnemonic(rawValue: 2474)
    static let rcwsetl = Mnemonic(rawValue: 2475)
    static let rcwseta = Mnemonic(rawValue: 2476)
    static let rcwsetal = Mnemonic(rawValue: 2477)
    static let rcwsclr = Mnemonic(rawValue: 2478)
    static let rcwsclrl = Mnemonic(rawValue: 2479)
    static let rcwsclra = Mnemonic(rawValue: 2480)
    static let rcwsclral = Mnemonic(rawValue: 2481)
    static let rcwsswp = Mnemonic(rawValue: 2482)
    static let rcwsswpl = Mnemonic(rawValue: 2483)
    static let rcwsswpa = Mnemonic(rawValue: 2484)
    static let rcwsswpal = Mnemonic(rawValue: 2485)
    static let rcwsset = Mnemonic(rawValue: 2486)
    static let rcwssetl = Mnemonic(rawValue: 2487)
    static let rcwsseta = Mnemonic(rawValue: 2488)
    static let rcwssetal = Mnemonic(rawValue: 2489)
    // CAS non-pair (2490..2497).
    static let rcwcas = Mnemonic(rawValue: 2490)
    static let rcwcasl = Mnemonic(rawValue: 2491)
    static let rcwcasa = Mnemonic(rawValue: 2492)
    static let rcwcasal = Mnemonic(rawValue: 2493)
    static let rcwscas = Mnemonic(rawValue: 2494)
    static let rcwscasl = Mnemonic(rawValue: 2495)
    static let rcwscasa = Mnemonic(rawValue: 2496)
    static let rcwscasal = Mnemonic(rawValue: 2497)
    // 128-bit pair clrp/swpp/setp (2498..2521).
    static let rcwclrp = Mnemonic(rawValue: 2498)
    static let rcwclrpl = Mnemonic(rawValue: 2499)
    static let rcwclrpa = Mnemonic(rawValue: 2500)
    static let rcwclrpal = Mnemonic(rawValue: 2501)
    static let rcwswpp = Mnemonic(rawValue: 2502)
    static let rcwswppl = Mnemonic(rawValue: 2503)
    static let rcwswppa = Mnemonic(rawValue: 2504)
    static let rcwswppal = Mnemonic(rawValue: 2505)
    static let rcwsetp = Mnemonic(rawValue: 2506)
    static let rcwsetpl = Mnemonic(rawValue: 2507)
    static let rcwsetpa = Mnemonic(rawValue: 2508)
    static let rcwsetpal = Mnemonic(rawValue: 2509)
    static let rcwsclrp = Mnemonic(rawValue: 2510)
    static let rcwsclrpl = Mnemonic(rawValue: 2511)
    static let rcwsclrpa = Mnemonic(rawValue: 2512)
    static let rcwsclrpal = Mnemonic(rawValue: 2513)
    static let rcwsswpp = Mnemonic(rawValue: 2514)
    static let rcwsswppl = Mnemonic(rawValue: 2515)
    static let rcwsswppa = Mnemonic(rawValue: 2516)
    static let rcwsswppal = Mnemonic(rawValue: 2517)
    static let rcwssetp = Mnemonic(rawValue: 2518)
    static let rcwssetpl = Mnemonic(rawValue: 2519)
    static let rcwssetpa = Mnemonic(rawValue: 2520)
    static let rcwssetpal = Mnemonic(rawValue: 2521)
    // CASP 128-bit pair (2522..2529).
    static let rcwcasp = Mnemonic(rawValue: 2522)
    static let rcwcaspl = Mnemonic(rawValue: 2523)
    static let rcwcaspa = Mnemonic(rawValue: 2524)
    static let rcwcaspal = Mnemonic(rawValue: 2525)
    static let rcwscasp = Mnemonic(rawValue: 2526)
    static let rcwscaspl = Mnemonic(rawValue: 2527)
    static let rcwscaspa = Mnemonic(rawValue: 2528)
    static let rcwscaspal = Mnemonic(rawValue: 2529)

    // MARK: - FEAT_RCPC3 ordered load/store pair (2530..2531)

    static let stilp = Mnemonic(rawValue: 2530)
    static let ldiapp = Mnemonic(rawValue: 2531)

    // MARK: - FEAT_GCS guarded control stack store (2532..2533)

    static let gcsstr = Mnemonic(rawValue: 2532)
    static let gcssttr = Mnemonic(rawValue: 2533)

    // MARK: - FEAT_LSUI ST-aliases (Rt=ZR, A=0 collapses LDT* to STT*) (2534..2539)

    static let sttadd = Mnemonic(rawValue: 2534)
    static let sttaddl = Mnemonic(rawValue: 2535)
    static let sttclr = Mnemonic(rawValue: 2536)
    static let sttclrl = Mnemonic(rawValue: 2537)
    static let sttset = Mnemonic(rawValue: 2538)
    static let sttsetl = Mnemonic(rawValue: 2539)
}

extension Mnemonic {
    /// Canonical lowercase name for every Loads & Stores mnemonic constant —
    /// the family's slice of ``Mnemonic/name``, declared beside the
    /// constants it names so the two cannot drift. Unallocated raw
    /// values in the family's range return `"?<raw>"`.
    static func loadsAndStoresName(_ m: Mnemonic) -> String {
        switch m {
        case .ldr: "ldr"
        case .str: "str"
        case .ldrb: "ldrb"
        case .strb: "strb"
        case .ldrh: "ldrh"
        case .strh: "strh"
        case .ldrsb: "ldrsb"
        case .ldrsh: "ldrsh"
        case .ldrsw: "ldrsw"
        case .ldur: "ldur"
        case .stur: "stur"
        case .ldurb: "ldurb"
        case .sturb: "sturb"
        case .ldurh: "ldurh"
        case .sturh: "sturh"
        case .ldursb: "ldursb"
        case .ldursh: "ldursh"
        case .ldursw: "ldursw"
        case .prfum: "prfum"
        case .ldp: "ldp"
        case .stp: "stp"
        case .ldpsw: "ldpsw"
        case .stgp: "stgp"
        case .ldnp: "ldnp"
        case .stnp: "stnp"
        case .ldxr: "ldxr"
        case .stxr: "stxr"
        case .ldxrb: "ldxrb"
        case .stxrb: "stxrb"
        case .ldxrh: "ldxrh"
        case .stxrh: "stxrh"
        case .ldxp: "ldxp"
        case .stxp: "stxp"
        case .ldaxr: "ldaxr"
        case .stlxr: "stlxr"
        case .ldaxrb: "ldaxrb"
        case .stlxrb: "stlxrb"
        case .ldaxrh: "ldaxrh"
        case .stlxrh: "stlxrh"
        case .ldaxp: "ldaxp"
        case .stlxp: "stlxp"
        case .ldar: "ldar"
        case .stlr: "stlr"
        case .ldarb: "ldarb"
        case .stlrb: "stlrb"
        case .ldarh: "ldarh"
        case .stlrh: "stlrh"
        case .ldapr: "ldapr"
        case .ldaprb: "ldaprb"
        case .ldaprh: "ldaprh"
        case .ldlar: "ldlar"
        case .ldlarb: "ldlarb"
        case .ldlarh: "ldlarh"
        case .stllr: "stllr"
        case .stllrb: "stllrb"
        case .stllrh: "stllrh"
        case .ldapur: "ldapur"
        case .ldapurb: "ldapurb"
        case .ldapurh: "ldapurh"
        case .ldapursb: "ldapursb"
        case .ldapursh: "ldapursh"
        case .ldapursw: "ldapursw"
        case .stlur: "stlur"
        case .stlurb: "stlurb"
        case .stlurh: "stlurh"
        case .ldadd: "ldadd"
        case .ldadda: "ldadda"
        case .ldaddl: "ldaddl"
        case .ldaddal: "ldaddal"
        case .ldaddb: "ldaddb"
        case .ldaddab: "ldaddab"
        case .ldaddlb: "ldaddlb"
        case .ldaddalb: "ldaddalb"
        case .ldaddh: "ldaddh"
        case .ldaddah: "ldaddah"
        case .ldaddlh: "ldaddlh"
        case .ldaddalh: "ldaddalh"
        case .ldclr: "ldclr"
        case .ldclra: "ldclra"
        case .ldclrl: "ldclrl"
        case .ldclral: "ldclral"
        case .ldclrb: "ldclrb"
        case .ldclrab: "ldclrab"
        case .ldclrlb: "ldclrlb"
        case .ldclralb: "ldclralb"
        case .ldclrh: "ldclrh"
        case .ldclrah: "ldclrah"
        case .ldclrlh: "ldclrlh"
        case .ldclralh: "ldclralh"
        case .ldeor: "ldeor"
        case .ldeora: "ldeora"
        case .ldeorl: "ldeorl"
        case .ldeoral: "ldeoral"
        case .ldeorb: "ldeorb"
        case .ldeorab: "ldeorab"
        case .ldeorlb: "ldeorlb"
        case .ldeoralb: "ldeoralb"
        case .ldeorh: "ldeorh"
        case .ldeorah: "ldeorah"
        case .ldeorlh: "ldeorlh"
        case .ldeoralh: "ldeoralh"
        case .ldset: "ldset"
        case .ldseta: "ldseta"
        case .ldsetl: "ldsetl"
        case .ldsetal: "ldsetal"
        case .ldsetb: "ldsetb"
        case .ldsetab: "ldsetab"
        case .ldsetlb: "ldsetlb"
        case .ldsetalb: "ldsetalb"
        case .ldseth: "ldseth"
        case .ldsetah: "ldsetah"
        case .ldsetlh: "ldsetlh"
        case .ldsetalh: "ldsetalh"
        case .ldsmax: "ldsmax"
        case .ldsmaxa: "ldsmaxa"
        case .ldsmaxl: "ldsmaxl"
        case .ldsmaxal: "ldsmaxal"
        case .ldsmaxb: "ldsmaxb"
        case .ldsmaxab: "ldsmaxab"
        case .ldsmaxlb: "ldsmaxlb"
        case .ldsmaxalb: "ldsmaxalb"
        case .ldsmaxh: "ldsmaxh"
        case .ldsmaxah: "ldsmaxah"
        case .ldsmaxlh: "ldsmaxlh"
        case .ldsmaxalh: "ldsmaxalh"
        case .ldsmin: "ldsmin"
        case .ldsmina: "ldsmina"
        case .ldsminl: "ldsminl"
        case .ldsminal: "ldsminal"
        case .ldsminb: "ldsminb"
        case .ldsminab: "ldsminab"
        case .ldsminlb: "ldsminlb"
        case .ldsminalb: "ldsminalb"
        case .ldsminh: "ldsminh"
        case .ldsminah: "ldsminah"
        case .ldsminlh: "ldsminlh"
        case .ldsminalh: "ldsminalh"
        case .ldumax: "ldumax"
        case .ldumaxa: "ldumaxa"
        case .ldumaxl: "ldumaxl"
        case .ldumaxal: "ldumaxal"
        case .ldumaxb: "ldumaxb"
        case .ldumaxab: "ldumaxab"
        case .ldumaxlb: "ldumaxlb"
        case .ldumaxalb: "ldumaxalb"
        case .ldumaxh: "ldumaxh"
        case .ldumaxah: "ldumaxah"
        case .ldumaxlh: "ldumaxlh"
        case .ldumaxalh: "ldumaxalh"
        case .ldumin: "ldumin"
        case .ldumina: "ldumina"
        case .lduminl: "lduminl"
        case .lduminal: "lduminal"
        case .lduminb: "lduminb"
        case .lduminab: "lduminab"
        case .lduminlb: "lduminlb"
        case .lduminalb: "lduminalb"
        case .lduminh: "lduminh"
        case .lduminah: "lduminah"
        case .lduminlh: "lduminlh"
        case .lduminalh: "lduminalh"
        case .swp: "swp"
        case .swpa: "swpa"
        case .swpl: "swpl"
        case .swpal: "swpal"
        case .swpb: "swpb"
        case .swpab: "swpab"
        case .swplb: "swplb"
        case .swpalb: "swpalb"
        case .swph: "swph"
        case .swpah: "swpah"
        case .swplh: "swplh"
        case .swpalh: "swpalh"
        case .stadd: "stadd"
        case .staddl: "staddl"
        case .staddb: "staddb"
        case .staddlb: "staddlb"
        case .staddh: "staddh"
        case .staddlh: "staddlh"
        case .stclr: "stclr"
        case .stclrl: "stclrl"
        case .stclrb: "stclrb"
        case .stclrlb: "stclrlb"
        case .stclrh: "stclrh"
        case .stclrlh: "stclrlh"
        case .steor: "steor"
        case .steorl: "steorl"
        case .steorb: "steorb"
        case .steorlb: "steorlb"
        case .steorh: "steorh"
        case .steorlh: "steorlh"
        case .stset: "stset"
        case .stsetl: "stsetl"
        case .stsetb: "stsetb"
        case .stsetlb: "stsetlb"
        case .stseth: "stseth"
        case .stsetlh: "stsetlh"
        case .stsmax: "stsmax"
        case .stsmaxl: "stsmaxl"
        case .stsmaxb: "stsmaxb"
        case .stsmaxlb: "stsmaxlb"
        case .stsmaxh: "stsmaxh"
        case .stsmaxlh: "stsmaxlh"
        case .stsmin: "stsmin"
        case .stsminl: "stsminl"
        case .stsminb: "stsminb"
        case .stsminlb: "stsminlb"
        case .stsminh: "stsminh"
        case .stsminlh: "stsminlh"
        case .stumax: "stumax"
        case .stumaxl: "stumaxl"
        case .stumaxb: "stumaxb"
        case .stumaxlb: "stumaxlb"
        case .stumaxh: "stumaxh"
        case .stumaxlh: "stumaxlh"
        case .stumin: "stumin"
        case .stuminl: "stuminl"
        case .stuminb: "stuminb"
        case .stuminlb: "stuminlb"
        case .stuminh: "stuminh"
        case .stuminlh: "stuminlh"
        case .cas: "cas"
        case .casa: "casa"
        case .casl: "casl"
        case .casal: "casal"
        case .casb: "casb"
        case .casab: "casab"
        case .caslb: "caslb"
        case .casalb: "casalb"
        case .cash: "cash"
        case .casah: "casah"
        case .caslh: "caslh"
        case .casalh: "casalh"
        case .casp: "casp"
        case .caspa: "caspa"
        case .caspl: "caspl"
        case .caspal: "caspal"
        case .prfm: "prfm"
        case .ldraa: "ldraa"
        case .ldrab: "ldrab"
        case .ldtr: "ldtr"
        case .sttr: "sttr"
        case .ldtrb: "ldtrb"
        case .sttrb: "sttrb"
        case .ldtrh: "ldtrh"
        case .sttrh: "sttrh"
        case .ldtrsb: "ldtrsb"
        case .ldtrsh: "ldtrsh"
        case .ldtrsw: "ldtrsw"
        case .ldtp: "ldtp"
        case .sttp: "sttp"
        case .ldtnp: "ldtnp"
        case .sttnp: "sttnp"
        case .sttxr: "sttxr"
        case .stltxr: "stltxr"
        case .ldtxr: "ldtxr"
        case .ldatxr: "ldatxr"
        case .cast: "cast"
        case .casat: "casat"
        case .caslt: "caslt"
        case .casalt: "casalt"
        case .caspt: "caspt"
        case .caspat: "caspat"
        case .casplt: "casplt"
        case .caspalt: "caspalt"
        case .rprfm: "rprfm"
        case .ld64b: "ld64b"
        case .st64b: "st64b"
        case .st64bv: "st64bv"
        case .st64bv0: "st64bv0"
        case .swpp: "swpp"
        case .swppa: "swppa"
        case .swppl: "swppl"
        case .swppal: "swppal"
        case .ldclrp: "ldclrp"
        case .ldclrpa: "ldclrpa"
        case .ldclrpl: "ldclrpl"
        case .ldclrpal: "ldclrpal"
        case .ldsetp: "ldsetp"
        case .ldsetpa: "ldsetpa"
        case .ldsetpl: "ldsetpl"
        case .ldsetpal: "ldsetpal"
        case .cpyfp: "cpyfp"
        case .cpyfpwt: "cpyfpwt"
        case .cpyfprt: "cpyfprt"
        case .cpyfpt: "cpyfpt"
        case .cpyfpwn: "cpyfpwn"
        case .cpyfpwtwn: "cpyfpwtwn"
        case .cpyfprtwn: "cpyfprtwn"
        case .cpyfptwn: "cpyfptwn"
        case .cpyfprn: "cpyfprn"
        case .cpyfpwtrn: "cpyfpwtrn"
        case .cpyfprtrn: "cpyfprtrn"
        case .cpyfptrn: "cpyfptrn"
        case .cpyfpn: "cpyfpn"
        case .cpyfpwtn: "cpyfpwtn"
        case .cpyfprtn: "cpyfprtn"
        case .cpyfptn: "cpyfptn"
        case .cpyfm: "cpyfm"
        case .cpyfmwt: "cpyfmwt"
        case .cpyfmrt: "cpyfmrt"
        case .cpyfmt: "cpyfmt"
        case .cpyfmwn: "cpyfmwn"
        case .cpyfmwtwn: "cpyfmwtwn"
        case .cpyfmrtwn: "cpyfmrtwn"
        case .cpyfmtwn: "cpyfmtwn"
        case .cpyfmrn: "cpyfmrn"
        case .cpyfmwtrn: "cpyfmwtrn"
        case .cpyfmrtrn: "cpyfmrtrn"
        case .cpyfmtrn: "cpyfmtrn"
        case .cpyfmn: "cpyfmn"
        case .cpyfmwtn: "cpyfmwtn"
        case .cpyfmrtn: "cpyfmrtn"
        case .cpyfmtn: "cpyfmtn"
        case .cpyfe: "cpyfe"
        case .cpyfewt: "cpyfewt"
        case .cpyfert: "cpyfert"
        case .cpyfet: "cpyfet"
        case .cpyfewn: "cpyfewn"
        case .cpyfewtwn: "cpyfewtwn"
        case .cpyfertwn: "cpyfertwn"
        case .cpyfetwn: "cpyfetwn"
        case .cpyfern: "cpyfern"
        case .cpyfewtrn: "cpyfewtrn"
        case .cpyfertrn: "cpyfertrn"
        case .cpyfetrn: "cpyfetrn"
        case .cpyfen: "cpyfen"
        case .cpyfewtn: "cpyfewtn"
        case .cpyfertn: "cpyfertn"
        case .cpyfetn: "cpyfetn"
        case .cpyp: "cpyp"
        case .cpypwt: "cpypwt"
        case .cpyprt: "cpyprt"
        case .cpypt: "cpypt"
        case .cpypwn: "cpypwn"
        case .cpypwtwn: "cpypwtwn"
        case .cpyprtwn: "cpyprtwn"
        case .cpyptwn: "cpyptwn"
        case .cpyprn: "cpyprn"
        case .cpypwtrn: "cpypwtrn"
        case .cpyprtrn: "cpyprtrn"
        case .cpyptrn: "cpyptrn"
        case .cpypn: "cpypn"
        case .cpypwtn: "cpypwtn"
        case .cpyprtn: "cpyprtn"
        case .cpyptn: "cpyptn"
        case .cpym: "cpym"
        case .cpymwt: "cpymwt"
        case .cpymrt: "cpymrt"
        case .cpymt: "cpymt"
        case .cpymwn: "cpymwn"
        case .cpymwtwn: "cpymwtwn"
        case .cpymrtwn: "cpymrtwn"
        case .cpymtwn: "cpymtwn"
        case .cpymrn: "cpymrn"
        case .cpymwtrn: "cpymwtrn"
        case .cpymrtrn: "cpymrtrn"
        case .cpymtrn: "cpymtrn"
        case .cpymn: "cpymn"
        case .cpymwtn: "cpymwtn"
        case .cpymrtn: "cpymrtn"
        case .cpymtn: "cpymtn"
        case .cpye: "cpye"
        case .cpyewt: "cpyewt"
        case .cpyert: "cpyert"
        case .cpyet: "cpyet"
        case .cpyewn: "cpyewn"
        case .cpyewtwn: "cpyewtwn"
        case .cpyertwn: "cpyertwn"
        case .cpyetwn: "cpyetwn"
        case .cpyern: "cpyern"
        case .cpyewtrn: "cpyewtrn"
        case .cpyertrn: "cpyertrn"
        case .cpyetrn: "cpyetrn"
        case .cpyen: "cpyen"
        case .cpyewtn: "cpyewtn"
        case .cpyertn: "cpyertn"
        case .cpyetn: "cpyetn"
        case .setp: "setp"
        case .setpt: "setpt"
        case .setpn: "setpn"
        case .setptn: "setptn"
        case .setm: "setm"
        case .setmt: "setmt"
        case .setmn: "setmn"
        case .setmtn: "setmtn"
        case .sete: "sete"
        case .setet: "setet"
        case .seten: "seten"
        case .setetn: "setetn"
        case .setgp: "setgp"
        case .setgpt: "setgpt"
        case .setgpn: "setgpn"
        case .setgptn: "setgptn"
        case .setgm: "setgm"
        case .setgmt: "setgmt"
        case .setgmn: "setgmn"
        case .setgmtn: "setgmtn"
        case .setge: "setge"
        case .setget: "setget"
        case .setgen: "setgen"
        case .setgetn: "setgetn"
        case .ldtadd: "ldtadd"
        case .ldtaddl: "ldtaddl"
        case .ldtadda: "ldtadda"
        case .ldtaddal: "ldtaddal"
        case .ldtclr: "ldtclr"
        case .ldtclrl: "ldtclrl"
        case .ldtclra: "ldtclra"
        case .ldtclral: "ldtclral"
        case .ldtset: "ldtset"
        case .ldtsetl: "ldtsetl"
        case .ldtseta: "ldtseta"
        case .ldtsetal: "ldtsetal"
        case .swpt: "swpt"
        case .swptl: "swptl"
        case .swpta: "swpta"
        case .swptal: "swptal"
        case .rcwclr: "rcwclr"
        case .rcwclrl: "rcwclrl"
        case .rcwclra: "rcwclra"
        case .rcwclral: "rcwclral"
        case .rcwswp: "rcwswp"
        case .rcwswpl: "rcwswpl"
        case .rcwswpa: "rcwswpa"
        case .rcwswpal: "rcwswpal"
        case .rcwset: "rcwset"
        case .rcwsetl: "rcwsetl"
        case .rcwseta: "rcwseta"
        case .rcwsetal: "rcwsetal"
        case .rcwsclr: "rcwsclr"
        case .rcwsclrl: "rcwsclrl"
        case .rcwsclra: "rcwsclra"
        case .rcwsclral: "rcwsclral"
        case .rcwsswp: "rcwsswp"
        case .rcwsswpl: "rcwsswpl"
        case .rcwsswpa: "rcwsswpa"
        case .rcwsswpal: "rcwsswpal"
        case .rcwsset: "rcwsset"
        case .rcwssetl: "rcwssetl"
        case .rcwsseta: "rcwsseta"
        case .rcwssetal: "rcwssetal"
        case .rcwcas: "rcwcas"
        case .rcwcasl: "rcwcasl"
        case .rcwcasa: "rcwcasa"
        case .rcwcasal: "rcwcasal"
        case .rcwscas: "rcwscas"
        case .rcwscasl: "rcwscasl"
        case .rcwscasa: "rcwscasa"
        case .rcwscasal: "rcwscasal"
        case .rcwclrp: "rcwclrp"
        case .rcwclrpl: "rcwclrpl"
        case .rcwclrpa: "rcwclrpa"
        case .rcwclrpal: "rcwclrpal"
        case .rcwswpp: "rcwswpp"
        case .rcwswppl: "rcwswppl"
        case .rcwswppa: "rcwswppa"
        case .rcwswppal: "rcwswppal"
        case .rcwsetp: "rcwsetp"
        case .rcwsetpl: "rcwsetpl"
        case .rcwsetpa: "rcwsetpa"
        case .rcwsetpal: "rcwsetpal"
        case .rcwsclrp: "rcwsclrp"
        case .rcwsclrpl: "rcwsclrpl"
        case .rcwsclrpa: "rcwsclrpa"
        case .rcwsclrpal: "rcwsclrpal"
        case .rcwsswpp: "rcwsswpp"
        case .rcwsswppl: "rcwsswppl"
        case .rcwsswppa: "rcwsswppa"
        case .rcwsswppal: "rcwsswppal"
        case .rcwssetp: "rcwssetp"
        case .rcwssetpl: "rcwssetpl"
        case .rcwssetpa: "rcwssetpa"
        case .rcwssetpal: "rcwssetpal"
        case .rcwcasp: "rcwcasp"
        case .rcwcaspl: "rcwcaspl"
        case .rcwcaspa: "rcwcaspa"
        case .rcwcaspal: "rcwcaspal"
        case .rcwscasp: "rcwscasp"
        case .rcwscaspl: "rcwscaspl"
        case .rcwscaspa: "rcwscaspa"
        case .rcwscaspal: "rcwscaspal"
        case .stilp: "stilp"
        case .ldiapp: "ldiapp"
        case .gcsstr: "gcsstr"
        case .gcssttr: "gcssttr"
        case .sttadd: "sttadd"
        case .sttaddl: "sttaddl"
        case .sttclr: "sttclr"
        case .sttclrl: "sttclrl"
        case .sttset: "sttset"
        case .sttsetl: "sttsetl"
        default: "?\(m.rawValue)"
        }
    }
}
