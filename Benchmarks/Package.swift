// swift-tools-version: 6.0
// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The benchmark harness — its OWN SwiftPM package, deliberately
// outside the root package's target graph so the published `iris`
// package keeps zero dependencies and no Package.resolved (benchmarks
// are not the library). Depends on the library by relative
// path; build and run from this directory:
//
//     swift run -c release iris-bench            # full battery
//     swift run -c release iris-bench smoke --baseline baseline.json

import PackageDescription

let package = Package(
    name: "iris-benchmarks",
    // ContinuousClock and getrusage are everywhere the library builds;
    // macOS 13 floors the Apple side for Swift Concurrency + Clock.
    // The deployment floor here is the HARNESS's, not the library's.
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "iris-bench",
            dependencies: [
                .product(name: "Iris", package: "iris"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
    ],
)
