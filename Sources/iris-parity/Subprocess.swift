// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation

#if canImport(Glibc)
    import Glibc
#endif

struct SubprocessResult {
    let stdout: String
    let stderr: String
    let exitCode: Int32
    let timedOut: Bool
}

/// Run `launchPath args...`, optionally feeding stdin, draining both pipes
/// concurrently and SIGTERMing the child after `timeoutSeconds` (SIGKILL 5s
/// later).
func runSubprocess(
    _ launchPath: String,
    _ args: [String],
    stdin: Data? = nil,
    timeoutSeconds: Double = 600,
) -> SubprocessResult? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: launchPath)
    process.arguments = args

    let outPipe = Pipe()
    let errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    let inPipe: Pipe? = stdin.map { _ in Pipe() }
    if let inPipe {
        process.standardInput = inPipe
    }

    do {
        try process.run()
    } catch {
        return nil
    }

    let sigkillGraceSeconds = 5.0
    let pid = process.processIdentifier
    let escalation = DispatchWorkItem {
        if process.isRunning { kill(pid, SIGKILL) }
    }
    let killer = DispatchWorkItem {
        process.terminate()
        DispatchQueue.global().asyncAfter(deadline: .now() + sigkillGraceSeconds, execute: escalation)
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeoutSeconds, execute: killer)

    let group = DispatchGroup()
    nonisolated(unsafe) var outData = Data()
    nonisolated(unsafe) var errData = Data()

    if let inPipe, let stdin {
        group.enter()
        DispatchQueue.global().async {
            let handle = inPipe.fileHandleForWriting
            handle.write(stdin)
            handle.closeFile()
            group.leave()
        }
    }
    group.enter()
    DispatchQueue.global().async {
        outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        group.leave()
    }
    group.enter()
    DispatchQueue.global().async {
        errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        group.leave()
    }
    group.wait()
    process.waitUntilExit()

    let timedOut = !killer.isCancelled && process.terminationReason == .uncaughtSignal
    killer.cancel()
    escalation.cancel()

    return SubprocessResult(
        stdout: String(decoding: outData, as: UTF8.self),
        stderr: String(decoding: errData, as: UTF8.self),
        exitCode: process.terminationStatus,
        timedOut: timedOut,
    )
}
