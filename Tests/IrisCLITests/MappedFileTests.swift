// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import IrisCLICore
import Testing

#if canImport(Glibc)
    import Glibc
#elseif canImport(Darwin)
    import Darwin
#endif

/// Validates the bounds-checked mmap substrate: construction failure
/// modes, typed reads at every boundary, string reads, buffer views,
/// and sub-range windows sharing one mapping.
@Suite("Mapped file reads")
struct MappedFileTests {
    /// Map a fresh temporary file holding `bytes`.
    func mapped(_ bytes: [UInt8], _ body: (MappedFile?) -> Void) {
        withTemporaryFile(bytes: bytes) { body(MappedFile(path: $0)) }
    }

    @Test func missingFileFailsToMap() {
        #expect(MappedFile(path: "/nonexistent/iris/mapped/file") == nil)
    }

    @Test func directoryFailsToMap() {
        #expect(MappedFile(path: FileManager.default.temporaryDirectory.path) == nil)
    }

    @Test func emptyFileFailsToMap() {
        mapped([]) { #expect($0 == nil) }
    }

    @Test func unreadableFileFailsToMap() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("iris-cli-test-\(UUID().uuidString)").path
        #expect(FileManager.default.createFile(atPath: path, contents: Data([1, 2, 3]), attributes: [.posixPermissions: 0o000]))
        if geteuid() == 0 {
            // Root bypasses permission bits (CI containers run as root),
            // so mode 000 is still readable here and mapping succeeds.
            #expect(MappedFile(path: path) != nil)
        } else {
            #expect(MappedFile(path: path) == nil)
        }
        try FileManager.default.removeItem(atPath: path)
    }

    @Test func typedReadsAreBoundsChecked() {
        mapped([0x01, 0x02, 0x03, 0x04, 0x05]) { file in
            #expect(file?.size == 5)
            #expect(file?.read(at: 0) == UInt32(0x0403_0201))
            #expect(file?.read(at: 1) == UInt32(0x0504_0302))
            #expect(file?.read(at: 2, as: UInt32.self) == nil)
            #expect(file?.read(at: 4) == UInt8(0x05))
            #expect(file?.read(at: 5, as: UInt8.self) == nil)
            #expect(file?.read(at: -1, as: UInt8.self) == nil)
            #expect(file?.read(at: Int.max, as: UInt32.self) == nil)
            #expect(file?.read(at: 0, as: UInt64.self) == nil)
        }
    }

    @Test func pathSurvivesIntoSubViews() {
        mapped([1, 2, 3, 4]) { file in
            let path = file?.path
            #expect(path?.contains("iris-cli-test-") == true)
            #expect(file?.subFile(at: 1, length: 2)?.path == path)
        }
    }

    @Test func withBytesYieldsZeroCopyWindow() {
        mapped([9, 8, 7, 6]) { file in
            let sum = file?.withBytes(at: 1, length: 2) { buffer in
                Int(buffer[0]) + Int(buffer[1])
            }
            #expect(sum == 15)
            #expect(file?.withBytes(at: 3, length: 2) { _ in 0 } == nil)
            #expect(file?.withBytes(at: -1, length: 1) { _ in 0 } == nil)
            #expect(file?.withBytes(at: 0, length: -1) { _ in 0 } == nil)
            #expect(file?.withBytes(at: Int.max, length: 1) { _ in 0 } == nil)
            #expect(file?.withBytes(at: 0, length: 0) { _ in 42 } == 42)
        }
    }

    @Test func cStringReads() {
        mapped(Array("ab\0cd".utf8)) { file in
            #expect(file?.readCString(at: 0, maxLength: 16) == "ab")
            #expect(file?.readCString(at: 3, maxLength: 16) == nil) // no NUL before EOF
            #expect(file?.readCString(at: 0, maxLength: 2) == nil) // NUL outside window
            #expect(file?.readCString(at: 0, maxLength: 3) == "ab")
            #expect(file?.readCString(at: -1, maxLength: 4) == nil)
            #expect(file?.readCString(at: 5, maxLength: 4) == nil)
            #expect(file?.readCString(at: 0, maxLength: 0) == nil)
        }
    }

    @Test func invalidUTF8IsRepaired() {
        mapped([0x61, 0xFF, 0x62, 0x00]) { file in
            #expect(file?.readCString(at: 0, maxLength: 8) == "a\u{FFFD}b")
        }
    }

    @Test func fixedStringReads() {
        mapped(Array("__TEXT\0\0__data".utf8)) { file in
            #expect(file?.readFixedString(at: 0, length: 8) == "__TEXT")
            #expect(file?.readFixedString(at: 8, length: 6) == "__data") // no NUL: whole window
            #expect(file?.readFixedString(at: 0, length: 0) == "")
            #expect(file?.readFixedString(at: -1, length: 4) == nil)
            #expect(file?.readFixedString(at: 10, length: 8) == nil)
            #expect(file?.readFixedString(at: 1, length: Int.max) == nil)
        }
    }

    @Test func subViewsComposeAndOutliveParent() {
        mapped([1, 2, 3, 4, 5, 6, 7, 8]) { file in
            let sub = file?.subFile(at: 2, length: 4)
            #expect(sub?.size == 4)
            #expect(sub?.read(at: 0) == UInt8(3))
            let subSub = sub?.subFile(at: 1, length: 2)
            #expect(subSub?.size == 2)
            #expect(subSub?.read(at: 0) == UInt8(4))
            #expect(subSub?.read(at: 2, as: UInt8.self) == nil)
            #expect(sub?.subFile(at: 2, length: 3) == nil)
            #expect(sub?.subFile(at: -1, length: 1) == nil)
            #expect(sub?.subFile(at: 1, length: Int.max) == nil)
            #expect(sub?.subFile(at: 4, length: 0)?.size == 0)
        }
    }

    @Test func unmappableFileFailsCleanly() throws {
        // A 200 TB sparse file is a valid regular file whose mapping
        // cannot be reserved (exceeds user address space): open and
        // fstat succeed, mmap itself fails, and the initializer returns
        // nil instead of trapping.
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("iris-cli-test-\(UUID().uuidString)").path
        #expect(FileManager.default.createFile(atPath: path, contents: nil))
        let handle = try #require(FileHandle(forWritingAtPath: path))
        do {
            try handle.truncate(atOffset: 200 << 40)
        } catch {
            // The filesystem cannot create the sparse vehicle (ext4 caps
            // regular files at 16 TiB, so Linux CI rejects the truncate).
            // The mmap-failure arm is exercised on hosts that can.
            try handle.close()
            try FileManager.default.removeItem(atPath: path)
            return
        }
        try handle.close()
        #expect(MappedFile(path: path) == nil)
        try FileManager.default.removeItem(atPath: path)
    }

    @Test func mappingSurvivesUnlink() {
        // The fixture-walk helper unlinks before reads complete; pin the
        // kernel-pins-the-inode property the helper relies on.
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("iris-cli-test-\(UUID().uuidString)").path
        #expect(FileManager.default.createFile(atPath: path, contents: Data([0xAB, 0xCD])))
        let file = MappedFile(path: path)
        try? FileManager.default.removeItem(atPath: path)
        #expect(file?.read(at: 0) == UInt16(0xCDAB))
    }

    @Test func unsafeBaseAddressMatchesReads() {
        mapped([0x11, 0x22, 0x33, 0x44]) { file in
            let direct = file.map { withExtendedLifetime($0) { $0.unsafeBaseAddress.load(as: UInt8.self) } }
            #expect(direct == 0x11)
            let sub = file?.subFile(at: 2, length: 2)
            let subDirect = sub.map { withExtendedLifetime($0) { $0.unsafeBaseAddress.load(as: UInt8.self) } }
            #expect(subDirect == 0x33)
        }
    }
}
