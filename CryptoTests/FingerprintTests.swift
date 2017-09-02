//
//  FingerprintTests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class FingerprintTests: XCTestCase {
    func testMD5() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        let output = try! Digest.md5(fileAt: url)
        XCTAssertEqual(output.hex, "cd1208fef864a0aa38748431f6956be1")
    }

    func testSHA1() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        let output = try! Digest.sha1(fileAt: url)
        XCTAssertEqual(output.hex, "68e4ad14e37d1a1d057086f97509b518581b8c0a")
    }

    func testSHA256() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        let output = try! Digest.sha256(fileAt: url)
        XCTAssertEqual(output.hex, "f5a112cccffb8c428a8948e6525765fdb0be88bba76fcb9c37e2e290815946cc")
    }

    func testSHA512() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        let output = try! Digest.sha512(fileAt: url)
        XCTAssertEqual(output.hex, "4629f80e7672e5e8ff34425c6ab511a3859a0ac19ae94571d3208bb90f31034b5ce2103dac0be2ee06933c08c797c274ed6fd5078e5c1010272f37859517bffb")
    }
}

class FingerprintPerformanceTests: XCTestCase {
    func testMD5Performance() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        self.measure {
            for _ in (0..<40) {
                _ = try! Digest.md5(fileAt: url)
            }
        }
    }

    func testSHA1Performance() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        self.measure {
            for _ in (0..<40) {
                _ = try! Digest.sha1(fileAt: url)
            }
        }
    }

    func testSHA256Performance() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        self.measure {
            for _ in (0..<40) {
                _ = try! Digest.sha256(fileAt: url)
            }
        }
    }

    func testSHA512Performance() {
        let url = Bundle(for: FingerprintTests.self).url(forResource: "image", withExtension: "jpg")!
        self.measure {
            for _ in (0..<40) {
                _ = try! Digest.sha512(fileAt: url)
            }
        }
    }
}
