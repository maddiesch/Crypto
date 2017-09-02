//
//  DigestTests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class DigestTests: XCTestCase {
    func testMD5() {
        let data = "testing".data(using: .utf8)!
        let output = try! Digest.md5(input: data)
        XCTAssertEqual(output.hex, "ae2b1fca515949e5d54fb22b8ed95575")
    }

    func testSHA1() {
        let data = "testing".data(using: .utf8)!
        let output = try! Digest.sha1(input: data)
        XCTAssertEqual(output.hex, "dc724af18fbdd4e59189f5fe768a5f8311527050")
    }

    func testSHA256() {
        let data = "testing".data(using: .utf8)!
        let output = try! Digest.sha256(input: data)
        XCTAssertEqual(output.hex, "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90")
    }

    func testSHA512() {
        let data = "testing".data(using: .utf8)!
        let output = try! Digest.sha512(input: data)
        XCTAssertEqual(output.hex, "521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50")
    }
}
