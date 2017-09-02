//
//  RSAKeyTests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/31/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class RSAKeyTests: XCTestCase {
    let pair = try! RSA.Key.fetch("com.testing.attr-keys")

    func testPublicType() {
        XCTAssertTrue(pair.public.isPublic)
        XCTAssertFalse(pair.public.isPrivate)
    }

    func testPrivateType() {
        XCTAssertFalse(pair.private.isPublic)
        XCTAssertTrue(pair.private.isPrivate)
    }

    func testFetchingKeyFromPublic() {
        do {
            _ = try pair.public.copyPublicKey()
            XCTFail("Should have raised error")
        } catch {
            XCTAssertNotNil(error)
        }
    }
}
