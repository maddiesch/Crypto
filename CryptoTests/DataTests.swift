//
//  DataTests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class DataTests: XCTestCase {
    func testHex() {
        let data = Data(bytes: [255, 128, 5, 18, 12])
        XCTAssertEqual(data.hex, "ff8005120c")
    }

    func testRandomDataLength() {
        do {
            let random = try Data(randomDataOfLength: 48)
            XCTAssertEqual(random.count, 48)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRandomData() {
        do {
            let random1 = try Data(randomDataOfLength: 48)
            let random2 = try Data(randomDataOfLength: 48)
            XCTAssertNotEqual(random1, random2)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}

