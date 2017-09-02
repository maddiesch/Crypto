//
//  AESTests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class AESTests: XCTestCase {
    func testAESEncrypt() {
        do {
            let message = "This is a super sekret message.".data(using: .utf8)!
            let password = "password".data(using: .utf8)!
            let key = try AES.Key(password: password)
            _ = try AES.encrypt(data: message, usingKey: key)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testAESDecript() {
        do {
            let data = Data(base64Encoded: "bFiDXSkplvxi8PXOwPN6EgqaDVy1TbjrnEUL2Rnqzec=")!
            let iv = Data(base64Encoded: "xsTNs2lIddq2MUefUYY0Fw==")!
            let salt = Data(base64Encoded: "F/hVRdWK3MM=")!
            let password = "password".data(using: .utf8)!
            let result = AES.Result(data: data, iv: iv, salt: salt)
            let key = AES.Key(password: password, salt: salt, rounds: 10_000)
            let message = try AES.decrypt(result: result, key: key)
            let messageS = String(data: message, encoding: .utf8)
            XCTAssertEqual(messageS, "This is a super sekret message.")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testAES() {
        do {
            let message = "This is a super sekret message.".data(using: .utf8)!
            let password = "password".data(using: .utf8)!
            let key = try AES.Key(password: password)
            let result = try AES.encrypt(data: message, usingKey: key)
            let decrypted = try AES.decrypt(result: result, key: key)
            let messageS = String(data: decrypted, encoding: .utf8)
            XCTAssertEqual(messageS, "This is a super sekret message.")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testTargetRounds() {
        let count = AES.Key.rounds(forTargetDelay: 100, withPasswordLength: 16, saltLength: 8)
        XCTAssertGreaterThan(count, 0)
    }
}
