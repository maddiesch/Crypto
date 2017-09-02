//
//  RSATests.swift
//  CryptoTests
//
//  Created by Skylar Schipper on 8/31/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import XCTest
@testable import Crypto

class RSATests: XCTestCase {
    func testRSAKeyFetching() {
        do {
            let pair = try RSA.Key.fetch("com.testing.keys")
            XCTAssertNotNil(pair.public)
            XCTAssertNotNil(pair.private)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRSAEncryption() {
        let plain = "Test Message".data(using: .utf8)!
        do {
            let pair = try RSA.Key.fetch("com.testing.keys")
            let secret = try RSA.encrypt(data: plain, withKey: pair.public)
            XCTAssertNotNil(secret)
            XCTAssertNotEqual(secret, plain)
            let out = try RSA.decrypt(data: secret, withKey: pair.private)
            XCTAssertNotNil(secret)
            XCTAssertEqual(String(data: out, encoding: .utf8)!, "Test Message")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testExternalValues() {
        do {
            let pair = try RSA.Key.fetch("com.testing.keys")
            let raw = try pair.private.externalRepresentation()
            XCTAssertNotNil(raw)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRawValue() {
        do {
            let original = try RSA.Key(.private)
            let raw = try original.externalRepresentation()
            XCTAssertNotNil(raw)
            let key = try RSA.Key(raw, .private)
            XCTAssertNotNil(key)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRandomPrivateValue() {
        do {
            let key = try RSA.Key(.private)
            XCTAssertNotNil(key)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testRandomPublicValue() {
        do {
            let key = try RSA.Key(.public)
            XCTAssertNotNil(key)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testPublicKeyFromPrivate() {
        do {
            let key = try RSA.Key(.private)
            XCTAssertNotNil(key)
            let pub = try key.copyPublicKey()
            XCTAssertNotNil(pub)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testSignature() {
        do {
            let pair = try RSA.Key.fetch("com.testing.keys")
            let raw = "At enim blandit vulputate donec nonummy elit ornare faucibus turpis tristique.  Blandit inceptos velit mattis nec eget suspendisse dui fusce fusce ac pretium sociosqu.  Accumsan eget enim inceptos cursus ut sit elit cras nulla arcu congue hendrerit tristique.  Nunc tempor massa purus eget amet habitasse sapien justo duis quis mauris elit quisque curabitur nisi ante.  Hymenaeos mauris consectetuer in eget est tempor vivamus nec eu erat turpis dolor ipsum adipiscing aliquam.  Sem vel suspendisse commodo diam et viverra nonummy nam pellentesque sed.  Nulla felis fusce sem tincidunt integer sit per et praesent conubia consectetuer eros.".data(using: .utf8)!
            let sig = try RSA.createSignature(forData: raw, withKey: pair.private)
            XCTAssertNotNil(sig)
            let status = try RSA.verifySignature(forData: raw, usingSignature: sig, withKey: pair.public)
            XCTAssertTrue(status)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testWrongKeyTypeEncrypt() {
        let pair = try! RSA.Key.fetch("com.testing.keys")
        do {
            let message = "Content to encrypt".data(using: .utf8)!
            _ = try RSA.encrypt(data: message, withKey: pair.private)
            XCTFail("Shouldn't have passed")
        } catch {
            XCTAssertTrue(error is RSA.RSAError)
        }
    }

    func testBlockSizeEncrypt() {
        let pair = try! RSA.Key.fetch("com.testing.keys")
        let message = try! Data(randomDataOfLength: 5000)
        do {
            _ = try RSA.encrypt(data: message, withKey: pair.public)
            XCTFail("Shouldn't have passed")
        } catch {
            XCTAssertTrue(error is RSA.RSAError)
        }
    }



    func testWrongKeyTypeDecrypt() {
        let pair = try! RSA.Key.fetch("com.testing.keys")
        do {
            let message = "Content to decrypt".data(using: .utf8)!
            _ = try RSA.decrypt(data: message, withKey: pair.public)
            XCTFail("Shouldn't have passed")
        } catch {
            XCTAssertTrue(error is RSA.RSAError)
        }
    }

    func testBlockSizeDecrypt() {
        let pair = try! RSA.Key.fetch("com.testing.keys")
        let message = try! Data(randomDataOfLength: 5000)
        do {
            _ = try RSA.decrypt(data: message, withKey: pair.private)
            XCTFail("Shouldn't have passed")
        } catch {
            XCTAssertTrue(error is RSA.RSAError)
        }
    }
}


