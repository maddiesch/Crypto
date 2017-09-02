//
//  RSA.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/31/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public struct RSA {
    /// Encrypt the passed data.
    ///
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - key: The key used to encrypt the data. Must be a public key
    /// - Returns: The encrypted data
    /// - Throws: RSAError
    public static func encrypt(data: Data, withKey key: Key) throws -> Data {
        guard key.isPublic else {
            throw RSAError.invalidKeyType
        }
        guard data.count <= key.blockSize else {
            let message = Localized("crypto.errors.rsa.encrypt.data-too-big")
            throw RSAError.encrypt(message)
        }
        let buffer = data.withUnsafeBytes { UnsafePointer<UInt8>($0) }
        var cypherBuffer = Array<UInt8>(repeating: 0, count: key.blockSize)
        var cypherSize = key.blockSize
        let status = SecKeyEncrypt(key.ref, .PKCS1, buffer, data.count, &cypherBuffer, &cypherSize)
        guard status == errSecSuccess else {
            throw RSAError.underlyingError(NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil))
        }
        return Data(bytes: &cypherBuffer, count: cypherSize)
    }


    /// Decrypte the passed data.
    ///
    /// - Parameters:
    ///   - data: The data to decrypt.
    ///   - key: The key used to decrypt the data. Must be a private key
    /// - Returns: The decryted data
    /// - Throws: RSAError
    public static func decrypt(data: Data, withKey key: Key) throws -> Data {
        guard key.isPrivate else {
            throw RSAError.invalidKeyType
        }
        guard data.count <= key.blockSize else {
            let message = Localized("crypto.errors.rsa.decrypt.data-too-big")
            throw RSAError.decrypt(message)
        }
        let buffer = data.withUnsafeBytes { UnsafePointer<UInt8>($0) }
        var clearSize = key.blockSize
        var clearBuffer = Array<UInt8>(repeating: 0, count: clearSize)

        let status = SecKeyDecrypt(key.ref, .PKCS1, buffer, data.count, &clearBuffer, &clearSize)
        guard status == errSecSuccess else {
            throw RSAError.underlyingError(NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil))
        }
        return Data(bytes: &clearBuffer, count: clearSize)
    }

    public static func createSignature(forData data: Data, withKey key: Key, usingAlgorithm algo: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512) throws -> Data {
        guard key.isPrivate else {
            throw RSAError.invalidKeyType
        }
        guard SecKeyIsAlgorithmSupported(key.ref, .sign, algo) else {
            throw RSAError.algorithmUnsupported
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key.ref, algo, data as CFData, &error) else {
            throw error!.takeRetainedValue()
        }
        return signature as Data
    }

    public static func verifySignature(forData data: Data, usingSignature sig: Data, withKey key: Key, usingAlgorithm algo: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512) throws -> Bool {
        guard key.isPublic else {
            throw RSAError.invalidKeyType
        }
        guard SecKeyIsAlgorithmSupported(key.ref, .verify, algo) else {
            throw RSAError.algorithmUnsupported
        }
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key.ref, algo, data as CFData, sig as CFData, &error) else {
            throw error!.takeRetainedValue()
        }
        return true
    }
}
