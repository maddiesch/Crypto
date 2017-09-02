//
//  AES.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation
import CommonCrypto

public struct AES {
    /// Encrypt the passed data
    ///
    /// - Parameters:
    ///   - data: The message to encrypt.
    ///   - key: The key used to encrypt the data
    /// - Returns: An AES.Result struct
    public static func encrypt(data: Data, usingKey key: Key) throws -> Result {
        let iv = try Data(randomDataOfLength: kCCBlockSizeAES128)
        let rawKey = try key.create()

        let message = try self.perform(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), data, rawKey, iv)

        return Result(data: message, iv: iv, salt: key.salt)
    }

    public static func decrypt(result: Result, key: Key) throws -> Data {
        let rawKey = try key.create()
        return try self.perform(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), result.data, rawKey, result.iv)
    }

    private static func perform(_ op: CCOperation, _ algo: CCAlgorithm, _ input: Data, _ key: Data, _ iv: Data) throws -> Data {
        let rawIV = iv.withUnsafeBytes { UnsafeRawPointer($0) }
        let rawKey = key.withUnsafeBytes { UnsafeRawPointer($0) }
        let rawInput = input.withUnsafeBytes { UnsafeRawPointer($0) }
        let options = CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode)

        var size = 0
        var buffer = Array<UInt8>(repeating: 0, count: input.count + kCCBlockSizeAES128)

        let status = CCCrypt(op, algo, options, rawKey, kCCKeySizeAES256, rawIV, rawInput, input.count, &buffer, buffer.count, &size)
        guard status == Int32(kCCSuccess) else {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
            throw AESError.underlyingError(error)
        }

        return Data(bytes: buffer[0..<size])
    }
}
