//
//  Digest.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation
import CommonCrypto

public struct Digest {
    /// MD5 the input data
    ///
    /// - Parameter input: The data to hash
    /// - Returns: The hashed value
    public static func md5(input: Data) throws -> Data {
        let bytes = Array<UInt8>(input)
        var hash = Array<UInt8>(repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(bytes, CC_LONG(bytes.count), &hash)
        return Data(bytes: hash)
    }
    
    /// SHA-1 the input data
    ///
    /// - Parameter input: The data to hash
    /// - Returns: The hashed value
    public static func sha1(input: Data) throws -> Data {
        let bytes = Array<UInt8>(input)
        var hash = Array<UInt8>(repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CC_SHA1(bytes, CC_LONG(bytes.count), &hash)
        return Data(bytes: hash)
    }

    /// SHA-256 the input data
    ///
    /// - Parameter input: The data to hash
    /// - Returns: The hashed value
    public static func sha256(input: Data) throws -> Data {
        let bytes = Array<UInt8>(input)
        var hash = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(bytes, CC_LONG(bytes.count), &hash)
        return Data(bytes: hash)
    }

    /// SHA-512 the input data
    ///
    /// - Parameter input: The data to hash
    /// - Returns: The hashed value
    public static func sha512(input: Data) throws -> Data {
        let bytes = Array<UInt8>(input)
        var hash = Array<UInt8>(repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        CC_SHA512(bytes, CC_LONG(bytes.count), &hash)
        return Data(bytes: hash)
    }
}
