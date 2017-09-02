//
//  Fingerprint.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation
import CommonCrypto

public extension Digest {
    public enum FingerprintError : Error {
        /// An error occured with the stream
        case stream(String)
        /// The hashing context errored
        case context(String)
    }

    private static func stream<T>(_ url: URL, _ block: (CFReadStream) throws -> T) throws -> T {
        guard let stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url as CFURL) else {
            let message = Localized("crypto.digest.stream.create-failed")
            throw FingerprintError.stream(message)
        }
        guard CFReadStreamOpen(stream) else {
            let message = Localized("crypto.digest.stream.open-failed")
            throw FingerprintError.stream(message)
        }
        defer {
            CFReadStreamClose(stream)
        }
        return try block(stream)
    }

    /// MD5 The file at the passed URL
    ///
    /// - Parameter url: The location of the file to hash
    /// - Returns: The hash data
    /// - Throws: FingerprintError
    public static func md5(fileAt url: URL) throws -> Data {
        return try self.stream(url) { stream in
            var context = CC_MD5_CTX()
            guard CC_MD5_Init(&context) == 1 else {
                let message = Localized("crypto.digest.hashing.create-failed")
                throw FingerprintError.context(message)
            }

            let size = 4096
            var hasData = true
            while hasData {
                var buffer = Array<UInt8>(repeating: 9, count: size)
                let count = CFReadStreamRead(stream, &buffer, buffer.count)
                switch count {
                case -1:
                    let message = Localized("crypto.digest.stream.read-failed")
                    throw FingerprintError.stream(message)
                case 0:
                    hasData = false
                default:
                    guard CC_MD5_Update(&context, buffer, CC_LONG(count)) == 1 else {
                        let message = Localized("crypto.digest.hashing.updated-failed")
                        throw FingerprintError.context(message)
                    }
                }
            }

            var digest = Array<UInt8>(repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            guard CC_MD5_Final(&digest, &context) == 1 else {
                let message = Localized("crypto.digest.hashing.finalize-failed")
                throw FingerprintError.context(message)
            }

            return Data(bytes: digest)
        }
    }

    /// SHA-1 The file at the passed URL
    ///
    /// - Parameter url: The location of the file to hash
    /// - Returns: The hash data
    /// - Throws: FingerprintError
    public static func sha1(fileAt url: URL) throws -> Data {
        return try self.stream(url) { stream in
            var context = CC_SHA1_CTX()
            
            guard CC_SHA1_Init(&context) == 1 else {
                let message = Localized("crypto.digest.hashing.create-failed")
                throw FingerprintError.context(message)
            }

            let size = 4096
            var hasData = true
            while hasData {
                var buffer = Array<UInt8>(repeating: 9, count: size)
                let count = CFReadStreamRead(stream, &buffer, buffer.count)
                switch count {
                case -1:
                    let message = Localized("crypto.digest.stream.read-failed")
                    throw FingerprintError.stream(message)
                case 0:
                    hasData = false
                default:
                    guard CC_SHA1_Update(&context, buffer, CC_LONG(count)) == 1 else {
                        let message = Localized("crypto.digest.hashing.updated-failed")
                        throw FingerprintError.context(message)
                    }
                }
            }

            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            guard CC_SHA1_Final(&digest, &context) == 1 else {
                let message = Localized("crypto.digest.hashing.finalize-failed")
                throw FingerprintError.context(message)
            }

            return Data(bytes: digest)
        }
    }

    /// SHA-256 The file at the passed URL
    ///
    /// - Parameter url: The location of the file to hash
    /// - Returns: The hash data
    /// - Throws: FingerprintError
    public static func sha256(fileAt url: URL) throws -> Data {
        return try self.stream(url) { stream in
            var context = CC_SHA256_CTX()
            guard CC_SHA256_Init(&context) == 1 else {
                let message = Localized("crypto.digest.hashing.create-failed")
                throw FingerprintError.context(message)
            }

            let size = 4096
            var hasData = true
            while hasData {
                var buffer = Array<UInt8>(repeating: 9, count: size)
                let count = CFReadStreamRead(stream, &buffer, buffer.count)
                switch count {
                case -1:
                    let message = Localized("crypto.digest.stream.read-failed")
                    throw FingerprintError.stream(message)
                case 0:
                    hasData = false
                default:
                    guard CC_SHA256_Update(&context, buffer, CC_LONG(count)) == 1 else {
                        let message = Localized("crypto.digest.hashing.updated-failed")
                        throw FingerprintError.context(message)
                    }
                }
            }

            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            guard CC_SHA256_Final(&digest, &context) == 1 else {
                let message = Localized("crypto.digest.hashing.finalize-failed")
                throw FingerprintError.context(message)
            }

            return Data(bytes: digest)
        }
    }

    /// SHA-512 The file at the passed URL
    ///
    /// - Parameter url: The location of the file to hash
    /// - Returns: The hash data
    /// - Throws: FingerprintError
    public static func sha512(fileAt url: URL) throws -> Data {
        return try self.stream(url) { stream in
            var context = CC_SHA512_CTX()
            guard CC_SHA512_Init(&context) == 1 else {
                let message = Localized("crypto.digest.hashing.create-failed")
                throw FingerprintError.context(message)
            }

            let size = 4096
            var hasData = true
            while hasData {
                var buffer = Array<UInt8>(repeating: 9, count: size)
                let count = CFReadStreamRead(stream, &buffer, buffer.count)
                switch count {
                case -1:
                    let message = Localized("crypto.digest.stream.read-failed")
                    throw FingerprintError.stream(message)
                case 0:
                    hasData = false
                default:
                    guard CC_SHA512_Update(&context, buffer, CC_LONG(count)) == 1 else {
                        let message = Localized("crypto.digest.hashing.updated-failed")
                        throw FingerprintError.context(message)
                    }
                }
            }

            var digest = Array<UInt8>(repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            guard CC_SHA512_Final(&digest, &context) == 1 else {
                let message = Localized("crypto.digest.hashing.finalize-failed")
                throw FingerprintError.context(message)
            }

            return Data(bytes: digest)
        }
    }
}
