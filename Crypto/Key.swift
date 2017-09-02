//
//  Key.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation
import CommonCrypto

public extension AES {
    public struct Key {
        private static let algo = CCPBKDFAlgorithm(kCCPBKDF2)
        private static let prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        private static let size = kCCKeySizeAES256

        /// The user supplied password
        public let password: Data
        /// The hashing salt
        public let salt: Data
        /// The number of rounds to hash
        public let rounds: UInt32

        private let algo: CCPBKDFAlgorithm
        private let prf: CCPseudoRandomAlgorithm

        public init(password: Data, rounds: UInt32 = 10_000) throws {
            let salt = try Data(randomDataOfLength: 8)
            self.init(password: password, salt: salt, rounds: rounds)
        }

        public init(password: Data, salt: Data, rounds: UInt32) {
            self.password = password
            self.salt = salt
            self.rounds = rounds
            self.algo = Key.algo
            self.prf = Key.prf
        }

        internal func create() throws -> Data {
            let rawPassword = self.password.withUnsafeBytes { UnsafePointer<Int8>($0) }
            let rawSalt = self.salt.withUnsafeBytes { UnsafePointer<UInt8>($0) }
            var buffer = Array<UInt8>(repeating: 0, count: kCCKeySizeAES256)
            let result = CCKeyDerivationPBKDF(self.algo, rawPassword, self.password.count, rawSalt, self.salt.count, self.prf, self.rounds, &buffer, Key.size)
            guard result == Int32(kCCSuccess) else {
                let message = Localized("crypto.errors.aes.key.derived-key-failed")
                throw AESError.key(message)
            }
            return Data(bytes: buffer)
        }

        /// Calculate the number of rounds needed to perform for a given delay.
        ///
        /// - Parameters:
        ///   - msec: The target amount of time the hashing should take in milliseconds
        ///   - pLen: The length of the password to be hashed
        ///   - sLen: The length of the salt used in the hash
        /// - Returns: The number of rounds for the current system
        public static func rounds(forTargetDelay msec: UInt32, withPasswordLength pLen: Int, saltLength sLen: Int) -> UInt32 {
            return CCCalibratePBKDF(Key.algo, pLen, sLen, Key.prf, Key.size, msec)
        }
    }
}
