//
//  RSAKey.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/31/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public extension RSA {
    /// A public/private key pair.
    typealias KeyPair = (`public`: Key, `private`: Key)

    /// The data structure wrapping a key
    public struct Key {
        /// RSA key sizes
        public enum Size : Int {
            case size1024 = 1024
            case size2048 = 2048
            case size4096 = 4096

            public static let `default` = Size.size4096
        }

        /// The key class. Either public or private
        public enum KeyClass {
            case `public`
            case `private`

            fileprivate var keyClass: CFString {
                switch self {
                case .public:
                    return kSecAttrKeyClassPublic
                case .private:
                    return kSecAttrKeyClassPrivate
                }
            }
        }

        /// Fetch a key/pair from the OS Keychain
        ///
        /// - Parameters:
        ///   - identifier: The identifier for keypair.
        ///   - size: The size of the keys
        ///   - permanent: If the keys should be persisted to the keychain
        /// - Returns: A KeyPair
        /// - Throws: RSAError
        static func fetch(_ identifier: String, size: Size = Size.default, permanent: Bool = false) throws -> KeyPair {
            let pubAttr: [NSObject: NSObject] = [
                kSecAttrIsPermanent: permanent as NSObject,
                kSecAttrApplicationTag: "\(identifier).public".data(using: .utf8)! as NSObject,
                kSecClass: kSecClassKey,
                kSecReturnData: kCFBooleanTrue
            ]

            let privAttr: [NSObject: NSObject] = [
                kSecAttrIsPermanent: permanent as NSObject,
                kSecAttrApplicationTag: "\(identifier).private".data(using: .utf8)! as NSObject,
                kSecClass: kSecClassKey,
                kSecReturnData: kCFBooleanTrue
            ]

            var pairAttr = [NSObject: NSObject]()
            pairAttr[kSecAttrKeyType] = kSecAttrKeyTypeRSA
            pairAttr[kSecAttrKeySizeInBits] = size.rawValue as NSObject
            pairAttr[kSecPublicKeyAttrs] = pubAttr as NSObject
            pairAttr[kSecPrivateKeyAttrs] = privAttr as NSObject

            var pubKey: SecKey?
            var privKey: SecKey?

            let status = SecKeyGeneratePair(pairAttr as CFDictionary, &pubKey, &privKey)
            guard status == errSecSuccess else {
                throw RSAError.underlyingError(NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil))
            }
            guard let pub = pubKey else {
                let message = Localized("crypto.errors.rsa.key.generation.public")
                throw RSAError.key(message)
            }
            guard let priv = privKey else {
                let message = Localized("crypto.errors.rsa.key.generation.private")
                throw RSAError.key(message)
            }
            return (public: Key(pub), private: Key(priv))
        }

        internal let ref: SecKey

        private init(_ key: SecKey) {
            self.ref = key
        }

        public init(_ data: Data, _ keyClass: KeyClass, _ size: Size = .default) throws {
            let attrs: [NSObject: NSObject] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass.keyClass,
                kSecAttrKeySizeInBits: size.rawValue as NSObject
            ]
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
                throw error!.takeRetainedValue()
            }
            self.init(key)
        }

        public init(_ keyClass: KeyClass, _ size: Size = .default) throws {
            let attrs: [NSObject: NSObject] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass.keyClass,
                kSecAttrKeySizeInBits: size.rawValue as NSObject
            ]
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
                throw error!.takeRetainedValue()
            }
            self.init(key)
        }

        public var blockSize: Int {
            return SecKeyGetBlockSize(self.ref)
        }

        /// Get the external representation of the key
        ///
        /// - Returns: The data representing the key
        /// - Throws: A CFError if copy failed or the key can't be exported.
        public func externalRepresentation() throws -> Data {
            var error: Unmanaged<CFError>?
            guard let data = SecKeyCopyExternalRepresentation(self.ref, &error) else {
                throw error!.takeRetainedValue()
            }
            return data as Data
        }

        /// Copy the public key from a private key.
        ///
        /// - Returns: The matching public key.
        /// - Throws: RSAError if the key isn't private or the copy failed.
        public func copyPublicKey() throws -> Key {
            guard self.isPrivate else {
                let message = Localized("crypto.errors.rsa.key.copy.non-private")
                throw RSAError.key(message)
            }
            guard let key = SecKeyCopyPublicKey(self.ref) else {
                let message = Localized("crypto.errors.rsa.key.copy.failed")
                throw RSAError.key(message)
            }
            return RSA.Key(key)
        }

        private var attributes: [NSObject: NSObject] {
            return SecKeyCopyAttributes(self.ref) as? [NSObject: NSObject] ?? [:]
        }

        /// Check if the key is a public key
        public var isPublic: Bool {
            return self.attributes[kSecAttrKeyClass] == kSecAttrKeyClassPublic
        }

        /// Check if the key is a private key
        public var isPrivate: Bool {
            return self.attributes[kSecAttrKeyClass] == kSecAttrKeyClassPrivate
        }
    }
}
