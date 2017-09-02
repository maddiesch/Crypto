//
//  Data.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public extension Data {
    /// Create a hex string from the data
    public var hex: String {
        var string = ""
        for byte in self {
            string += String(format: "%02x", byte)
        }
        return string
    }

    public init(randomDataOfLength length: Int) throws {
        var buffer = Array<UInt8>(repeating: 0, count: length)
        guard SecRandomCopyBytes(kSecRandomDefault, length, &buffer) == 0 else {
            let message = Localized("crypto.errors.data.random-copy-failed")
            throw DataError.random(message)
        }
        self.init(bytes: buffer)
    }
}

public enum DataError : Error {
    case random(String)
}
