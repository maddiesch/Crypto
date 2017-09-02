//
//  RSAError.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/31/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public extension RSA {
    public enum RSAError : Error {
        case key(String)
        case encrypt(String)
        case decrypt(String)
        case invalidKeyType
        case underlyingError(NSError)
        case algorithmUnsupported
    }
}
