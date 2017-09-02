//
//  AESError.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public extension AES {
    public enum AESError : Error {
        /// Key creation error
        case key(String)
        /// AES execution error
        case crypt(String)

        case underlyingError(NSError)
    }
}
