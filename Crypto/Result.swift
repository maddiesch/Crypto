//
//  Result.swift
//  Crypto
//
//  Created by Skylar Schipper on 8/5/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

public extension AES {
    public struct Result {
        /// The encrypted data
        public let data: Data
        /// The IV used
        public let iv: Data
        /// The salt used in the key
        public let salt: Data
    }
}
