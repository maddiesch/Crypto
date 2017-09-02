//
//  Localization.swift
//  Crypto
//
//  Created by Skylar Schipper on 9/2/17.
//  Copyright © 2017 Skylar Schipper. All rights reserved.
//

import Foundation

/// Get a localized string from the local bundle
///
/// - Parameter key: The key for the localized string
/// - Returns: The localized key
internal func Localized(_ key: String) -> String {
    return NSLocalizedString(key, tableName: nil, bundle: Bundle(for: LocalizedClass.self), comment: "Localized String")
}

fileprivate class LocalizedClass {
}
