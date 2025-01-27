//
//  Account.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 4/11/2024.
//


//
//  Account.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 4/11/2024.


import Foundation
import Security

class KeychainManager {
    private let serviceName = "com.zaytech.keychainmanager"
    
    static let shared = KeychainManager()
    private init() {}
    
    // Save sensitive data
    func saveCredentials(email: String, password: String) -> Bool {
        let credentials: [String: String] = [
            "email": email,
            "password": password
        ]
        
        guard let credentialsData = try? JSONSerialization.data(withJSONObject: credentials) else {
            print("Failed to encode credentials")
            return false
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: "user_credentials",
            kSecValueData as String: credentialsData
        ]
        
        SecItemDelete(query as CFDictionary)
    
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // Retrieve sensitive data
    func getCredentials() -> (email: String?, password: String?)? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: "user_credentials",
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let credentialsData = result as? Data else {
            print("Failed to retrieve credentials")
            return nil
        }
        
        guard let credentials = try? JSONSerialization.jsonObject(with: credentialsData) as? [String: String] else {
            print("Failed to decode credentials")
            return nil
        }
        
        let email = credentials["email"]
        let password = credentials["password"]
        return (email: email, password: password)
    }
    
    // Clear sensitive data
    func clearCredentials() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: "user_credentials"
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}
