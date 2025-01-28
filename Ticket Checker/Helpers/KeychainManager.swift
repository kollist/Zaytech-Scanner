
//
//  Account.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 4/11/2024.


import Foundation
import Security
import LocalAuthentication

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
            kSecValueData as String: credentialsData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // Retrieve sensitive data with biometric or device authentication
    func getCredentialsWithAuthentication(completion: @escaping (Result<(email: String, password: String), ErrorResponse>) -> Void) {
        
        // Fetch credentials from Keychain
        self.getCredentials { result in
            switch result {
            case .success(let credentials):
                let context = LAContext()
                context.localizedReason = "Authenticate to unlock your stored account details"
                
                // Biometric Authentication
                guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
                    completion(.failure(ErrorResponse(error: "Biometric authentication not available", statusCode: nil, errorCode: "BIOMETRIC_NOT_AVAILABLE", details: nil)))
                    return
                }
                context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: context.localizedReason) { success, error in
                    if success {
                        completion(.success(credentials))
                    } else if let error = error {
                        completion(.failure(ErrorResponse(error: error.localizedDescription, statusCode: nil, errorCode: nil, details: nil)))
                    } else {
                        completion(.failure(ErrorResponse(error: "Authentication failed", statusCode: nil, errorCode: "AUTH_FAILED", details: nil)))
                    }
                }
            case .failure(let error):
                completion(.failure(ErrorResponse(error: error.localizedDescription, statusCode: nil, errorCode: nil, details: nil)))
            }
        }
    }
    
    // Basic retrieval of credentials (without biometric/authentication)
    private func getCredentials(completion: @escaping (Result<(email: String, password: String), ErrorResponse>) -> Void) {
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
            completion(.failure(ErrorResponse(error: "Keychain error", statusCode: nil, errorCode: "KEYCHAIN_ERROR", details: nil)))
            return
        }
        
        do {
            guard let credentials = try JSONSerialization.jsonObject(with: credentialsData) as? [String: String],
                  let email = credentials["email"],
                  let password = credentials["password"] else {
                throw NSError(domain: "Decoding Error", code: -1, userInfo: nil)
            }
            completion(.success((email: email, password: password)))
        } catch {
            completion(.failure(ErrorResponse(error: error.localizedDescription, statusCode: nil, errorCode: "DECODING_ERROR", details: nil)))
        }
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

