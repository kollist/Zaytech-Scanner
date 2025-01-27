//
//  UserDefaultsManager.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 22/11/2024.
//

import Foundation

enum TokenValidationResult {
    case noToken
    case noSlug
    case valid
    case invalid
}


class UserDefaultsManager {
    private let defaults = UserDefaults.standard

    static let shared = UserDefaultsManager()
    private init() {} // Singleton
    
    // Save non-sensitive data
    func saveToken(accessToken: String, expiresIn: Int) {
        let expirationDate = Date().addingTimeInterval(TimeInterval(expiresIn))
        defaults.set(accessToken, forKey: "access_token")
        defaults.set(expirationDate, forKey: "expires_in")
    }
    
    // Retrieve non-sensitive data
    func getToken() -> (accessToken: String?, expiresIn: Date?) {
        let accessToken = defaults.string(forKey: "access_token")
        let expirationDate = defaults.object(forKey: "expires_in") as? Date
        return (accessToken: accessToken, expiresIn: expirationDate)
    }
    
    // Check if token is valid
    func isTokenValid(completion: @escaping (TokenValidationResult) -> Void) {
        guard (defaults.string(forKey: "access_token") != nil) else {
            completion(.noToken)
            return
        }
        
        guard (defaults.string(forKey: "slug") != nil) else {
            completion(.noSlug)
            return
        }
        
        ProfileModal.shared.fetchProfile { result in
            switch result {
            case .success(_):
                completion(.valid)
            case .failure(_):
                completion(.invalid)
            }
        }
    }
    
    // Clear non-sensitive data
    func clearToken() {
        defaults.removeObject(forKey: "access_token")
        defaults.removeObject(forKey: "expires_in")
    }
    
    func saveMerchant(slug: String) {
        defaults.set(slug, forKey: "slug")
    }
    func clearMerchant() {
        defaults.removeObject(forKey: "slug")
    }
    func getMerchant() -> String? {
        let slug = defaults.string(forKey: "slug")
        return slug
    }
    
}
