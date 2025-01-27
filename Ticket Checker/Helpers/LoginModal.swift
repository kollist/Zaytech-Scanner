//
//  LoginModal.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 15/11/2024.
//

import Foundation


class LoginModal {
    static let shared = LoginModal()
    private init() {}
    
    func login(email: String, password: String, gtoken: String, rememberMe: Bool, completion: @escaping (Result<Profile, ErrorResponse>) -> Void) {
        let sooApi = SOOApi.login(email: email, password: password, gToken: gtoken, platform: "ios", rememberMe: rememberMe)
        
        NetworkManager.shared.request(sooApi: sooApi) { result in
            switch result {
            case .success(let data):
                do {
                    let profile = try JSONDecoder().decode(Profile.self, from: data)
                    self.handleLoginSuccess(profile, email: email, password: password)
                    completion(.success(profile))
                } catch let decodingError as DecodingError {
                    let errorResponse = ErrorResponse(
                        error: self.handleDecodingError(decodingError),
                        statusCode: nil,
                        errorCode: "DECODING_ERROR",
                        details: decodingError.localizedDescription
                    )
                    completion(.failure(errorResponse))
                } catch {
                    let errorResponse = ErrorResponse(
                        error: "An unexpected error occurred while decoding the response.",
                        statusCode: nil,
                        errorCode: "UNKNOWN_DECODING_ERROR",
                        details: error.localizedDescription
                    )
                    completion(.failure(errorResponse))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    private func handleDecodingError(_ error: DecodingError) -> String {
        switch error {
            case .dataCorrupted(let context):
                return "Data corrupted: \(context.debugDescription)"
            case .keyNotFound(let key, let context):
                return "Key '\(key.stringValue)' not found: \(context.debugDescription)"
            case .typeMismatch(let type, let context):
                return "Type mismatch for type '\(type)': \(context.debugDescription)"
            case .valueNotFound(let type, let context):
                return "Value not found for type '\(type)': \(context.debugDescription)"
            @unknown default:
                return "An unknown decoding error occurred."
        }
    }
    
    private func handleLoginSuccess(_ profile: Profile, email: String, password: String) {
        // Store sensitive data in Keychain
        _ = KeychainManager.shared.saveCredentials(email: email, password: password)
        
        // Store non-sensitive data in UserDefaults
        UserDefaultsManager.shared.saveToken(accessToken: profile.token.token, expiresIn: profile.token.expiresIn)
        
        // Store user data in UserDefaults
        UserDefaults.standard.set(profile.user?.name, forKey: "user_name")
        UserDefaults.standard.set(profile.user?.email, forKey: "email")
        UserDefaults.standard.set(profile.user?.emailVerified, forKey: "email_verified")
        
        // Store merchant data in UserDefaults
        if let firstMerchant = profile.user?.groupMerchants.first {
            UserDefaults.standard.set(firstMerchant?.name, forKey: "merchantName")
            UserDefaults.standard.set(firstMerchant?.slug, forKey: "merchantSlug")
        }
    }
}
