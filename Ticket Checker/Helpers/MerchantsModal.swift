//
//  LocationModal.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 16/12/2024.
//

import Foundation

class MerchantsModal {
    static let shared = MerchantsModal()
    private init() {}
    
    func fetchLocations(completion: @escaping (Result<[Merchant], ErrorResponse>) -> Void) {
        guard let token = UserDefaultsManager.shared.getToken().accessToken else {
            let errorResponse = ErrorResponse(
                error: "No access token found",
                statusCode: 401,
                errorCode: nil,
                details: nil
            )
            completion(.failure(errorResponse))
            return
        }
        
        let profile = SOOApi.merchants(token: token)
        NetworkManager.shared.request(sooApi: profile) { result in
            switch result {
            case .success(let data):
                do {
                    let merchants = try JSONDecoder().decode([Merchant].self, from: data)
                    completion(.success(merchants))
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
}
