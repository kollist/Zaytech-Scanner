//
//  NetworkManager.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 6/11/2024.


import Foundation
import Alamofire

struct ErrorResponse: Codable, Error {
    let error: String
    let statusCode: Int?
    let errorCode: String?
    let details: String?
    
    // Helper property to check if the error is related to authorization
    var isUnauthorized: Bool {
        return statusCode == 401
    }
    
    // Default error message for safety
    var safeErrorMessage: String {
        return error.isEmpty ? "An unexpected error occurred, please try again later" : error
    }
}



class NetworkManager {
    
    static let shared = NetworkManager()
    
    // Generalized request function for both GET and POST request
    func request(
        sooApi: SOOApi,
        completion: @escaping (Result<Data, ErrorResponse>) -> Void
    ) {
        AF.request(sooApi.url, method: sooApi.method, parameters: sooApi.parameters, encoding: sooApi.parameterEncoding, headers: sooApi.headers)
            .validate()
            .responseData { response in
                switch response.result {
                    case .success(let data):
                        completion(.success(data))
                    case .failure(let error):
                        if let data = response.data, let errorResponse = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                            completion(.failure(errorResponse))
                        } else {
                            let genericError = ErrorResponse(error: error.localizedDescription, statusCode: response.response?.statusCode, errorCode: nil, details: nil)
                            completion(.failure(genericError))
                        }
                }
            }
    }
}

