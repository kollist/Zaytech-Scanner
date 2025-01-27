//
//  EndPointType.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 7/11/2024.
//

import Alamofire
import Foundation


protocol EndPointType {
    var url: String { get }
    var parameters: [String: Any] { get }
    var key: String? { get }
    var method: HTTPMethod { get }
    var parameterEncoding: ParameterEncoding { get }
    var headers: HTTPHeaders? { get }
}


enum SOOApi {
    case login(email: String, password: String, gToken: String, platform: String, rememberMe: Bool)
    case eticket(ticketNumber: String)//, token: String)
    case profile(token: String)
    case locations(token: String, slug: String)
    case merchants(token: String)
}


extension SOOApi: EndPointType {
    
    
    private func isProd() -> Bool {
        if let envStr = Bundle.main.object(forInfoDictionaryKey: "PROD") as? String {
            return envStr.lowercased() == "true"
        } else {
            return false
        }
    }
    var url: String {
        var baseUrl: String {
            let env: Environment = isProd() ? .production : .sandbox
            return env.baseURL
        }
        
        switch self {
            case .login:
                return baseUrl + "/users/login"
            case .eticket:
                return baseUrl + "/public/check-eticket"
            case .profile:
                return baseUrl + "/users/me"
            case .locations(token: _, slug: let slug):
                return baseUrl + "/group-merchants/\(slug)/locations"
        case .merchants:
            return baseUrl + "/users/group-merchants"
        }
    }
    
    var parameters: [String : Any] {
        switch self {
            case .login(let email, let password, let gToken, let platform, let rememberMe):
                return ["email": email, "password": password, "gtoken": gToken, "platform": platform, "remember_me": rememberMe]
            case .eticket:
                return [:]
            case .profile:
                return [:]
            case .locations:
                return [:]
            case .merchants:
                return [:]
        }
    }
    
    var key: String? {
        return nil
    }
    
    var parameterEncoding: any Alamofire.ParameterEncoding {
        switch self {
            case .login, .eticket:
                return JSONEncoding.default
            default:
                return URLEncoding.default
        }
    }
    
    var headers: Alamofire.HTTPHeaders? {
        switch self {
            case .eticket(let token):
                return [.authorization(bearerToken: token)]
            case .profile(token: let token):
                return [.authorization(bearerToken: token)]
        case .locations(token: let token, slug: _):
                return [.authorization(bearerToken: token)]
            case .login:
                return nil
        case .merchants(token: let token):
            return [.authorization(bearerToken: token)]
        }
    }
    
    var method: HTTPMethod {
        switch self {
            case .login:
                return .post
            case .eticket:
                return .get
            case .profile:
                return .get
            case .locations:
                return .get
            case .merchants:
                return .get
        }
    }
}
