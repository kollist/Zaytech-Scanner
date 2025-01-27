//
//  Envrionment.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 1/11/2024.
//

import Foundation


enum Environment {
    case sandbox
    case production

    var baseURL: String {
        switch self {
            case .sandbox:
                return "https://api-v2-sandbox.smartonlineorders.com/v2"
            case .production:
                return "https://api-v2.smartonlineorders.com/v2"
        }
    }
    
}

