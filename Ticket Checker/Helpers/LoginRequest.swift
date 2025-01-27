//
//  LoginRequest.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 6/11/2024.
//


import Foundation
import SwiftEmailValidator

struct LoginRequest {
    let email: String
    let password: String
    let token: String
    var platform = "ios"
    let rememberMe: Bool
}
