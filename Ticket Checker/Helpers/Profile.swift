//
//  Profile.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 12/11/2024.

import Foundation


class Profile: Codable {
    var user: User?
    var token: Token
    
    init(user: User?, token: Token) {
        self.user = user
        self.token = token
    }
    
    enum CodingKeys: String, CodingKey {
        case user = "user"
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.user = try container.decode(User?.self, forKey: .user)
        
        let accessToken = try container.decode(String.self, forKey: .accessToken)
        let tokenType = try container.decode(String.self, forKey: .tokenType)
        let expiresIn = try container.decode(Int.self, forKey: .expiresIn)
        
        self.token = Token(token: accessToken, tokenType: tokenType, expiresIn: expiresIn)
    }
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encodeIfPresent(user, forKey: .user)

        try container.encode(token.token, forKey: .accessToken)
        try container.encode(token.tokenType, forKey: .tokenType)
        try container.encode(token.expiresIn, forKey: .expiresIn)
    }
}

class Token: Codable {
    var token: String
    var tokenType: String
    var expiresIn: Int
    
    init(token: String, tokenType: String, expiresIn: Int) {
        self.token = token
        self.tokenType = tokenType
        self.expiresIn = expiresIn
    }
    
    enum CodingKeys: String, CodingKey {
        case token = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.token = try container.decode(String.self, forKey: .token)
        self.tokenType = try container.decode(String.self, forKey: .tokenType)
        self.expiresIn = try container.decode(Int.self, forKey: .expiresIn)
    }
}

class User: Codable {
    var name: String?
    var email: String?
    var emailVerified: Bool?
    var groupMerchants: [Merchant?]
    
    init(name: String? = nil, email: String? = nil, emailVerified: Bool? = nil, groupMerchants: [Merchant?]) {
        self.name = name
        self.email = email
        self.emailVerified = emailVerified
        self.groupMerchants = groupMerchants
    }
    
    enum CodingKeys: String, CodingKey {
        case name
        case email
        case emailVerified = "email_verified"
        case groupMerchants = "group-merchants"
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.email = try container.decodeIfPresent(String.self, forKey: .email)
        self.emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        self.groupMerchants = try container.decode([Merchant?].self, forKey: .groupMerchants)
    }
}

class Merchant: Codable {
    var name: String?
    var slug: String?
    var address: String?
    var state: String?
    var phone: String?
    var email: String?
    var website: String?
    var timezone: String?
    var createdAt: String?
    var updatedAt: String?
    var locations: [Location?]
    
    init(
        name: String? = nil,
        slug: String? = nil,
        address: String? = nil,
        state: String? = nil,
        phone: String? = nil,
        email: String? = nil,
        website: String? = nil,
        timezone: String? = nil,
        createdAt: String? = nil,
        updatedAt: String? = nil,
        locations: [Location?]
    ) {
        self.name = name
        self.slug = slug
        self.address = address
        self.state = state
        self.phone = phone
        self.email = email 
        self.website = website
        self.timezone = timezone
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.locations = locations
    }
    
    enum CodingKeys: String, CodingKey {
        case name
        case slug
        case address
        case state
        case phone
        case email
        case website
        case timezone
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case locations
    }
    
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String?.self, forKey: .name)
        slug = try container.decode(String?.self, forKey: .slug)
        address = try container.decode(String?.self, forKey: .address)
        state = try container.decode(String?.self, forKey: .state)
        phone = try container.decode(String?.self, forKey: .phone)
        email = try container.decode(String?.self, forKey: .email)
        website = try container.decode(String?.self, forKey: .website)
        timezone = try container.decode(String?.self, forKey: .timezone)
        createdAt = try container.decode(String?.self, forKey: .createdAt)
        updatedAt = try container.decode(String?.self, forKey: .updatedAt)
        locations = try container.decode([Location?].self, forKey: .locations)
    }
}

class Location: Codable {
    var uuid: String?
    var name: String?
    var label: String?
    var address1: String?
    var city: String?
    var state: String?
    var zipCode: String?
    var lat: String?
    var lng: String?
    var timezone: String?
    var logoUrl: String?
    
    init(uuid: String? = nil, name: String? = nil, label: String? = nil, address1: String? = nil, city: String? = nil, state: String? = nil, zipCode: String? = nil, lat: String? = nil, lng: String? = nil, timezone: String? = nil, logoUrl: String? = nil) {
        self.uuid = uuid
        self.name = name
        self.label = label
        self.address1 = address1
        self.city = city
        self.state = state
        self.zipCode = zipCode
        self.lat = lat
        self.lng = lng
        self.timezone = timezone
        self.logoUrl = logoUrl
    }
    
    enum CodingKeys: String, CodingKey {
        case uuid, name, label, address1, city, state
        case zipCode = "zip_code"
        case lat, lng, timezone
        case kioskSettings
    }
    
    enum KioskSettingsKeys: String, CodingKey {
            case logoUrl
        }
        
        required init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            uuid = try container.decodeIfPresent(String.self, forKey: .uuid)
            name = try container.decodeIfPresent(String.self, forKey: .name)
            label = try container.decodeIfPresent(String.self, forKey: .label)
            address1 = try container.decodeIfPresent(String.self, forKey: .address1)
            city = try container.decodeIfPresent(String.self, forKey: .city)
            state = try container.decodeIfPresent(String.self, forKey: .state)
            zipCode = try container.decodeIfPresent(String.self, forKey: .zipCode)
            lat = try container.decodeIfPresent(String.self, forKey: .lat)
            lng = try container.decodeIfPresent(String.self, forKey: .lng)
            timezone = try container.decodeIfPresent(String.self, forKey: .timezone)
            
            if let kioskSettingsContainer = try? container.nestedContainer(keyedBy: KioskSettingsKeys.self, forKey: .kioskSettings) {
                logoUrl = try kioskSettingsContainer.decodeIfPresent(String.self, forKey: .logoUrl)
            }
        }
        
        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encodeIfPresent(uuid, forKey: .uuid)
            try container.encodeIfPresent(name, forKey: .name)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encodeIfPresent(address1, forKey: .address1)
            try container.encodeIfPresent(city, forKey: .city)
            try container.encodeIfPresent(state, forKey: .state)
            try container.encodeIfPresent(zipCode, forKey: .zipCode)
            try container.encodeIfPresent(lat, forKey: .lat)
            try container.encodeIfPresent(lng, forKey: .lng)
            try container.encodeIfPresent(timezone, forKey: .timezone)
            
            var kioskSettingsContainer = container.nestedContainer(keyedBy: KioskSettingsKeys.self, forKey: .kioskSettings)
            try kioskSettingsContainer.encodeIfPresent(logoUrl, forKey: .logoUrl)
        }}
