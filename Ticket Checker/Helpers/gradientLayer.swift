//
//  gradientLayer.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 4/11/2024.
//

import UIKit
import Foundation


func gradientLayer() -> CAGradientLayer {
    let gradientLayer = CAGradientLayer()
    let innerColor = UIColor(red: 24/255, green: 81/255, blue: 197/255, alpha: 1).cgColor  // #1851C5
    let outerColor = UIColor(red: 12/255, green: 39/255, blue: 95/255, alpha: 1).cgColor  // #0C275F
    gradientLayer.colors = [innerColor, outerColor]
    gradientLayer.locations = [0.0, 1.0]
    gradientLayer.startPoint = CGPoint(x: 0.5, y: 0.5)
    gradientLayer.endPoint = CGPoint(x: 1.0, y: 1.0)
    gradientLayer.type = .radial
    
    return gradientLayer
}
