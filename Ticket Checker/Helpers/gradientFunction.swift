//
//  GradientFunction.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 20/10/2024.
//

import Foundation
import UIKit

func gradientFunction(_ view: UIView, colors: [CGColor]) {
    let gradientLayer = CAGradientLayer()
    gradientLayer.frame = view.bounds
    gradientLayer.colors = colors // Two colors for the gradient
    
    // Set the direction of the gradient (top to bottom)
    gradientLayer.startPoint = CGPoint(x: 0.5, y: 0.0) // top-left
    gradientLayer.endPoint = CGPoint(x: 0.5, y: 1.0) // bottom-right
    
    // Add the gradient layer to the view
    view.layer.insertSublayer(gradientLayer, at: 0)
}
