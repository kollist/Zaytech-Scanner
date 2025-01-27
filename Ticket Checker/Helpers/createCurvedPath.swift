//
//  createCurvedPath.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 21/10/2024.
//

import UIKit


func createCurvedPath(_ view: UIView) -> UIBezierPath {
    let path = UIBezierPath()
    let width = view.bounds.width
    let height = view.bounds.height

    // Start from top-left
    path.move(to: CGPoint(x: 0, y: 0))
    // Top-right corner
    path.addLine(to: CGPoint(x: width, y: 0))
    // Bottom-right corner with a curve
    path.addLine(to: CGPoint(x: width, y: height - 20)) // adjust 30 to control the curve depth
    path.addQuadCurve(to: CGPoint(x: 0, y: height - 20), controlPoint: CGPoint(x: width / 2, y: height + 20)) // Control point to create the curve
    // Bottom-left corner
    path.addLine(to: CGPoint(x: 0, y: height - 20))
    // Close the path
    path.close()

    return path
}
