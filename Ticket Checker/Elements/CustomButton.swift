//
//  Button.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 18/10/2024.
//

import UIKit


class CustomButton: UIButton {
    
    
    override func layoutSubviews() {
        super.layoutSubviews()
        setupButton()
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
    }

    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
        setupButton()
    }
    
    private func setupButton() {
        self.translatesAutoresizingMaskIntoConstraints = false
        self.layer.cornerRadius = 25
        self.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        self.backgroundColor = UIColor(named: "ButtonColor") ?? .systemBlue
        self.setTitleColor(.white, for: .normal)
    }
    
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        setupButton()
    }
    
    func config(_ title: String = "Check Manually") {
        self.setTitle(title, for: .normal)
    }
}
 
