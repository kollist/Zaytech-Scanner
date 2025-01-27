//
//  EventTitle.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 21/10/2024.
//

import UIKit

class TitleLabel: UILabel {

    override func layoutSubviews() {
        super.layoutSubviews()
        configureLabel()
    }
    
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        configureLabel()
    }

    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
        configureLabel()
    }
    
    private func configureLabel() {
        self.font = UIFont.systemFont(ofSize: 16, weight: .bold)
        self.textColor = .label
        self.translatesAutoresizingMaskIntoConstraints = false 
    }
    
    func config(_ eventTitle: String) {
        self.text = eventTitle
    }
}
