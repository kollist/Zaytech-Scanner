//
//  StatusDataView.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 20/10/2024.
//

import UIKit
import Foundation

class EventView: UIView {
    
    override func layoutSubviews() {
        super.layoutSubviews()
        configureView()
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
    }

    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
        configureSubviews()
    }
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        configureSubviews()
    }
    private func configureView() {
        self.translatesAutoresizingMaskIntoConstraints = false
    }
    
    private func configureSubviews() {
        self.configureView()
    }

    
}
