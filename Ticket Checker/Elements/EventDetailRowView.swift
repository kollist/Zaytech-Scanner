//
//  EventDetailRowView.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 21/10/2024.
//

import UIKit

class EventDetailRowView: UIView {
    
    override func layoutSubviews() {
        super.layoutSubviews()
        configureSubviews()
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
    
    private func setupView() {
        self.translatesAutoresizingMaskIntoConstraints = false
        self.layer.cornerRadius = 0
    }
    lazy var lblKey: UILabel = {
        var lbl = UILabel()
        lbl.translatesAutoresizingMaskIntoConstraints = false
        lbl.textColor = .gray
        lbl.font = .preferredFont(forTextStyle: .caption1)
        lbl.numberOfLines = 0
        return lbl
    }()
    lazy var lblValue: UILabel = {
        var lbl = UILabel()
        lbl.translatesAutoresizingMaskIntoConstraints = false
        lbl.textColor = .label
        lbl.numberOfLines = 0
        return lbl
    }()
    
    private func configureSubviews()
    {
        self.setupView()
        self.addSubview(lblKey)
        self.addSubview(lblValue)
        
        NSLayoutConstraint.activate([
            lblKey.leadingAnchor.constraint(equalTo: self.leadingAnchor),
            lblKey.topAnchor.constraint(equalTo: self.topAnchor),
            
            lblValue.trailingAnchor.constraint(equalTo: self.trailingAnchor),
            lblValue.topAnchor.constraint(equalTo: self.topAnchor)
        ])
    }
    
    func config(key: String, value: String, fontWeight: UIFont.Weight = .regular)
    {
        lblKey.text = key
        lblValue.text = value
        lblValue.font = .systemFont(ofSize: 12, weight: fontWeight)
        
    }
    
}
