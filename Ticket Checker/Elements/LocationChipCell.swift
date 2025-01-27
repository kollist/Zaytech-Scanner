//
//  LocationChipCell.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 24/1/2025.
//

import UIKit

class LocationChipCell: UICollectionViewCell {
    private let titleLabel = UILabel()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupUI()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupUI() {
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = .systemFont(ofSize: 16)
        titleLabel.numberOfLines = 0
        titleLabel.textAlignment = .center
        titleLabel.textColor = UIColor(named: "LocationCapsuleColor")
        
        contentView.addSubview(titleLabel)
        contentView.backgroundColor = UIColor(named: "LocationCapsulesBg")
        contentView.layer.cornerRadius = 20
        contentView.layer.masksToBounds = true
        
        NSLayoutConstraint.activate([
            titleLabel.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            titleLabel.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 8),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -8)
        ])
    }
    
    func configure(with text: String) {
        titleLabel.text = text
    }
}
