//
//  EventDataDetailsViws.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 21/10/2024.
//

import UIKit

class EventDataDetailsView: UIView {
    
    override func layoutSubviews() {
        super.layoutSubviews()
        configureSubviews()
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        configureSubviews()
    }

    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
        configureSubviews()
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        configureSubviews()
    }
    
    private lazy var backgroundImage: UIImageView = {
        let backgroundImage = UIImageView()
        backgroundImage.image = UIImage(named: "EventDetailsBg")
        backgroundImage.contentMode = .scaleAspectFill
        backgroundImage.translatesAutoresizingMaskIntoConstraints = false
        backgroundImage.clipsToBounds = true
        return backgroundImage
    }()
    
    private lazy var stackView: UIStackView = {
        let stackView = UIStackView()
        stackView.axis = .vertical
        stackView.spacing = 45
        stackView.translatesAutoresizingMaskIntoConstraints = false
        return stackView
    }()
    
    private func configureSubviews() {
        self.translatesAutoresizingMaskIntoConstraints = false
        self.addSubview(backgroundImage)
        self.addSubview(stackView)
        
        NSLayoutConstraint.activate([
            backgroundImage.leadingAnchor.constraint(equalTo: self.leadingAnchor),
            backgroundImage.trailingAnchor.constraint(equalTo: self.trailingAnchor),
            backgroundImage.topAnchor.constraint(equalTo: self.topAnchor),
            backgroundImage.bottomAnchor.constraint(equalTo: self.bottomAnchor),
            
            stackView.leadingAnchor.constraint(equalTo: self.leadingAnchor, constant: 20),
            stackView.trailingAnchor.constraint(equalTo: self.trailingAnchor, constant: -20),
            stackView.topAnchor.constraint(equalTo: self.topAnchor, constant: 30),
            stackView.bottomAnchor.constraint(lessThanOrEqualTo: self.bottomAnchor, constant: -20)
        ])
        
        self.sendSubviewToBack(backgroundImage)
    }

    func addEventRow(_ rowView: EventDetailRowView, _ seperate : Bool = true) {
        stackView.addArrangedSubview(rowView)
        
        if (seperate) {
            let separator = UIView()
            separator.backgroundColor = UIColor(named: "SeperatorColor")
            separator.translatesAutoresizingMaskIntoConstraints = false
            rowView.addSubview(separator)
            NSLayoutConstraint.activate([
                separator.bottomAnchor.constraint(equalTo: rowView.bottomAnchor, constant: 30),
                separator.leadingAnchor.constraint(equalTo: rowView.leadingAnchor),
                separator.trailingAnchor.constraint(equalTo: rowView.trailingAnchor),
                separator.heightAnchor.constraint(equalToConstant: 1)
            ])
        }
    }
}
