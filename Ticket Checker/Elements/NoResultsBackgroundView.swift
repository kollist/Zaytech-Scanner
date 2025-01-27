//
//  NoResultsBackgroundView.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 23/1/2025.
//


import UIKit

class NoResultsBackgroundView: UIView {

    private let imageView: UIImageView = {
        let imageView = UIImageView()
        imageView.image = UIImage(named: "NoResultsIcon") // Replace with your custom asset if needed
        imageView.tintColor = .lightGray
        imageView.contentMode = .scaleAspectFit
        return imageView
    }()

    private let messageLabel: UILabel = {
        let label = UILabel()
        label.text = "No merchant with the given name"
        label.textColor = .lightGray
        label.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        label.textAlignment = .center
        return label
    }()

    override init(frame: CGRect) {
        super.init(frame: frame)
        setupView()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupView()
    }

    private func setupView() {
        addSubview(imageView)
        addSubview(messageLabel)

        imageView.translatesAutoresizingMaskIntoConstraints = false
        messageLabel.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            // Center the image in the view
            imageView.centerXAnchor.constraint(equalTo: centerXAnchor),
            imageView.centerYAnchor.constraint(equalTo: centerYAnchor, constant: -50),
            imageView.heightAnchor.constraint(equalToConstant: 80),

            // Position the label below the image
            messageLabel.topAnchor.constraint(equalTo: imageView.bottomAnchor, constant: 10),
            messageLabel.centerXAnchor.constraint(equalTo: centerXAnchor)
        ])
    }
}
