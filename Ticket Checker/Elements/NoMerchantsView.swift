//
//  EmptyStateView.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 23/1/2025.
//

import UIKit
import Lottie

// MARK: - Empty State View
class NoMerchantsView: UIView {
    var refreshData: ((_ completion: @escaping () -> Void) -> Void)?
    
    private lazy var animationView: LottieAnimationView = {
        let animationView = LottieAnimationView()
        return animationView
    }()
    
    private let containerStackView: UIStackView = {
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 8
        stack.alignment = .center
        stack.isUserInteractionEnabled = true
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }()
    
    private let refreshButton: UIButton = {
        let btn = UIButton()
        btn.translatesAutoresizingMaskIntoConstraints = false
        btn.setTitle("Refresh", for: .normal)
        btn.layer.cornerRadius = 15
        btn.titleLabel?.numberOfLines = 1
        btn.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .medium)
        btn.backgroundColor = UIColor(named: "ButtonColor") ?? .systemBlue
        btn.setTitleColor(.white, for: .normal)
        btn.addTarget(self, action: #selector(refreshAction), for: .touchUpInside)
        return btn
    }()
    
    private let imageView: UIImageView = {
        let imageView = UIImageView()
        imageView.image = UIImage(named: "EmptyStateIcon")
        imageView.tintColor = .systemGray2
        imageView.contentMode = .scaleAspectFit
        return imageView
    }()
    
    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = "Oops! No merchants were found under your name"
        label.font = .systemFont(ofSize: 15, weight: .medium)
        label.textColor = .systemGray
        label.numberOfLines = 0
        label.textAlignment = .center
        return label
    }()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupView()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupView() {
        self.isUserInteractionEnabled = true
        containerStackView.isUserInteractionEnabled = true
        refreshButton.isUserInteractionEnabled = true
        self.addSubview(containerStackView)
        containerStackView.addArrangedSubview(imageView)
        containerStackView.addArrangedSubview(titleLabel)
        containerStackView.addArrangedSubview(refreshButton)
        
        NSLayoutConstraint.activate([
            containerStackView.centerYAnchor.constraint(equalTo: self.centerYAnchor),
            containerStackView.centerXAnchor.constraint(equalTo: self.centerXAnchor),
            containerStackView.leadingAnchor.constraint(equalToSystemSpacingAfter: self.leadingAnchor, multiplier: 1),
            self.trailingAnchor.constraint(equalToSystemSpacingAfter: containerStackView.trailingAnchor, multiplier: 1),
            
            imageView.heightAnchor.constraint(equalToConstant: 70),
            imageView.widthAnchor.constraint(equalToConstant: 150),
            
            refreshButton.widthAnchor.constraint(equalToConstant: 120),
            refreshButton.heightAnchor.constraint(equalToConstant: 30),
        ])
        bringSubviewToFront(containerStackView)
    }
    
    @objc func refreshAction() {
        addLoaderAnimation()
        
        refreshData? { [weak self] in
            DispatchQueue.main.async {
                self?.removeLoaderAnimation()
            }
        }
    }
    
    // MARK: - Loader Animation
    private func addLoaderAnimation() {
        animationView = .init(name: "loader")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.frame = refreshButton.bounds
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        refreshButton.isEnabled = false
        refreshButton.setTitle("", for: .normal)
        refreshButton.addSubview(animationView)
        animationView.play()
        NSLayoutConstraint.activate([
            animationView.centerXAnchor.constraint(equalTo: refreshButton.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: refreshButton.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: 15),
            animationView.heightAnchor.constraint(equalToConstant: 15),
            
        ])
    }
    private func removeLoaderAnimation() {
        DispatchQueue.main.async {
            self.animationView.stop()
            self.animationView.removeFromSuperview()
            self.refreshButton.setTitle("Refresh", for: .normal)
            self.refreshButton.isEnabled = true
        }
    }

}
