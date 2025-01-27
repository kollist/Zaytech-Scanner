//
//  ErrorAlertViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 8/1/2025.
//


import UIKit

class ErrorAlertViewController: UIViewController {
    
    // MARK: - Properties
    private let errorMessage: String
    private var containerViewBottomConstraint: NSLayoutConstraint?
    
    // MARK: - UI Components
    private let containerView: UIView = {
        let view = UIView()
        view.backgroundColor = .systemBackground
        view.layer.cornerRadius = 20
        view.layer.maskedCorners = [.layerMinXMinYCorner, .layerMaxXMinYCorner]
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let messageLabel: UILabel = {
        let label = UILabel()
        label.textAlignment = .center
        label.font = .systemFont(ofSize: 16)
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let dismissButton: UIButton = {
        let button = CustomButton()
        button.config("Dismiss")
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    private let homeIndicatorView: UIView = {
        let view = UIView()
        view.backgroundColor = .systemGray3
        view.layer.cornerRadius = 2.5
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    // MARK: - Initialization
    init(message: String) {
        self.errorMessage = message
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .overFullScreen
        modalTransitionStyle = .crossDissolve
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // MARK: - Lifecycle Methods
    override func viewDidLoad() {
        super.viewDidLoad()
        setupViews()
        setupActions()
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        animateIn()
    }
    
    // MARK: - Setup Methods
    private func setupViews() {
        view.backgroundColor = UIColor.black.withAlphaComponent(0.5)
        
        view.addSubview(containerView)
        containerView.addSubview(messageLabel)
        containerView.addSubview(dismissButton)
        containerView.addSubview(homeIndicatorView)
        
        messageLabel.text = errorMessage
        
        containerViewBottomConstraint = containerView.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: 400)
        
        NSLayoutConstraint.activate([
            containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            containerViewBottomConstraint!,
            containerView.heightAnchor.constraint(equalToConstant: 200),
            
            messageLabel.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 50),
            messageLabel.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: messageLabel.trailingAnchor, multiplier: 2),

            dismissButton.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 24),
            dismissButton.trailingAnchor.constraint(equalTo: containerView.trailingAnchor, constant: -24),
            dismissButton.bottomAnchor.constraint(equalTo: homeIndicatorView.topAnchor, constant: -16),
            dismissButton.heightAnchor.constraint(equalToConstant: 50),
            
            homeIndicatorView.centerXAnchor.constraint(equalTo: containerView.centerXAnchor),
            homeIndicatorView.bottomAnchor.constraint(equalTo: containerView.bottomAnchor, constant: -8),
            homeIndicatorView.widthAnchor.constraint(equalToConstant: 40),
            homeIndicatorView.heightAnchor.constraint(equalToConstant: 5)
        ])
    }
    
    private func setupActions() {
        dismissButton.addTarget(self, action: #selector(dismissTapped), for: .touchUpInside)
        
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(backgroundTapped))
        view.addGestureRecognizer(tapGesture)
    }
    
    // MARK: - Animation Methods
    private func animateIn() {
        containerViewBottomConstraint?.constant = 0
        UIView.animate(withDuration: 0.3, delay: 0, options: .curveEaseOut, animations: {
            self.view.backgroundColor = UIColor.black.withAlphaComponent(0.5)
            self.view.layoutIfNeeded()
        })
    }
    
    private func animateOut(completion: @escaping () -> Void) {
        containerViewBottomConstraint?.constant = 400
        UIView.animate(withDuration: 0.3, delay: 0, options: .curveEaseIn, animations: {
            self.view.backgroundColor = .clear
            self.view.layoutIfNeeded()
        }, completion: { _ in
            completion()
        })
    }
    
    // MARK: - Actions
    @objc private func dismissTapped() {
        animateOut { [weak self] in
            self?.dismiss(animated: false)
        }
    }
    
    @objc private func backgroundTapped() {
        dismissTapped()
    }
}

