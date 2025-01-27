//
//  ProfileViewController.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 21/1/2025.
//

import UIKit
import Lottie
import SwiftUICore

class ProfileViewController: UIViewController {
    
    // MARK: - Properties
    private let user: User
    private let merchant: Merchant
    var onLogout: ((_ completion: @escaping () -> Void) -> Void)?
    var onChangeMerchant: ((_ completion: @escaping () -> Void) -> Void)?
    
    // MARK: - UI Components
    
    private let shadowContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        
        // Shadow configuration
        view.layer.shadowColor = UIColor.label.cgColor
        view.layer.shadowOpacity = 0.2
        view.layer.shadowOffset = CGSize(width: 0, height: 4)
        view.layer.shadowRadius = 6
        view.layer.masksToBounds = false
        
        return view
    }()
    
    private let profileContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.layer.cornerRadius = 12
        view.backgroundColor = .systemBackground
        view.layer.masksToBounds = true
        
        return view
    }()
    
    private let initialsView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = UIColor(named: "ProfileIconColor")
        view.layer.cornerRadius = 25
        return view
    }()
    
    private let initialsLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 18, weight: .semibold)
        label.textColor = .black
        return label
    }()
    
    private let nameLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 16, weight: .semibold)
        label.textColor = .label
        return label
    }()
    
    private let emailLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 14)
        label.textColor = .secondaryLabel
        return label
    }()
    
    private let groupTitleLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 14)
        label.textColor = .secondaryLabel
        label.text = "Your selected group: "
        return label
    }()
    
    private let groupContainer: UIView = {
        let view = UIView()
        view.backgroundColor = UIColor(named: "CellBackgroundColor")
        view.isUserInteractionEnabled = true
        view.layer.cornerRadius =  10
        view.layer.borderWidth = 0.75
        view.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let groupIconImageView: UIImageView = {
        let imageView = UIImageView()
        imageView.contentMode = .scaleToFill
        imageView.image = UIImage(named: "MerchantSymbol")
        imageView.translatesAutoresizingMaskIntoConstraints = false
        return imageView
    }()
    
    private let groupNameLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 16, weight: .semibold)
        return label
    }()
    
    private let groupHandleLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 14)
        label.textColor = .secondaryLabel
        return label
    }()
    
    private let changeButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Change", for: .normal)
        button.titleLabel?.font = .systemFont(ofSize: 16, weight: .semibold)
        button.setTitleColor(.white, for: .normal)
        button.backgroundColor = UIColor(named: "ButtonColor")
        button.layer.cornerRadius = 15
        button.isUserInteractionEnabled = true
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    private let locationsStackView: UIStackView = {
        let stackView = UIStackView()
        stackView.axis = .vertical
        stackView.spacing = 5
        stackView.translatesAutoresizingMaskIntoConstraints = false
        return stackView
    }()
    
    private let logoutButton: UIButton = {
        let button = UIButton(type: .system)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Log Out", for: .normal)
        button.titleLabel?.font = .systemFont(ofSize: 16, weight: .medium)
        button.backgroundColor = .red
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 25
        
        let imageConfig = UIImage.SymbolConfiguration(pointSize: 18, weight: .medium)
        let image = UIImage(systemName: "rectangle.portrait.and.arrow.right", withConfiguration: imageConfig)
        button.setImage(image, for: .normal)
        button.tintColor = .white
        button.semanticContentAttribute = .forceRightToLeft
        return button
    }()
    
    private let locationsStackViewContainer: UIView = {
        let view = UIView()
        view.backgroundColor = UIColor(named: "InputFieldBg")
        view.layer.cornerRadius = 15
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    // MARK: - Initializer
    init(user: User, merchant: Merchant) {
        self.user = user
        self.merchant = merchant
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // MARK: - Lifecycle
    override func viewDidLoad() {
        super.viewDidLoad()
        setupView()
        setupNavigationBar()
        setupConstraints()
        configureWithUser(user)
        configureWithMerchant(merchant)
        let merchantsNumber = user.groupMerchants.count
        if (merchantsNumber > 1) {
            self.addChangeMerchantConditionally()
        }
    }
    
    // MARK: - Setup
    private func setupView() {
        view.backgroundColor = .systemBackground
        
        
        view.addSubview(shadowContainer)
        
        shadowContainer.addSubview(profileContainer)
        
        profileContainer.addSubview(initialsView)
        
        initialsView.addSubview(initialsLabel)
        profileContainer.addSubview(nameLabel)
        profileContainer.addSubview(emailLabel)
        
        view.addSubview(groupTitleLabel)
        view.addSubview(groupContainer)
        
        groupContainer.addSubview(groupIconImageView)
        groupContainer.addSubview(groupNameLabel)
        groupContainer.addSubview(groupHandleLabel)
        groupContainer.addSubview(locationsStackViewContainer)
        
        locationsStackViewContainer.addSubview(locationsStackView)
        
        view.addSubview(logoutButton)
        
        logoutButton.addTarget(self, action: #selector(logoutTapped), for: .touchUpInside)
        changeButton.addTarget(self, action: #selector(changeTapped), for: .touchUpInside)
    }
    
    private func setupNavigationBar() {
        let backButton = UIBarButtonItem(
            image: UIImage(systemName: "chevron.left"),
            style: .plain,
            target: self,
            action: #selector(backTapped)
        )
        backButton.tintColor = .label
        backButton.title = "Test"
        navigationItem.leftBarButtonItem = backButton
    }
    
    private func addChangeMerchantConditionally() {
        groupContainer.addSubview(changeButton)
        
        NSLayoutConstraint.activate([
            changeButton.centerYAnchor.constraint(equalTo: groupIconImageView.centerYAnchor),
            changeButton.trailingAnchor.constraint(equalTo: groupContainer.trailingAnchor, constant: -15),
            changeButton.widthAnchor.constraint(equalToConstant: 90),
            changeButton.heightAnchor.constraint(equalToConstant: 30),
        ])
    }
    
    private func setupConstraints() {
        NSLayoutConstraint.activate([
            
            shadowContainer.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 40),
            shadowContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            shadowContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            shadowContainer.heightAnchor.constraint(equalToConstant: 80),
            
            profileContainer.leadingAnchor.constraint(equalTo: shadowContainer.leadingAnchor),
            profileContainer.trailingAnchor.constraint(equalTo: shadowContainer.trailingAnchor),
            profileContainer.heightAnchor.constraint(equalTo: shadowContainer.heightAnchor, multiplier: 1),
            
            initialsView.leadingAnchor.constraint(equalTo: profileContainer.leadingAnchor, constant: 20),
            initialsView.centerYAnchor.constraint(equalTo: profileContainer.centerYAnchor),
            initialsView.widthAnchor.constraint(equalToConstant: 50),
            initialsView.heightAnchor.constraint(equalToConstant: 50),
            
            initialsLabel.centerXAnchor.constraint(equalTo: initialsView.centerXAnchor),
            initialsLabel.centerYAnchor.constraint(equalTo: initialsView.centerYAnchor),
            
            nameLabel.topAnchor.constraint(equalTo: profileContainer.topAnchor, constant: 20),
            nameLabel.leadingAnchor.constraint(equalTo: initialsView.trailingAnchor, constant: 25),
            
            emailLabel.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 5),
            emailLabel.leadingAnchor.constraint(equalTo: nameLabel.leadingAnchor),
            
            groupTitleLabel.topAnchor.constraint(equalTo: shadowContainer.bottomAnchor, constant: 25),
            groupTitleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            groupTitleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            
            groupContainer.topAnchor.constraint(equalTo: groupTitleLabel.bottomAnchor, constant: 15),
            groupContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            groupContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            
            groupIconImageView.topAnchor.constraint(equalTo: groupContainer.topAnchor, constant: 15),
            groupIconImageView.leadingAnchor.constraint(equalTo: groupContainer.leadingAnchor, constant: 15),
            groupIconImageView.widthAnchor.constraint(equalToConstant: 50),
            groupIconImageView.heightAnchor.constraint(equalToConstant: 50),
            
            groupNameLabel.topAnchor.constraint(equalTo: groupContainer.topAnchor, constant: 20),
            groupNameLabel.leadingAnchor.constraint(equalTo: groupIconImageView.trailingAnchor, constant: 15),
            
            groupHandleLabel.topAnchor.constraint(equalTo: groupNameLabel.bottomAnchor, constant: 3),
            groupHandleLabel.leadingAnchor.constraint(equalTo: groupNameLabel.leadingAnchor),
            
            locationsStackViewContainer.topAnchor.constraint(equalTo: groupIconImageView.bottomAnchor, constant: 20),
            locationsStackViewContainer.leadingAnchor.constraint(equalTo: groupContainer.leadingAnchor, constant: 15),
            locationsStackViewContainer.trailingAnchor.constraint(equalTo: groupContainer.trailingAnchor, constant: -15),
            locationsStackViewContainer.bottomAnchor.constraint(equalTo: groupContainer.bottomAnchor, constant: -15),
            
            locationsStackView.topAnchor.constraint(equalTo: locationsStackViewContainer.topAnchor, constant: 15),
            locationsStackView.leadingAnchor.constraint(equalTo: locationsStackViewContainer.leadingAnchor, constant: 15),
            locationsStackView.trailingAnchor.constraint(equalTo: locationsStackViewContainer.trailingAnchor, constant: -15),
            locationsStackView.bottomAnchor.constraint(equalTo: locationsStackViewContainer.bottomAnchor, constant: -15),
            
            logoutButton.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: logoutButton.trailingAnchor, multiplier: 2),
            logoutButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -15),
            logoutButton.topAnchor.constraint(greaterThanOrEqualTo: groupContainer.bottomAnchor, constant: 25),
            logoutButton.heightAnchor.constraint(equalToConstant: 50)
        ])
    }
    
    private func configureWithUser(_ user: User) {
        nameLabel.text = user.name
        emailLabel.text = user.email
        initialsLabel.text = user.name?.split(separator: " ").prefix(2).map { String($0.prefix(1)) }.joined()
    }
    
    private func configureWithMerchant(_ merchant: Merchant) {
        groupNameLabel.text = merchant.name
        groupHandleLabel.text = "@\(merchant.slug ?? "no-slug")"
        
        locationsStackView.arrangedSubviews.forEach { $0.removeFromSuperview() }
        
        let maxVisibleLocations = 2
        let visibleLocations = merchant.locations.prefix(maxVisibleLocations)
        
        for location in visibleLocations {
            let label = UILabel()
            label.text = location?.name
            label.font = .systemFont(ofSize: 14)
            label.textColor = .secondaryLabel
            locationsStackView.addArrangedSubview(label)
        }
        
        if merchant.locations.count > maxVisibleLocations {
            let title = "+\(merchant.locations.count - maxVisibleLocations) more"
            
            let attributedString = NSMutableAttributedString(string: title)
            attributedString.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: NSRange(location: 0, length: title.count))
            
            let moreButton = UIButton(type: .system)
            moreButton.titleLabel?.font = .systemFont(ofSize: 14, weight: .medium)
            moreButton.contentHorizontalAlignment = .left
            moreButton.addTarget(self, action: #selector(moreTapped), for: .touchUpInside)
            moreButton.setAttributedTitle(attributedString, for: .normal)
            locationsStackView.addArrangedSubview(moreButton)
        }
    }
    
    // MARK: - Actions
    @objc private func backTapped() {
        navigationController?.popViewController(animated: true)
    }
    
    @objc private func logoutTapped() {
        self.addLoaderAnimation(with: logoutButton, 30)
        self.onLogout? {
            self.removeLoaderAnimation(from: self.logoutButton, "Log Out", true)
        }
    }
    
    @objc private func changeTapped() {
        self.addLoaderAnimation(with: changeButton, 15)
        self.onChangeMerchant? {
            self.removeLoaderAnimation(from: self.changeButton, "Change")
        }
        
    }
    
    @objc private func moreTapped() {
        let vc = MerchantLocationsViewController(merchant: self.merchant)
        vc.modalPresentationStyle = .overCurrentContext
        vc.modalTransitionStyle = .crossDissolve
        self.present(vc, animated: true)
    }
    
    // MARK: - Animation
    private lazy var animationView: LottieAnimationView = {
        let animationView = LottieAnimationView()
        return animationView
    }()
    
    lazy var loaderContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = .black.withAlphaComponent(0)
        return view
    }()
    
    private func addLoaderAnimation(with item: UIButton, _ size: CGFloat) {
        animationView = .init(name: "loader")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.frame = view.bounds
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        item.isEnabled = false
        item.setTitle("", for: .normal)
        item.addSubview(animationView)
        self.view.addSubview(loaderContainer)
        animationView.play()
        NSLayoutConstraint.activate([
            animationView.centerXAnchor.constraint(equalTo: item.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: item.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: size),
            animationView.heightAnchor.constraint(equalToConstant: size),
            
            loaderContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            loaderContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            loaderContainer.topAnchor.constraint(equalTo: view.topAnchor),
            loaderContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
        ])
    }
    private func removeLoaderAnimation(from item: UIButton, _ title: String, _ icon: Bool = false) {
        DispatchQueue.main.async {
            self.loaderContainer.removeFromSuperview()
            self.animationView.stop()
            self.animationView.removeFromSuperview()
            item.setTitle(title, for: .normal)
            item.isEnabled = true
            if (icon) {
                let imageConfig = UIImage.SymbolConfiguration(pointSize: 18, weight: .medium)
                let image = UIImage(systemName: "rectangle.portrait.and.arrow.right", withConfiguration: imageConfig)
                item.setImage(image, for: .normal)
            }
            item.tintColor = .white
            item.semanticContentAttribute = .forceRightToLeft
        }
    }
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        
        self.groupContainer.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        self.shadowContainer.layer.shadowColor = UIColor.label.cgColor
    }
}
