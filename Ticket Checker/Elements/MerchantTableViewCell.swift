//
//  MerchantTableViewCell.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 16/1/2025.
//


import UIKit
import Lottie

class MerchantTableViewCell: UITableViewCell {
    static let identifier = "MerchantTableViewCell"
    
    // MARK: - Properties
    private let maxLocationsToShow = 2
    private var merchantSlug: String? = nil
    var onSlugSaved: ((_ slug: String?) -> Void)?
    var onLocationsShow: (() -> Void)?
    
    // MARK: - UI Components
    private let separatorDot: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = .systemGray
        view.layer.cornerRadius = 3
        return view
    }()
    
    private lazy var animationView: LottieAnimationView = {
        let animationView = LottieAnimationView()
        return animationView
    }()
    
    lazy var animationViewLoaderContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = .black.withAlphaComponent(0)
        return view
    }()
    
    private let containerView: UIView = {
        let view = UIView()
        view.isUserInteractionEnabled = true
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let namesView: UIView = {
        let view = UIView()
        view.isUserInteractionEnabled = true
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let logoImageView: UIImageView = {
        let imageView = UIImageView()
        imageView.contentMode = .scaleToFill
        imageView.image = UIImage(named: "MerchantSymbol")
        imageView.translatesAutoresizingMaskIntoConstraints = false
        return imageView
    }()
    
    private let merchantNameLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 17, weight: .bold)
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let merchantSlugLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 15)
        label.textColor = .systemGray
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let locationsStackViewContainer: UIView = {
        let view = UIView()
        view.backgroundColor = UIColor(named: "InputFieldBg")
        view.layer.cornerRadius = 15
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let locationsStackView: UIStackView = {
        let stackView = UIStackView()
        stackView.axis = .vertical
        stackView.spacing = 5
        stackView.translatesAutoresizingMaskIntoConstraints = false
        return stackView
    }()
    
    private let moreLocationsButton: UIButton = {
        let moreButton = UIButton(type: .system)
        moreButton.titleLabel?.font = .systemFont(ofSize: 14, weight: .medium)
        moreButton.contentHorizontalAlignment = .left
        moreButton.addTarget(self, action: #selector(moreTapped), for: .touchUpInside)
        return moreButton
    }()
    
    private let accessButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Access", for: .normal)
        button.titleLabel?.font = .systemFont(ofSize: 16, weight: .semibold)
        button.setTitleColor(.white, for: .normal)
        button.backgroundColor = UIColor(named: "ButtonColor")
        button.layer.cornerRadius = 15
        button.isUserInteractionEnabled = true
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(selectMerchant), for: .touchUpInside)
        return button
    }()
    
    // MARK: - Initialization
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupCell()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // MARK: - Style
    private func styleCell() {
        backgroundColor = UIColor(named: "CellBackgroundColor")
        selectionStyle = .none
        contentView.isUserInteractionEnabled = true
        layer.cornerRadius =  10
        layer.borderWidth = 0.75
        layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
    }
    // MARK: - Setup
    private func setupCell() {
        styleCell()
        addSubview(containerView)
        
        containerView.addSubview(namesView)
        containerView.addSubview(accessButton)
        containerView.addSubview(logoImageView)
        containerView.addSubview(locationsStackViewContainer)
        
        namesView.addSubview(merchantNameLabel)
        namesView.addSubview(merchantSlugLabel)
        namesView.addSubview(separatorDot)
        
        locationsStackViewContainer.addSubview(locationsStackView)
        
        NSLayoutConstraint.activate([
            containerView.topAnchor.constraint(equalTo: self.topAnchor, constant: 20),
            containerView.leadingAnchor.constraint(equalTo: self.leadingAnchor, constant: 20),
            containerView.trailingAnchor.constraint(equalTo: self.trailingAnchor, constant: -20),
            containerView.bottomAnchor.constraint(equalTo: self.bottomAnchor, constant: -20),
            
            locationsStackViewContainer.topAnchor.constraint(equalTo: namesView.bottomAnchor, constant: 20),
            locationsStackViewContainer.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            locationsStackViewContainer.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
            locationsStackViewContainer.bottomAnchor.constraint(equalTo: containerView.bottomAnchor),
            
            namesView.heightAnchor.constraint(equalToConstant: 40),
            namesView.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 5),
            namesView.leadingAnchor.constraint(equalTo: logoImageView.trailingAnchor, constant: 15),
            namesView.trailingAnchor.constraint(equalTo: accessButton.leadingAnchor, constant: -15),
            
            merchantNameLabel.topAnchor.constraint(equalTo: namesView.topAnchor),
            merchantNameLabel.leadingAnchor.constraint(equalTo: namesView.leadingAnchor),
            
            merchantSlugLabel.topAnchor.constraint(equalTo: merchantNameLabel.bottomAnchor, constant: 3),
            merchantSlugLabel.leadingAnchor.constraint(equalTo: namesView.leadingAnchor),
            
            separatorDot.leadingAnchor.constraint(equalTo: merchantSlugLabel.trailingAnchor, constant: 8),
            separatorDot.topAnchor.constraint(equalTo: merchantNameLabel.bottomAnchor, constant: 10),
            separatorDot.heightAnchor.constraint(equalToConstant: 6),
            separatorDot.widthAnchor.constraint(equalToConstant: 6),
            
            logoImageView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            logoImageView.topAnchor.constraint(equalTo: containerView.topAnchor),
            logoImageView.widthAnchor.constraint(equalToConstant: 50),
            logoImageView.heightAnchor.constraint(equalToConstant: 50),
            
            locationsStackView.topAnchor.constraint(equalTo: locationsStackViewContainer.topAnchor, constant: 15),
            locationsStackView.leadingAnchor.constraint(equalTo: locationsStackViewContainer.leadingAnchor, constant: 15),
            locationsStackView.bottomAnchor.constraint(equalTo: locationsStackViewContainer.bottomAnchor, constant: -15),
            locationsStackView.trailingAnchor.constraint(equalTo: locationsStackViewContainer.trailingAnchor, constant: -15),
            
            accessButton.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 10),
            accessButton.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
            accessButton.widthAnchor.constraint(equalToConstant: 90),
            accessButton.heightAnchor.constraint(equalToConstant: 30)
        ])
    }
    
    // MARK: - Configuration
    func configure(with merchant: Merchant, less: Bool) {
        // Set Merchant Slug and Name to their labels
        merchantNameLabel.text = merchant.name
        merchantSlugLabel.text = "@\(merchant.slug ?? "no-slug")"
        
        // Set Merchant Slug To Local Variable
        if let slug = merchant.slug {
            self.merchantSlug = slug
        }
        
        // Clear previous location labels
        locationsStackView.arrangedSubviews.forEach { $0.removeFromSuperview() }
        
        if (less) {
            lessMerchantsStyle(merchant: merchant)
        } else {
            manyMerchantsStyle(merchant: merchant)
        }
    }
    
    override func prepareForReuse() {
        super.prepareForReuse()
        merchantNameLabel.text = nil
        merchantSlugLabel.text = nil
        moreLocationsButton.setTitle(nil, for: .normal)
        locationsStackView.arrangedSubviews.forEach { $0.removeFromSuperview() }
    }
    
    private func lessMerchantsStyle(merchant: Merchant) {
        // Remove Many Merchants Style
        separatorDot.removeFromSuperview()
        moreLocationsButton.removeFromSuperview()
        namesView.bottomAnchor.constraint(equalTo: containerView.bottomAnchor).isActive = false
        
        // No locations label
        let noLocationsLabel = UILabel()
        noLocationsLabel.text = "This merchant has no locations"
        
        // Add location labels
        let locationsToShow = merchant.locations.prefix(maxLocationsToShow)
        if locationsToShow.isEmpty {
            // No locations label
            let noLocationsLabel = UILabel()
            noLocationsLabel.text = "This merchant has no locations"
            noLocationsLabel.font = .systemFont(ofSize: 15, weight: .bold)
            noLocationsLabel.textColor = .systemGray
            noLocationsLabel.textAlignment = .center
            noLocationsLabel.translatesAutoresizingMaskIntoConstraints = false
            
            // Add the label to the stack view
            locationsStackView.addArrangedSubview(noLocationsLabel)
        } else {
            locationsToShow.forEach { location in
                let label = UILabel()
                label.text = location?.name
                label.textAlignment = .left
                label.font = .systemFont(ofSize: 15, weight: .medium)
                label.textColor = .systemGray
                locationsStackView.addArrangedSubview(label)
            }
        }
        
        // Show more button if there are additional locations
        let remainingLocations = merchant.locations.count - maxLocationsToShow
        if remainingLocations > 0 {
            let title = "+\(remainingLocations) more"
            
            let attributedString = NSMutableAttributedString(string: title)
            attributedString.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: NSRange(location: 0, length: title.count))
            
            moreLocationsButton.setAttributedTitle(attributedString, for: .normal)
            locationsStackView.addArrangedSubview(moreLocationsButton)
        }
    }
    private func manyMerchantsStyle(merchant: Merchant) {
        // Remove Less Merchants Locations Container
        locationsStackViewContainer.removeFromSuperview()
        namesView.bottomAnchor.constraint(equalTo: containerView.bottomAnchor).isActive = true
        
        // Setup the number of locations label
        let title = "\(merchant.locations.count) Locations"
        
        let attributedString = NSMutableAttributedString(string: title)
        attributedString.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: NSRange(location: 0, length: title.count))
        
        moreLocationsButton.setAttributedTitle(attributedString, for: .normal)
        namesView.addSubview(moreLocationsButton)
        NSLayoutConstraint.activate([
            moreLocationsButton.leadingAnchor.constraint(equalTo: separatorDot.trailingAnchor, constant: 8),
            moreLocationsButton.topAnchor.constraint(equalTo: merchantSlugLabel.topAnchor, constant: -6),
        ])
    }
    
    // MARK: - Chose Merchant
    @objc func selectMerchant() {
        self.addLoaderAnimation()
        DispatchQueue.main.asyncAfter (deadline: .now() + 0.25) {
            self.onSlugSaved?(self.merchantSlug)
            self.removeLoaderAnimation()
        }
    }
    
    // MARK: - See Locations
    @objc private func moreTapped() {
        onLocationsShow?()
    }
    
    // MARK: - Loader Animation
    private func addLoaderAnimation() {
        animationView = .init(name: "loader")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.frame = accessButton.bounds
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        accessButton.isEnabled = false
        accessButton.setTitle("", for: .normal)
        accessButton.addSubview(animationView)
        animationView.play()
        NSLayoutConstraint.activate([
            animationView.centerXAnchor.constraint(equalTo: accessButton.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: accessButton.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: 20),
            animationView.heightAnchor.constraint(equalToConstant: 20),
            
        ])
    }
    private func removeLoaderAnimation() {
        DispatchQueue.main.async {
            self.animationView.stop()
            self.animationView.removeFromSuperview()
            self.accessButton.setTitle("Access", for: .normal)
            self.accessButton.isEnabled = true
        }
    }
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        setupCell()
    }
}

