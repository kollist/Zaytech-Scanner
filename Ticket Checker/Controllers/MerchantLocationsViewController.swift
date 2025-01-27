//
//  MerchantLocationsViewController.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 24/1/2025.
//


import UIKit

class MerchantLocationsViewController: UIViewController, UICollectionViewDelegateFlowLayout, UICollectionViewDataSource, UIGestureRecognizerDelegate {
    
    private let merchant: Merchant
    private let collectionView: UICollectionView
    private let titleLabel = UILabel()
    private let containerView = UIView()
    
    init(merchant: Merchant) {
        self.merchant = merchant
        let layout = UICollectionViewFlowLayout()
        layout.minimumInteritemSpacing = 8
        layout.minimumLineSpacing = 8
        self.collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        addTapGesture()
        setupUI()
        setupConstraints()
    }
    
    private func setupUI() {
        
        // Set background color with alpha
        view.backgroundColor = UIColor.black.withAlphaComponent(0.3)
        
        // Title Label
        titleLabel.text = "\(String(describing: merchant.name ?? "Nameless Merchant")) - All Locations"
        titleLabel.font = UIFont.systemFont(ofSize: 24, weight: .bold)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.textAlignment = .left
        titleLabel.textColor = .label
        
        // Container View
        containerView.backgroundColor = UIColor(named: "LocationsBgColor")
        containerView.layer.cornerRadius = 15
        containerView.layer.masksToBounds = true
        containerView.translatesAutoresizingMaskIntoConstraints = false
        
        // Configure Collection View
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        collectionView.backgroundColor = .clear
        collectionView.register(LocationChipCell.self, forCellWithReuseIdentifier: "LocationChipCell")
        collectionView.delegate = self
        collectionView.dataSource = self
        
        // Add subviews
        containerView.addSubview(titleLabel)
        containerView.addSubview(collectionView)
        view.addSubview(containerView)
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        
        collectionView.layoutIfNeeded()
        let contentSize = collectionView.collectionViewLayout.collectionViewContentSize
        
        let maxHeight = view.bounds.height * 0.7
        let newHeight = min(contentSize.height, maxHeight) + view.safeAreaInsets.bottom
        let height = newHeight + titleLabel.frame.height + 40 + view.safeAreaInsets.bottom
        containerView.constraints.filter { $0.firstAttribute == .height }.forEach { $0.isActive = false }
        containerView.heightAnchor.constraint(equalToConstant: height).isActive = true
        
        UIView.animate(withDuration: 0.3) {
            self.view.layoutIfNeeded()
        }
    }
    
    private func setupConstraints() {
        
        
        NSLayoutConstraint.activate([
            // Container View: Fills the bottom part of the screen
            containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            containerView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            containerView.topAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            
            // Title Label: Positioned at the top of the container
            titleLabel.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 20),
            titleLabel.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor
                .constraint(equalTo: containerView.trailingAnchor, constant: -20),
            
            // Collection View: Below the title label and pinned to the bottom of the container
            collectionView.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 20),
            collectionView.leadingAnchor
                .constraint(equalTo: containerView.leadingAnchor, constant: 20),
            collectionView.trailingAnchor
                .constraint(equalTo: containerView.trailingAnchor, constant: -20),
            collectionView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            
        ])
    }
    
    // MARK: - UICollectionViewDataSource
    func numberOfSections(in collectionView: UICollectionView) -> Int {
        return 1
    }
    
    func collectionView(_ collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        return merchant.locations.count
    }
    
    func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        let cell = collectionView.dequeueReusableCell(
            withReuseIdentifier: "LocationChipCell",
            for: indexPath
        ) as! LocationChipCell
        cell.configure(with: merchant.locations[indexPath.item]?.name ?? "Nameless Location")
        return cell
    }
    
    // MARK: - UICollectionViewDelegateFlowLayout
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, sizeForItemAt indexPath: IndexPath) -> CGSize {
        let text = merchant.locations[indexPath.item]?.name ?? "Nameless Location"
        let padding: CGFloat = 20
        let size = (text as NSString).size(withAttributes: [.font: UIFont.systemFont(ofSize: 16)])
        return CGSize(width: size.width + padding, height: 40) // Chip size
    }
    
    private func safeAreaPadding() -> CGFloat {
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let window = windowScene.windows.first {
            return -window.safeAreaInsets.bottom
        }
        return 0
    }
    
    private func addTapGesture() {
        let tapGesture = UITapGestureRecognizer(
            target: self,
            action: #selector(handleTapOutsideContainer)
        )
        tapGesture.delegate = self
        view.addGestureRecognizer(tapGesture)
    }
    
    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
        return !(touch.view == containerView || touch.view?.isDescendant(of: containerView) == true)
    }
    
    @objc private func handleTapOutsideContainer() {
        dismiss(animated: true, completion: nil)
    }
    
}

