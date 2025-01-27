//
//  LocationsListViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 11/12/2024.
//

import UIKit

// MARK: - LocationsListViewController
class MerchantsListViewController: UIViewController {
    
    var onLocationSelected: ((_ slug: String?) -> Void)?
    var fetchLocations: ((_ completion: @escaping ([Merchant]) -> Void) -> Void)?
    
    private var merchants: [Merchant]
    private var isRoot: Bool
    private var filteredMerchants: [Merchant] = [] // Filtered data
    private let minimumMerchants = 5
    private let noMerchantsView = NoMerchantsView()
    
    init(merchants: [Merchant], isRoot: Bool) {
        self.merchants = merchants
        self.isRoot = isRoot
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private let tableView: UITableView = {
        let table = UITableView()
        table.separatorStyle = .none
        table.translatesAutoresizingMaskIntoConstraints = false
        table.sectionHeaderTopPadding = 0
        return table
    }()
    
    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = "Select the merchant hosting the event: "
        label.numberOfLines = 2
        label.font = .systemFont(ofSize: 20, weight: .semibold)
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let searchBarTextField: UITextField = {
        let textField = UITextField()
        textField.placeholder = "Search for merchant name..."
        textField.layer.borderWidth = 0.75
        textField.layer.cornerRadius = 10
        textField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        textField.autocapitalizationType = .none
        textField.font = .systemFont(ofSize: 15, weight: .medium)
        textField.translatesAutoresizingMaskIntoConstraints = false
        
        // Create left view container for the search icon
        let leftViewContainer = UIView()
        
        // Create and configure search icon
        let searchIcon = UIImageView()
        searchIcon.image = UIImage(named: "SearchIcon")
        searchIcon.contentMode = .scaleAspectFit
        searchIcon.translatesAutoresizingMaskIntoConstraints = false
        
        // Add search icon to container
        leftViewContainer.addSubview(searchIcon)
        
        // Set constraints for the search icon
        NSLayoutConstraint.activate([
            searchIcon.leadingAnchor.constraint(equalTo: leftViewContainer.leadingAnchor, constant: 10),
            searchIcon.topAnchor.constraint(equalTo: leftViewContainer.topAnchor, constant: 15),
            searchIcon.widthAnchor.constraint(equalToConstant: 20),
            searchIcon.heightAnchor.constraint(equalToConstant: 20),
        ])
        
        // Set the size of the left view container
        leftViewContainer.widthAnchor.constraint(equalToConstant: 40).isActive = true
        leftViewContainer.translatesAutoresizingMaskIntoConstraints = false
        
        // Set left view
        textField.leftView = leftViewContainer
        textField.leftViewMode = .always
        
        return textField
    }()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupView()
        setupTableView()
        
        filteredMerchants = merchants // Initially show all merchants
        
        if (!self.isRoot) {
            configNavButton()
        }
    }
    
    func configNavButton() {
        
        let backButton = UIBarButtonItem(
            image: UIImage(systemName: "chevron.left"),
            style: .plain,
            target: self,
            action: #selector(backTapped)
        )
        backButton.tintColor = .label
        navigationItem.leftBarButtonItem = backButton
    }
    
    @objc func backTapped() {
        navigationController?.popViewController(animated: true)
    }
    
    private func setupView() {
        view.backgroundColor = .systemBackground
        
        // Always add titleLabel and tableView
        view.addSubview(titleLabel)
        view.addSubview(tableView)
        
        var constraints = [
            titleLabel.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: titleLabel.trailingAnchor, multiplier: 2),
            
            tableView.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 15),
            tableView.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: tableView.trailingAnchor, multiplier: 2),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ]
        
        if merchants.count >= minimumMerchants {
            searchBarTextField.delegate = self
            view.addSubview(searchBarTextField)
            
            constraints.append(contentsOf: [
                searchBarTextField.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
                searchBarTextField.heightAnchor.constraint(equalToConstant: 50),
                searchBarTextField.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
                view.trailingAnchor.constraint(equalToSystemSpacingAfter: searchBarTextField.trailingAnchor, multiplier: 2),
                
                titleLabel.topAnchor.constraint(equalTo: searchBarTextField.bottomAnchor, constant: 20),
            ])
        } else {
            constraints.append(titleLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor))
        }
        
        NSLayoutConstraint.activate(constraints)
    }
    
    private func dataReloaded() {
        titleLabel.removeFromSuperview()
        self.setupView()
    }
    
    private func setupTableView() {
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(MerchantTableViewCell.self, forCellReuseIdentifier: MerchantTableViewCell.identifier)
        noMerchantsView.refreshData = { [weak self] completion in
            self?.fetchLocations? { merchants in
                self?.merchants = merchants
                self?.filteredMerchants = merchants
                completion()
                self?.tableView.reloadData()
                self?.view.layoutIfNeeded()
                self?.updateUI()
                self?.dataReloaded()
            }
        }
        updateUI()
    }
    
    private func updateUI() {
        if merchants.isEmpty {
            showNoMerchantsView()
        } else {
            hideNoMerchantsView()
        }
        tableView.reloadData()
    }
    
    private func showNoMerchantsView() {
        noMerchantsView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(noMerchantsView)
        view.bringSubviewToFront(noMerchantsView)
        view.isUserInteractionEnabled = true
        noMerchantsView.isUserInteractionEnabled = true
        
        NSLayoutConstraint.activate([
            noMerchantsView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            noMerchantsView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            
            noMerchantsView.heightAnchor.constraint(equalTo: view.heightAnchor, multiplier: 0.2),
            noMerchantsView.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.85),
        ])
    }
    
    private func hideNoMerchantsView() {
        noMerchantsView.removeFromSuperview()
    }
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        searchBarTextField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
    }
}

// MARK: - UITableView Delegate & DataSource
extension MerchantsListViewController: UITableViewDelegate, UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableView.automaticDimension
    }
    
    func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        return section > 0 ? UIView() : nil
    }
    
    func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        return section == 0 ? 0 : (filteredMerchants.count > 5 ? 17 : 36)
    }
    
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return filteredMerchants.count
    }
    
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: MerchantTableViewCell.identifier, for: indexPath) as? MerchantTableViewCell else { return UITableViewCell() }
        let lessType = filteredMerchants.count > minimumMerchants ? false : true;
        let merchant = filteredMerchants[indexPath.section]
        cell.configure(with: merchant, less: lessType)
        cell.onSlugSaved = { [weak self] slug in
            self?.onLocationSelected?(slug)
        }
        cell.onLocationsShow = { [weak self] in
            let vc = MerchantLocationsViewController(merchant: merchant)
            vc.modalPresentationStyle = .overCurrentContext
            vc.modalTransitionStyle = .crossDissolve
            self?.present(vc, animated: true)
        }
        return cell
    }
}

// MARK: - UITextField Delegate
extension MerchantsListViewController: UITextFieldDelegate {
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        let currentText = textField.text ?? ""
        guard let stringRange = Range(range, in: currentText) else { return false }
        let updatedText = currentText.replacingCharacters(in: stringRange, with: string)
        filterMerchants(with: updatedText)
        return true
    }
    // MARK: - Filtering Logic
    private func filterMerchants(with query: String) {
        if query.isEmpty {
            filteredMerchants = merchants // Show all merchants if the query is empty
            tableView.backgroundView = nil
        } else {
            filteredMerchants = merchants.filter { merchant in
                return merchant.name?.lowercased().contains(query.lowercased()) ?? false
            }
            if (filteredMerchants.count == 0) {
                tableView.backgroundView = NoResultsBackgroundView()
            }
        }
        tableView.reloadData()
    }
}
