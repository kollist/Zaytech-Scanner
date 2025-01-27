//
//  AppCoordinator.swift
//  ZaytechScanner
//
//  Created by Zaytech Mac on 16/1/2025.
//

import UIKit

protocol Coordinator {
    var navigationController: UINavigationController { get set }
    func start()
}


class AppCoordinator: Coordinator {
    var navigationController: UINavigationController
    var window: UIWindow?
    
    // Simulated state for example purposes
    private var hasChosenLocation: Bool = false
    private var userdefaults = UserDefaultsManager.shared
    private var merchantsmodal = MerchantsModal.shared
    private var profilemodal = ProfileModal.shared
    
    init(navigationController: UINavigationController, window: UIWindow?) {
        self.navigationController = navigationController
        self.window = window
    }
    
    func start() {
        showSplash()
    }
    
    private func showSplash() {
        let splashVC = SplashScreenViewController()
        splashVC.onSpalshEnding = { [weak self] in
            self?.determineStartingScreen()
        }
        window?.rootViewController = splashVC
        window?.makeKeyAndVisible()
    }
    
    
    private func determineStartingScreen() {
        self.userdefaults.isTokenValid { result in
            switch result {
            case .noToken:
                self.showLogin()
            case .noSlug:
                self.showLocations(true){}
            case .valid:
                self.showScanning() {}
            case .invalid:
                self.showLogin()
            }
        }
    }
    
    private func showLogin() {
        let loginVC = LoginViewController()
        loginVC.onLoginSuccess = { [weak self] profile, completion in
            let merchants = profile.user?.groupMerchants.compactMap { $0 } ?? []
            if merchants.count == 1, let slug = merchants.first?.slug {
                self?.userdefaults.saveMerchant(slug: slug)
                self?.showScanning() {
                    completion()
                }
                completion()
                return
            }
            self?.showLocations(true){
                completion()
            }
        }
        window?.rootViewController = loginVC
        window?.makeKeyAndVisible()
    }
    
    private func showLocations(_ isRoot: Bool, _ completion: @escaping () -> Void) {
        self.merchantsmodal.fetchLocations { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success(result: let merchants):
                let locationsVC = MerchantsListViewController(merchants: merchants, isRoot: isRoot)
                locationsVC.onLocationSelected = { [weak self] slug in
                    if let slugMerchant = slug {
                        self?.userdefaults.saveMerchant(slug: slugMerchant)
                        self?.hasChosenLocation = true
                        self?.showScanning() {
                            completion()
                        }
                    } else {
                        self?.showErrorVC("This merchant does not have a valid slug assigned.")
                    }
                }
                // Pass data-fetching logic via fetchLocations
                locationsVC.fetchLocations = { [weak self] completion in
                    self?.getLocations { merchants in
                        completion(merchants)
                    }
                }
                if isRoot {
                    // Set as rootViewController on first login
                    self.navigationController = UINavigationController(rootViewController: locationsVC)
                    self.window?.rootViewController = self.navigationController
                    self.window?.makeKeyAndVisible()
                } else {
                    // Push for subsequent changes
                    self.navigationController.pushViewController(locationsVC, animated: true)
                }
                
            case .failure(let error):
                self.showErrorVC(error.safeErrorMessage)
                if error.isUnauthorized {
                    self.showLogin()
                }
            }
            
            // Ensure completion is called after everything is handled
            completion()
        }
    }
    
    private func getLocations(completion: @escaping ([Merchant]) -> Void) {
        self.merchantsmodal.fetchLocations { [weak self] result in
            switch result {
            case .success(let merchants):
                completion(merchants) // Pass merchants to the completion handler
            case .failure(let error):
                self?.showErrorVC(error.safeErrorMessage)
                if error.isUnauthorized {
                    self?.showLogin()
                }
                completion([]) // Pass an empty array in case of failure
            }
        }
    }
    
    
    private func showErrorVC(_ message: String) {
        let errorVC = ErrorAlertViewController(message: message)
        
        guard let rootViewController = getRootViewController() else { return }
        
        rootViewController.present(errorVC, animated: true)
    }
    
    
    private func getRootViewController() -> UIViewController? {
        guard let rootViewController = window?.rootViewController else {
            print("Error: No rootViewController found for the window")
            return nil
        }
        return rootViewController
    }
    
    private func showScanning(completion: @escaping () -> Void) {
        let scanningVC = QRScannerViewController()
        
        scanningVC.onScanComplete = { [weak self] (event, ticketNumber) in
            if event != nil && ticketNumber != nil {
                self?.showResult(event, ticketNumber)
            } else {
                self?.showResult()
            }
        }
        
        scanningVC.onProfileTap = { [weak self] profileCompletion in
            self?.showProfile {
                profileCompletion() // Execute profileCompletion after profile is shown
            }
        }
        
        scanningVC.onShowCheckManual = { [weak self] manualCompletion in
            self?.showScanningManual(scanningVC)
            manualCompletion() // Execute manualCompletion after manual scanning is shown
        }
        
        self.navigationController = UINavigationController(rootViewController: scanningVC)
        window?.rootViewController = self.navigationController
        window?.makeKeyAndVisible()
        
        // Trigger the completion after everything is set up
        completion()
    }

    
    private func showScanningManual(_ scanningVC: QRScannerViewController) {
        let viewControllerToPresent = CheckManuallViewController()
        
        viewControllerToPresent.onScanComplete = { [weak self] (event, ticketNumber) in
            let eventExist = event ?? nil
            let ticketNumberExist = ticketNumber ?? nil
            self?.showResult(eventExist, ticketNumberExist)
            viewControllerToPresent.dismiss(animated: true)
        }
        
        let navigationController = UINavigationController(rootViewController: viewControllerToPresent)
        viewControllerToPresent.delegate = scanningVC
        navigationController.modalPresentationStyle = .overCurrentContext
        navigationController.modalTransitionStyle = .crossDissolve
        navigationController.setNavigationBarHidden(true, animated: false)
        self.navigationController.present(navigationController, animated: true, completion: nil)
    }
    
    private func showResult(_ event: Event? = nil, _ ticketNumber: String? = nil) {
        let resultVC = ResultViewController()
        if let eventExist = event, let ticketNumberExist = ticketNumber {
            resultVC.eventInstance = event
            resultVC.ticketNumber = ticketNumber
        } else {
            resultVC.notFound = true
        }

        resultVC.onBackToScan = { [weak self] in
            self?.navigationController.popToRootViewController(animated: true)
        }
        navigationController.pushViewController(resultVC, animated: true)
    }
    
    private func showProfile(_ completion: @escaping () -> Void) {
        profilemodal.fetchProfile { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success(let user):
                guard let slug = self.userdefaults.getMerchant() else {
                    self.handleMissingMerchant()
                    completion()
                    return
                }
                guard let merchant = user.groupMerchants.compactMap({ $0 }).first(where: { $0.slug == slug }) else {
                    self.handleInvalidMerchant()
                    completion()
                    return
                }
                
                // Initialize ProfileViewController with the user and valid merchant
                let profileVC = ProfileViewController(user: user, merchant: merchant)
                profileVC.onLogout = { [weak self] completion in
                    self?.handleLogout()
                    completion()
                }
                profileVC.onChangeMerchant = { [weak self] completion in
                    self?.showLocations(false){
                        completion()
                    }
                    
                }
                
                self.navigationController.pushViewController(profileVC, animated: true)
                
            case .failure(let error):
                self.handleProfileFetchError(error)
            }
            
            // Ensure completion is called after the process completes
            completion()
        }
    }
    
    private func handleMissingMerchant() {
        showErrorVC("Please choose a merchant before accessing the profile.")
        showLocations(true) {}
    }
    private func handleInvalidMerchant() {
        showErrorVC("The selected merchant is not valid. Please choose a valid merchant.")
        showLocations(true) {}
    }
    private func handleLogout() {
        userdefaults.clearToken()
        userdefaults.clearMerchant()
        hasChosenLocation = false
        showLogin()
    }
    private func handleProfileFetchError(_ error: ErrorResponse) {
        showErrorVC(error.safeErrorMessage)
        if error.isUnauthorized {
            showLogin()
        }
    }
}
