//
//  LoginViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 31/10/2024.
//

import UIKit
import Lottie
import SwiftEmailValidator
import RecaptchaEnterprise

class LoginViewController: UIViewController {
    var recaptchaClient: RecaptchaClient?
    let gradientLay = gradientLayer()
    var onLoginSuccess: ((_ profile: Profile, _ completion: @escaping () -> Void) -> Void)?
    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.backgroundColor = .systemBackground
        setupViews()
        runAnimation()
        
        // Add keyboard observers
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillShow(_:)), name: UIResponder.keyboardWillShowNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillHide(_:)), name: UIResponder.keyboardWillHideNotification, object: nil)
        
        // Add tap gesture recognizer to dismiss the keyboard
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        tapGesture.cancelsTouchesInView = false
        view.addGestureRecognizer(tapGesture)
    }
    @objc private func dismissKeyboard() {
        view.endEditing(true) // Dismiss the keyboard for any active responder
    }
    
    @objc private func keyboardWillShow(_ notification: Notification) {
        guard let keyboardFrame = notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect else {
            return
        }
        
        // Check if the active field is hidden by the keyboard
        if let activeField = view.findFirstResponder() as? UITextField {
            let keyboardHeight = keyboardFrame.height
            let bottomSpace = view.frame.height - (activeField.frame.origin.y + activeField.frame.height)
            
            if bottomSpace < keyboardHeight {
                let offset = keyboardHeight - bottomSpace + 10 // Add some padding
                UIView.animate(withDuration: 0.3) {
                    self.view.transform = CGAffineTransform(translationX: 0, y: -offset)
                }
            }
        }
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self, name: UIResponder.keyboardWillShowNotification, object: nil)
        NotificationCenter.default.removeObserver(self, name: UIResponder.keyboardWillHideNotification, object: nil)
    }
    
    @objc private func keyboardWillHide(_ notification: Notification) {
        // Reset the view position when the keyboard is hidden
        UIView.animate(withDuration: 0.3) {
            self.view.transform = .identity
        }
    }
    
    func runAnimation() {
        self.loginButton.transform = CGAffineTransform(translationX: 0, y: 200) // Start button off-screen below
        self.loginButton.alpha = 0 // Start button invisible
        self.titleLabel.transform = CGAffineTransform(translationX: 200, y: 0)
        self.titleLabel.alpha = 0
        self.subtitleLabel.transform = CGAffineTransform(translationX: 200, y: 0)
        self.subtitleLabel.alpha = 0
        self.passwordTextField.transform = CGAffineTransform(translationX: -200, y: 0)
        self.passwordTextField.alpha = 0
        self.passwordLabel.transform = CGAffineTransform(translationX: -200, y: 0)
        self.passwordLabel.alpha = 0
        self.emailTextField.transform = CGAffineTransform(translationX: -200, y: 0)
        self.emailTextField.alpha = 0
        self.emailLabel.transform = CGAffineTransform(translationX: -200, y: 0)
        self.emailLabel.alpha = 0
        
        self.addCurvedBottom(to: self.animatedView)
        UIView.animate(withDuration: 0.5, delay: 0, options: [.curveLinear], animations: {
            self.animatedView.transform = CGAffineTransform(translationX: 0, y: -UIScreen.main.bounds.height * 0.75)
        }) {_ in
            self.logoImageView.isHidden = false
            self.animateLoginButton()
        }
    }
    
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
    
    
    func addLoader() {
        animationView = .init(name: "loader")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.frame = view.bounds
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        loginButton.isEnabled = false
        loginButton.setTitle("", for: .normal)
        loginButton.addSubview(animationView)
        self.view.addSubview(loaderContainer)
        animationView.play()
        NSLayoutConstraint.activate([
            animationView.centerXAnchor.constraint(equalTo: loginButton.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: loginButton.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: 30),
            animationView.heightAnchor.constraint(equalToConstant: 30),
            
            loaderContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            loaderContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            loaderContainer.topAnchor.constraint(equalTo: view.topAnchor),
            loaderContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }
    func removeLoader() {
        DispatchQueue.main.async {
            self.loaderContainer.removeFromSuperview()
            self.animationView.stop()
            self.animationView.removeFromSuperview()
            self.loginButton.setTitle("Login", for: .normal)
            self.loginButton.isEnabled = true
        }
    }
    
    private func animateLoginButton() {
        self.loginButton.isHidden = false
        self.titleLabel.isHidden = false
        self.subtitleLabel.isHidden = false
        self.passwordTextField.isHidden = false
        self.passwordLabel.isHidden = false
        self.emailTextField.isHidden = false
        self.emailLabel.isHidden = false
        UIView.animate(withDuration: 1, delay: 0.2, usingSpringWithDamping: 0.6, initialSpringVelocity: 0.5, options: [], animations: {
            self.loginButton.transform = .identity
            self.loginButton.alpha = 1
            
            self.titleLabel.transform = .identity
            self.titleLabel.alpha = 1
            
            self.subtitleLabel.transform = .identity
            self.subtitleLabel.alpha = 1
            
            self.passwordTextField.transform = .identity
            self.passwordTextField.alpha = 1
            
            self.passwordLabel.transform = .identity
            self.passwordLabel.alpha = 1
            
            self.emailTextField.transform = .identity
            self.emailTextField.alpha = 1
            
            self.emailLabel.transform = .identity
            self.emailLabel.alpha = 1
            
        })
    }
    
    func getCaptchaToken() async {
        // Perform validation before adding the loader or fetching the token
        guard validateInputs() else {
            return
        }
        
        addLoader() // Only add the loader after inputs are validated
        
        let tokenTask: Task<String?, Never> = Task {
            guard let key_id = Bundle.main.object(forInfoDictionaryKey: "KEY_ID") as? String else {
                return nil
            }
            
            do {
                self.recaptchaClient = try await Recaptcha.fetchClient(withSiteKey: key_id)
                if let recaptchaClient = self.recaptchaClient {
                    let token = try await recaptchaClient.execute(withAction: .login)
                    return token
                }
            } catch {
                print("Error fetching recaptcha client: \(error)")
                return nil
            }
            
            return nil
        }
        
        if let token = await tokenTask.value {
            self.executeLogin(token)
        } else {
            removeLoader()
            showErrorAlert("Failed to retrieve captcha token.")
        }
    }
    
    @objc func loginBtnPressed() {
        Task.detached {
            await self.getCaptchaToken()
        }
    }
    
    private func executeLogin(_ gtoken: String) {
        self.login(
            email: emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
            password: passwordTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "",
            gtoken: gtoken
        )
    }
    
    private func validateInputs() -> Bool {
        let email = emailTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordTextField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if email.isEmpty {
            showErrorAlert("Email cannot be empty")
            return false
        }
        
        if password.isEmpty {
            showErrorAlert("Password cannot be empty")
            return false
        }
        
        if !isEmailValid(email) {
            showErrorAlert("The email is not valid")
            return false
        }
        
        if !isPasswordValid(password) {
            showErrorAlert("Password format is not valid")
            return false
        }
        
        return true
    }
    
    
    var isExecuting = false
    private func login(email: String, password: String, gtoken: String) {
        if (email == "") {
            removeLoader()
            showErrorAlert("Email cannot be empty")
            return
        }
        if (password == "") {
            removeLoader()
            showErrorAlert("Password cannot be empty")
            return
        }
        if (!isEmailValid(email)) {
            removeLoader()
            showErrorAlert("The email is not valid")
            return
        }
        if (!isPasswordValid(password)) {
            removeLoader()
            showErrorAlert("Password format is not valid")
            return
        }
        
        if !isExecuting {
            isExecuting = true
            LoginModal.shared.login(email: email, password: password, gtoken: gtoken, rememberMe: true) { [weak self] result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    switch result {
                    case .success(let profile):
                        self.onLoginSuccess?(profile) {
                            self.isExecuting = false
                            self.removeLoader()
                        }
                        
                    case .failure(let error):
                        self.isExecuting = false
                        self.removeLoader()
                        self.handleLoginFailure(with: error)
                    }
                }
            }
            
        }
    }
    
    private func handleLoginFailure(with error: ErrorResponse) {
        showErrorAlert(error.safeErrorMessage)
    }
    
    // Email Input Field
    private let emailTextField: UITextField = {
        let textField = UITextField()
        textField.placeholder = "Please enter your email"
        textField.layer.borderWidth = 0.75
        textField.layer.cornerRadius =  10
        textField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        textField.autocapitalizationType = .none
        textField.keyboardType = .emailAddress
        textField.backgroundColor = UIColor(named: "InputFieldBg")
        textField.font = .systemFont(ofSize: 15, weight: .medium)
        textField.translatesAutoresizingMaskIntoConstraints = false
        
        let paddingView = UIView(frame: CGRect(x: 0, y: 0, width: 20, height: 0))
        textField.leftView = paddingView
        textField.leftViewMode = .always // Ensure padding is always visible
        
        return textField
    }()
    
    private let passwordTextField: UITextField = {
        let textField = UITextField()
        textField.placeholder = "Please enter your password"
        textField.isSecureTextEntry = true
        textField.layer.cornerRadius =  10
        textField.backgroundColor = UIColor(named: "InputFieldBg")
        textField.layer.borderWidth = 0.75
        textField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.font = .systemFont(ofSize: 15, weight: .medium)
        textField.returnKeyType = .done
        
        let paddingView = UIView(frame: CGRect(x: 0, y: 0, width: 20, height: 0)) // Adjust width as needed
        textField.leftView = paddingView
        textField.leftViewMode = .always // Ensure padding is always visible
        
        return textField
    }()
    
    private let loginButton: UIButton = {
        let button = CustomButton()
        button.config("Login")
        button.translatesAutoresizingMaskIntoConstraints = false
        button.addTarget(self, action: #selector(loginBtnPressed), for: .touchUpInside)
        return button
    }()
    
    private let errorLabel: UILabel = {
        let label = UILabel()
        label.textAlignment = .left
        label.font = UIFont.systemFont(ofSize: 12)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.textColor = .red
        label.numberOfLines = 0
        return label
    }()
    
    lazy var titleLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 24, weight: .bold)
        label.text = "Welcome to Zaytech Scanner"
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false
        
        return label
    }()
    
    lazy var subtitleLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 14, weight: .light)
        label.text = "Please enter your credentials to login"
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false
        
        return label
    }()
    
    lazy var emailLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 15, weight: .bold)
        label.text = "Email"
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    lazy var passwordLabel: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 15, weight: .semibold)
        label.text = "Password"
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private func setupViews() {
        emailTextField.delegate = self
        passwordTextField.delegate = self
        
        view.addSubview(titleLabel)
        view.addSubview(subtitleLabel)
        view.addSubview(emailLabel)
        view.addSubview(emailTextField)
        view.addSubview(passwordLabel)
        view.addSubview(passwordTextField)
        view.addSubview(loginButton)
        view.addSubview(animatedView)
        view.addSubview(logoImageView)
        
        NSLayoutConstraint.activate([
            
            loginButton.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: loginButton.trailingAnchor, multiplier: 2),
            loginButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -15),
            loginButton.heightAnchor.constraint(equalToConstant: 50),
            loginButton.topAnchor.constraint(greaterThanOrEqualTo: passwordTextField.bottomAnchor, constant: 30),
            
            titleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            titleLabel.topAnchor.constraint(equalTo: logoImageView.bottomAnchor, constant: 35),
            
            subtitleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 15),
            
            emailLabel.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            emailLabel.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 30),
            
            emailTextField.topAnchor.constraint(equalTo: emailLabel.bottomAnchor, constant: 10),
            emailTextField.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: emailTextField.trailingAnchor, multiplier: 2),
            emailTextField.heightAnchor.constraint(equalToConstant: 50),
            
            passwordLabel.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            passwordLabel.topAnchor.constraint(equalTo: emailTextField.bottomAnchor, constant: 25),
            
            passwordTextField.leadingAnchor.constraint(equalToSystemSpacingAfter: view.leadingAnchor, multiplier: 2),
            view.trailingAnchor.constraint(equalToSystemSpacingAfter: passwordTextField.trailingAnchor, multiplier: 2),
            passwordTextField.topAnchor.constraint(equalTo: passwordLabel.bottomAnchor, constant: 10),
            passwordTextField.heightAnchor.constraint(equalToConstant: 50),
            
            animatedView.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            animatedView.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
            animatedView.topAnchor.constraint(equalTo: self.view.topAnchor),
            animatedView.heightAnchor.constraint(equalTo: self.view.heightAnchor, multiplier: 0.25),
            
            logoImageView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            logoImageView.topAnchor.constraint(equalTo: animatedView.bottomAnchor, constant: -30),
            logoImageView.widthAnchor.constraint(equalToConstant: 80),
            logoImageView.heightAnchor.constraint(equalToConstant: 80)
        ])
    }
    
    
    func addCurvedBottom(to view: UIView) {
        let path = UIBezierPath()
        let width = self.view.bounds.width
        let height = self.view.bounds.height
        
        path.move(to: CGPoint(x: 0, y: 0))
        path.addLine(to: CGPoint(x: width, y: 0))
        path.addLine(to: CGPoint(x: width, y: height - 20))
        path.addQuadCurve(to: CGPoint(x: 0, y: height - 20), controlPoint: CGPoint(x: width / 2, y: height + 20))
        path.close()
        
        let shapeLayer = CAShapeLayer()
        shapeLayer.path = path.cgPath
        shapeLayer.fillColor = UIColor.blue.cgColor
        
        view.layer.mask = shapeLayer
    }
    
    lazy var logoImageView: UIImageView = {
        let imgView = UIImageView()
        imgView.translatesAutoresizingMaskIntoConstraints = false
        imgView.image = UIImage(named: "Scanner")
        imgView.isHidden = true
        imgView.layer.borderWidth = 3
        imgView.layer.cornerRadius = 40
        imgView.layer.borderColor = UIColor.systemBackground.cgColor
        return imgView
    }()
    lazy var animatedView: UIView = {
        let view = UIView()
        gradientLay.frame = self.view.bounds
        view.layer.insertSublayer(gradientLay, at: 0)
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    // Validate email format using SwiftEmailValidator
    func isEmailValid(_ email: String) -> Bool {
        return EmailSyntaxValidator.correctlyFormatted(email.lowercased())
    }
    func isPasswordValid(_ password: String) -> Bool {
        if password.count < 6 {
            return false
        }
        return true
    }
    
    func showErrorAlert(_ message: String) {
        let errorAlert = ErrorAlertViewController(message: message)
        self.present(errorAlert, animated: true)
    }
    func showErrorLabel( _ txtField: UITextField? = nil) {
        errorLabel.removeFromSuperview()
        guard let textField = txtField else {
            return
        }
        view.addSubview(errorLabel)
        NSLayoutConstraint.activate([
            errorLabel.topAnchor.constraint(equalTo: textField.bottomAnchor, constant: 3),
            errorLabel.leadingAnchor.constraint(equalTo: textField.leadingAnchor)
        ])
    }
}


extension LoginViewController: UITextFieldDelegate {
    func textFieldShouldEndEditing(_ textField: UITextField) -> Bool {
        if textField.text != "" {
            if let input = textField.text {
                if textField == emailTextField {
                    if (!isEmailValid(input)) {
                        textField.layer.borderColor = UIColor.red.cgColor
                        errorLabel.text = "The email is not valid"
                        showErrorLabel(textField)
                    }
                }
                if textField == passwordTextField {
                    if (!isPasswordValid(input)) {
                        textField.layer.borderColor = UIColor.red.cgColor
                        errorLabel.text = "Password should be minimum 6 characters"
                        showErrorLabel(textField)
                    }
                }
            }
        }else {
            textField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
            showErrorLabel()
        }
        return true
    }
    func removeErrorLabel() {
        errorLabel.removeFromSuperview()
    }
    func textFieldDidChangeSelection(_ textField: UITextField) {
        showErrorLabel()
        textField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
    }
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if (textField == emailTextField) {
            passwordTextField.becomeFirstResponder()
        } else {
            textField.resignFirstResponder()
            Task.detached {
                await self.getCaptchaToken()
            }
        }
        return true
    }
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        logoImageView.layer.borderColor = UIColor.systemBackground.cgColor
        logoImageView.image = UIImage(named: "Scanner")
        passwordTextField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
        emailTextField.layer.borderColor = UIColor(named: "InputFieldBorders")?.cgColor
    }
}
