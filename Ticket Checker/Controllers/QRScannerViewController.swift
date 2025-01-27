//
//  ViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 17/10/2024.

import UIKit
import AVFoundation
import Lottie
import Network

class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate, UIGestureRecognizerDelegate {

    public var onScanComplete: ((_ event: Event?, _ ticketNumber: String?) -> Void)?
    public var onProfileTap: ((_ completion: @escaping () -> Void) -> Void)?
    public var onShowCheckManual: ((_ completion: @escaping () -> Void) -> Void)?
    private var monitor: NWPathMonitor?
    private var isConnectedToInternet: Bool = false
    var captureDevice: AVCaptureDevice?
    let session = AVCaptureSession()
    private var isProcessingQRCode = false
    private lazy var previewLayer: AVCaptureVideoPreviewLayer = {
        let layer = AVCaptureVideoPreviewLayer()
        layer.frame = view.bounds
        return layer
    }()
    private var isSessionRunning = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.title = "Scan QR code"
        let textAttributes: [NSAttributedString.Key: Any] = [
            .foregroundColor: UIColor.white,
            .font: UIFont.systemFont(ofSize: 18, weight: .semibold)
        ]
        navigationController?.navigationBar.titleTextAttributes = textAttributes
        setup()
        setupNavigationBarButton()
        // Set up the long press gesture
        let longPressGesture = UILongPressGestureRecognizer(target: self, action: #selector(handleLongPress(_:)))
        view.addGestureRecognizer(longPressGesture)
    }
    
    @objc func handleLongPress(_ gesture: UILongPressGestureRecognizer) {
        switch gesture.state {
        case .began:
            toggleFlash(on: true)
        case .ended, .cancelled, .failed:
            toggleFlash(on: false)
        default:
            break
        }
    }
    func toggleFlash(on: Bool) {
        guard let device = captureDevice, device.hasTorch else {
            errorAlert("Device does not support a torch.")
            return
        }
        
        do {
            try device.lockForConfiguration()
            device.torchMode = on ? .on : .off
            device.unlockForConfiguration()
        } catch {
            errorAlert("Failed to toggle flash: \(error.localizedDescription)")
        }
    }


    lazy var checkManuallyButton: CustomButton = {
        let btn = CustomButton()
        btn.config()
        btn.translatesAutoresizingMaskIntoConstraints = false
        btn.addTarget(self, action: #selector(showCheckManulVC), for: .touchUpInside)
        return btn
    }()
    private lazy var animationView: LottieAnimationView = {
        let animationView = LottieAnimationView()
        return animationView
    }()
    func addLoader() {
        animationView = .init(name: "loader")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        
        loaderContainer.addSubview(animationView)
        view.addSubview(loaderContainer)
        
        NSLayoutConstraint.activate([
            loaderContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            loaderContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            loaderContainer.topAnchor.constraint(equalTo: view.topAnchor),
            loaderContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
            animationView.centerXAnchor.constraint(equalTo: loaderContainer.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: loaderContainer.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: 60),
            animationView.heightAnchor.constraint(equalToConstant: 60),
        ])
        
        animationView.play()
    }

    lazy var loaderContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = .black.withAlphaComponent(0.2)
        return view
    }()
    func removeLoader() {
        DispatchQueue.main.async {
            self.animationView.stop()
            self.loaderContainer.removeFromSuperview()
        }
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        startCameraSession()
        startNetworkMonitor {  isConnected in
            if !isConnected {
                self.showNoInternetAlert()
            }
        }

        
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        stopCameraSession()
        monitor?.cancel()
    }
    private func startCameraSession() {
        guard !isSessionRunning else { return }
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.session.startRunning()
            DispatchQueue.main.async { self.isSessionRunning = true }
        }
    }

    private func stopCameraSession() {
        guard isSessionRunning else { return }
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.session.stopRunning()
            DispatchQueue.main.async { self.isSessionRunning = false }
        }
    }

    
    func captureAndScanQR() {
        DispatchQueue.main.async {
            if self.view.subviews.contains(self.goToSettingsButton) {
                self.checkManuallyButton.removeFromSuperview()
                self.goToSettingsButton.removeFromSuperview()
                self.view.addSubview(self.checkManuallyButton)
                
                NSLayoutConstraint.activate([
                    self.checkManuallyButton.leadingAnchor.constraint(equalTo: self.view.leadingAnchor, constant: 15),
                    self.checkManuallyButton.trailingAnchor.constraint(equalTo: self.view.trailingAnchor, constant: -15),
                    self.checkManuallyButton.heightAnchor.constraint(equalToConstant: 50),
                    self.checkManuallyButton.topAnchor.constraint(equalTo: self.view.bottomAnchor, constant: -30),
                ])
            }
        }
        
        if let captureDevice = AVCaptureDevice.default(for: AVMediaType.video) {
            self.captureDevice = captureDevice
            do {
                let input = try AVCaptureDeviceInput(device: captureDevice)
                session.addInput(input)
            } catch {
                errorAlert("Failed to access camera. Please make sure the camera is not being used by another application.")
            }
        } else {
            errorAlert("No camera available. Please check your device settings or ensure your device has a camera.")
            return
        }
        let output = AVCaptureMetadataOutput()
        session.addOutput(output)
        
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        
        previewLayer.session = session
        previewLayer.videoGravity = .resizeAspectFill
        
        
        DispatchQueue.global(qos: .background).async {
            self.session.startRunning()
        }
    }
    
    func addOverlay(x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat) {
        let overlayView = UIView(frame: CGRect(x: x, y: y, width: width, height: height))
        overlayView.backgroundColor = UIColor.black.withAlphaComponent(0.6)
        self.view.addSubview(overlayView)
    }
    
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !isProcessingQRCode else { return }
            isProcessingQRCode = true
        
            let resultVC = ResultViewController()
            if let metadataObject = metadataObjects.first {
                guard let readbleObject = metadataObject as? AVMetadataMachineReadableCodeObject else { return }
                
                if let ticketKey = readbleObject.stringValue {
                    stopCameraSession()
                    addLoader()
                    
                    let ticketChecker = TicketChecker()

                    let timeout: TimeInterval = 8
                    let timeoutHandler = DispatchWorkItem {
                        self.removeLoader()
                        ticketChecker.cancelCurrentRequest()
                        let alert = UIAlertController(title: "Error", message: "Request timed out. Please try again.", preferredStyle: .alert)
                        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
                            self.startCameraSession()
                            self.isProcessingQRCode = false
                        }))
                        self.present(alert, animated: true)
                        return
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: timeoutHandler)
                    ticketChecker.checkETicket(ticketNumber: ticketKey.trimmingCharacters(in: .whitespacesAndNewlines)) { result in
                        timeoutHandler.cancel()
                        self.removeLoader()
                        self.isProcessingQRCode = false
                        switch result {
                            case .success((let event, _ )):
                                DispatchQueue.main.async {
                                    let eventInstance = event
                                    let ticketNumber = ticketKey.trimmingCharacters(in: .whitespacesAndNewlines)
                                    self.onScanComplete?(eventInstance, ticketNumber)
                                }
                            case .failure(let error):
                                DispatchQueue.main.async {
                                    resultVC.notFound = true
                                    self.onScanComplete?(nil, nil)
                                }
                        }
                    }
            }
        }
    }
    
    
    func configureContainerView() {
        let squareSize: CGFloat = 250
        let squareFrame = CGRect(
            x: (self.view.frame.width - squareSize) / 2,
            y: (self.view.frame.height - squareSize) / 2,
            width: squareSize,
            height: squareSize
        )
        
        let maskLayer = CAShapeLayer()
        let path = UIBezierPath(rect: self.view.bounds)
        let squarePath = UIBezierPath(rect: squareFrame)
        path.append(squarePath)
        
        maskLayer.path = path.cgPath
        maskLayer.fillRule = .evenOdd
        
        
        let dimmingView = UIView(frame: self.view.bounds)
        dimmingView.backgroundColor = UIColor.black.withAlphaComponent(0.7)
        dimmingView.layer.mask = maskLayer
        
        self.view.addSubview(dimmingView)
        
        // Add corner borders (Top-left, Top-right, Bottom-left, Bottom-right)
        let cornerLength: CGFloat = 20
        
        let frames = [
            CGRect(x: squareFrame.minX, y: squareFrame.minY - 2, width: cornerLength, height: 2),
            CGRect(x: squareFrame.minX - 2, y: squareFrame.minY - 2, width: 2, height: cornerLength),
            CGRect(x: squareFrame.maxX - cornerLength , y: squareFrame.minY - 2, width: cornerLength, height: 2),
            CGRect(x: squareFrame.maxX, y: squareFrame.minY - 2, width: 2, height: cornerLength),
            CGRect(x: squareFrame.minX - 2, y: squareFrame.maxY + 2, width: cornerLength, height: 2),
            CGRect(x: squareFrame.minX - 2, y: squareFrame.maxY - cornerLength + 2, width: 2, height: cornerLength),
            CGRect(x: squareFrame.maxX - cornerLength + 2, y: squareFrame.maxY, width: cornerLength, height: 2),
            CGRect(x: squareFrame.maxX , y: squareFrame.maxY - cornerLength, width: 2, height: cornerLength)
        ]
        
        for frame in frames {
            let view = UIView(frame: frame)
            view.backgroundColor = .white
            self.view.addSubview(view)
        }
        
        self.view.bringSubviewToFront(checkManuallyButton)
    }
    
    lazy var settingsButton: UIButton = {
        let btn = UIButton(type: .system)
        btn.setImage(UIImage(systemName: "line.3.horizontal.decrease.circle"), for: .normal)
        btn.tintColor = .systemGray
        btn.translatesAutoresizingMaskIntoConstraints = false
        btn.addTarget(self, action: #selector(settingsAction), for: .touchUpInside)
        return btn
    }()
    
    private func setupNavigationBarButton() {
        // Create the custom button
        let settingsButton = UIButton(type: .system)
        settingsButton.setImage(UIImage(systemName: "line.3.horizontal.decrease.circle"), for: .normal)
        settingsButton.tintColor = .systemGray
        settingsButton.addTarget(self, action: #selector(settingsAction), for: .touchUpInside)
        
        // Wrap it in a UIBarButtonItem
        let barButtonItem = UIBarButtonItem(customView: settingsButton)
        navigationItem.rightBarButtonItem = barButtonItem
    }
    
    @objc func settingsAction() {
        guard let button = navigationItem.rightBarButtonItem?.customView as? UIButton else { return }
        
        // disable the button to prevent multiple taps
        button.isEnabled = false
        
        // perform your action
        self.onProfileTap? {
            button.isEnabled = true
        }
    }
    
    @objc func showCheckManulVC() {
        stopCameraSession()
        addLoaderAnimation(with: checkManuallyButton, 30)
        onShowCheckManual? {
            self.removeLoaderAnimation(from: self.checkManuallyButton, "Check Manually")
        }
    }
    
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
    private func removeLoaderAnimation(from item: UIButton, _ title: String) {
        DispatchQueue.main.async {
            self.loaderContainer.removeFromSuperview()
            self.animationView.stop()
            self.animationView.removeFromSuperview()
            item.setTitle(title, for: .normal)
            item.isEnabled = true
            item.tintColor = .white
            item.semanticContentAttribute = .forceRightToLeft
        }
    }
    
    func errorAlert(_ message: String) {
        DispatchQueue.main.async {
            if self.isViewLoaded && self.view.window != nil {
                let alert = UIAlertController(
                    title: "Error",
                    message: message,
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "Close", style: .cancel))
                self.present(alert, animated: true)
            }
        }
    }

    func checkCameraPermission() {
        let cameraAuthorizationStatus = AVCaptureDevice.authorizationStatus(for: .video)
        
        switch cameraAuthorizationStatus {
            case .authorized:
                self.captureAndScanQR()
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { granted in
                    if granted {
                        print("Camera access is granted after request.")
                        self.captureAndScanQR()
                        
                    } else {
                        self.presentNoAccessVC()
                    }
                }
            case .denied, .restricted:
                self.presentNoAccessVC()
            @unknown default:
                errorAlert("Unknown case in camera permission check.")
        }
    }
    
    private func presentNoAccessVC() {
        DispatchQueue.main.async {
            if self.isViewLoaded && self.view.window != nil {
                let alert = UIAlertController(
                    title: "Camera Access Denied",
                    message: "Enable camera access in settings to continue.",
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "Go to Settings", style: .default) { _ in
                    guard let settingsURL = URL(string: UIApplication.openSettingsURLString) else { return }
                    UIApplication.shared.open(settingsURL, options: [:], completionHandler: nil)
                })
                
                alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
                self.present(alert, animated: true)
                
                self.updateManualCheckButtonsLayout()
            }
        }
    }

    private func updateManualCheckButtonsLayout() {
        checkManuallyButton.removeFromSuperview()
        goToSettingsButton.removeFromSuperview()
        
        view.addSubview(checkManuallyButton)
        view.addSubview(goToSettingsButton)
        
        NSLayoutConstraint.activate([
            checkManuallyButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            checkManuallyButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            checkManuallyButton.heightAnchor.constraint(equalToConstant: 50),
            checkManuallyButton.bottomAnchor.constraint(equalTo: goToSettingsButton.topAnchor, constant: -15),
            
            goToSettingsButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            goToSettingsButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            goToSettingsButton.heightAnchor.constraint(equalToConstant: 50),
            goToSettingsButton.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -30)
        ])
    }

    @objc func goToSetting() {
        if let appSettingsURL = URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(appSettingsURL, options: [:], completionHandler: nil)
        }
    }

    lazy var goToSettingsButton: UIButton = {
        let btn = UIButton()
        btn.translatesAutoresizingMaskIntoConstraints = false
        btn.layer.cornerRadius = 25
        btn.layer.borderWidth = 1
        btn.layer.borderColor = UIColor.white.cgColor
        btn.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        btn.backgroundColor = .systemBackground.withAlphaComponent(0)
        btn.setTitleColor(.white, for: .normal)
        btn.addTarget(self, action: #selector(goToSetting), for: .touchUpInside)
        btn.setTitle("Camera Permission", for: .normal)
        btn.isUserInteractionEnabled = true
        return btn
    }()
    
    private func startNetworkMonitor(completion: @escaping (Bool) -> Void) {
        monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "NetworkMonitor")
        
        monitor?.pathUpdateHandler = { [weak self] path in
            let isConnected = path.status == .satisfied
            DispatchQueue.main.async {
                self?.isConnectedToInternet = isConnected
                completion(isConnected)
                
                if !isConnected {
                    self?.showNoInternetAlert()
                }
            }
        }
        
        monitor?.start(queue: queue)
    }

    private func showNoInternetAlert() {
        if self.presentedViewController is UIAlertController {
            return
        }
        
        self.isSessionRunning = false
        stopCameraSession()
        
        let alert = UIAlertController(
            title: "No Internet Connection",
            message: "Please check your internet connection and try again.",
            preferredStyle: .alert
        )
        
        let retryAction = UIAlertAction(title: "Retry", style: .default) { _ in
            self.startNetworkMonitor { isConnected in
                if isConnected {
                    self.startCameraSession()
                } else {
                    self.showNoInternetAlert()
                }
            }
        }
        
        alert.addAction(retryAction)
        
        DispatchQueue.main.async {
            self.present(alert, animated: true)
        }
    }
    
    func setup() {
        view.layer.addSublayer(previewLayer)
        view.addSubview(checkManuallyButton)
        view.bringSubviewToFront(settingsButton)
        
        NSLayoutConstraint.activate([
            
            checkManuallyButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            checkManuallyButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            checkManuallyButton.heightAnchor.constraint(equalToConstant: 50),
            checkManuallyButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -15),
        ])
        
        checkCameraPermission()
        configureContainerView()
        startNetworkMonitor {  isConnected in
            if !isConnected {
                self.showNoInternetAlert()
            }
        }
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
    }
}

extension QRScannerViewController: QRScannerDelegate {
    func didDismissModalView() {
        startCameraSession()
        removeLoader()
    }
}
