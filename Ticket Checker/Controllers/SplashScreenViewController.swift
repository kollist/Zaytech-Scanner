//
//  SpalshScreenViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 23/10/2024.
//

import UIKit
import Lottie

class SplashScreenViewController: UIViewController {
    
    var onSpalshEnding: (() -> Void)?
    private lazy var animationView: LottieAnimationView = {
        let animationView = LottieAnimationView()
        return animationView
    }()
    let gradientLay = gradientLayer()
    override func viewDidLoad() {
        super.viewDidLoad()
        navigationController?.setNavigationBarHidden(true, animated: true)
        animationView = .init(name: "splash")
        animationView.translatesAutoresizingMaskIntoConstraints = false
        animationView.frame = view.bounds
        animationView.contentMode = .scaleAspectFit
        animationView.loopMode = .loop
        animationView.animationSpeed = 1
        view.addSubview(animationView)
        animationView.play()
        NSLayoutConstraint.activate([
            animationView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            animationView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            animationView.widthAnchor.constraint(equalToConstant: 100),
            animationView.heightAnchor.constraint(equalToConstant: 200),
        ])
        
        gradientLay.frame = view.bounds
        view.layer.insertSublayer(gradientLay, at: 0)

        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.onSpalshEnding?()
        }
    }
}
