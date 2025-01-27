//
//  SuccessViewController.swift
//  Ticket Checker
//
//  Created by Zaytech Mac on 19/10/2024.
//

import UIKit

class ResultViewController: UIViewController, UIGestureRecognizerDelegate {

    public var onBackToScan: (() -> Void)?
    var eventInstance: Event?
    var ticketNumber: String?
    var notFound: Bool = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.backgroundColor = UIColor(named: "BgColor")
        setupNavigationBar()
        if notFound  {
            configError()
        } else {
            configThereIsResult()
        }
        
    }
    
    private func setupNavigationBar() {
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            image: nil,
            style: .plain,
            target: self,
            action: nil
        )
    }
    
    let statusView: EventStatusView = {
        let sv = EventStatusView()
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()
    
    lazy var ScanAgainButton: CustomButton = {
        let btn = CustomButton()
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(goBackToScan))
        tapGesture.cancelsTouchesInView = false
        tapGesture.delegate = self
        btn.addGestureRecognizer(tapGesture)
        btn.translatesAutoresizingMaskIntoConstraints = false
        return btn
    }()
    @objc func goBackToScan() {
        onBackToScan?()
    }
    lazy var errorCircle: UIView = {
        let eventView = EventView()
        eventView.backgroundColor = UIColor(named: "InfoBgColor") ?? .cyan
        eventView.layer.cornerRadius = 209 / 2
        eventView.layer.masksToBounds = true
        eventView.translatesAutoresizingMaskIntoConstraints = false
        return eventView
    }()
    
    lazy var errorImage: UIImageView = {
        let imgView = UIImageView()
        imgView.image = UIImage(named: "NotFoundTicketIcon")
        imgView.contentMode = .scaleAspectFit
        imgView.translatesAutoresizingMaskIntoConstraints = false
        imgView.clipsToBounds = true
        return imgView
    }()
    
    lazy var errorTitle: TitleLabel = {
        let lbl = TitleLabel()
        lbl.config("Ticket Not Found")
        lbl.translatesAutoresizingMaskIntoConstraints = false
        return lbl
    }()
    lazy var errorDescription: UILabel = {
        let lbl = UILabel()
        lbl.text = "Unfortunately, we couldn't find any tickets matching this QR code. Please double-check the code or try again later."
        lbl.font = UIFont.systemFont(ofSize: 12, weight: .light)
        lbl.translatesAutoresizingMaskIntoConstraints = false
        lbl.numberOfLines = 0
        lbl.textAlignment = .center
        lbl.lineBreakMode = .byWordWrapping
        lbl.textColor = .gray
        return lbl
    }()
    
    func configError() {
        ScanAgainButton.config("Try Again")
        self.view.backgroundColor = UIColor(named: "BgColor")
        
        errorCircle.addSubview(errorImage)
        
        self.view.addSubview(errorTitle)
        self.view.addSubview(errorDescription)
        self.view.addSubview(errorCircle)
        self.view.addSubview(ScanAgainButton)
        
        NSLayoutConstraint.activate([
            errorCircle.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
            errorCircle.centerYAnchor.constraint(equalTo: self.view.centerYAnchor, constant: -40),
            errorCircle.heightAnchor.constraint(equalToConstant: 209),
            errorCircle.widthAnchor.constraint(equalToConstant: 209),
            
            errorImage.centerXAnchor.constraint(equalTo: errorCircle.centerXAnchor),
            errorImage.centerYAnchor.constraint(equalTo: errorCircle.centerYAnchor, constant: 40),
            
            errorTitle.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
            errorTitle.topAnchor.constraint(equalTo: errorCircle.bottomAnchor, constant: 22),
            
            errorDescription.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
            errorDescription.widthAnchor.constraint(equalTo: self.view.widthAnchor, multiplier: 0.9),
            errorDescription.topAnchor.constraint(equalTo: errorTitle.bottomAnchor, constant: 10),
            
            ScanAgainButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            ScanAgainButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            ScanAgainButton.heightAnchor.constraint(equalToConstant: 50),
            ScanAgainButton.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -30),
        ])
    }
    
    

    
    lazy var eventView: EventView = {
        let eventView = EventView()
        eventView.translatesAutoresizingMaskIntoConstraints = false
        return eventView
    }()
    
    let eventDataDetailsView: EventDataDetailsView = {
        let eventDataView = EventDataDetailsView()
        eventDataView.translatesAutoresizingMaskIntoConstraints = false
        return eventDataView
    }()
    
    lazy var eventTitleLabel: TitleLabel = {
        let eventTitleLabel = TitleLabel()
        eventTitleLabel.translatesAutoresizingMaskIntoConstraints = false
        return eventTitleLabel
    }()
    func configThereIsResult() {
        if let event = eventInstance {
            let is_checked = event.nb_of_checks ?? 2 > 1 ? true : false
            statusView.config(checked: is_checked)
        }
        ScanAgainButton.config("SCAN ANOTHER")
        
        
        self.view.addSubview(ScanAgainButton)
        self.view.addSubview(statusView)
        eventView.addSubview(eventTitleLabel)
        eventView.addSubview(eventDataDetailsView)
        self.view.addSubview(eventView)
        
        if let event = self.eventInstance, let ticket = self.ticketNumber {
            
            eventTitleLabel.config(event.event_title ?? "")
            
            if let owner_name = event.owner_name {
                let eventRowOne = EventDetailRowView()
                eventRowOne.config(key: "Name:", value: owner_name, fontWeight: .bold)
                eventDataDetailsView.addEventRow(eventRowOne)
            }
            
            
            let eventRowTwo = EventDetailRowView()
            eventRowTwo.config(key: "Order Number:", value: ticket)
            eventDataDetailsView.addEventRow(eventRowTwo)
            
            if let e_date = event.formatDate() {
                let eventRowThree = EventDetailRowView()
                eventRowThree.config(key: "Date/time:", value: e_date)
                eventDataDetailsView.addEventRow(eventRowThree)
            }
            
            let eventRowFour = EventDetailRowView()
            eventRowFour.config(key: "Number of Person(s):", value: "\(event.guests) Person(s)", fontWeight: .bold)
            eventDataDetailsView.addEventRow(eventRowFour)
            
            let eventRowFive = EventDetailRowView()
            eventRowFive.config(key: "Price", value: "\(event.price)")
            eventDataDetailsView.addEventRow(eventRowFive, false)
        } else {
            eventTitleLabel.config("Title Not available")
        }
        
        NSLayoutConstraint.activate([
            statusView.topAnchor.constraint(equalTo: self.view.topAnchor),
            statusView.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            statusView.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
            statusView.heightAnchor.constraint(equalTo: self.view.heightAnchor, multiplier: 0.3),
            
            ScanAgainButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 15),
            ScanAgainButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -15),
            ScanAgainButton.heightAnchor.constraint(equalToConstant: 50),
            ScanAgainButton.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -30),
            
            eventTitleLabel.topAnchor.constraint(equalTo: eventView.topAnchor, constant: 30),
            eventTitleLabel.leadingAnchor.constraint(equalTo: eventView.leadingAnchor, constant: 45),
            
            eventDataDetailsView.topAnchor.constraint(equalTo: eventTitleLabel.bottomAnchor, constant: 25),
            eventDataDetailsView.leadingAnchor.constraint(equalTo: eventView.leadingAnchor, constant: 45),
            eventDataDetailsView.trailingAnchor.constraint(equalTo: eventView.trailingAnchor, constant: -45),
            
            eventView.topAnchor.constraint(equalTo: self.statusView.bottomAnchor),
            eventView.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            eventView.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
        ])
    }

}
