import Foundation
import UIKit

class TicketChecker {
    var environemnt = ""
    private var currentTask: URLSessionDataTask?
    func checkETicket(ticketNumber: String, completion: @escaping (Result<(Event, String), Error>) -> Void) {
        let endpoint1 = "https://api-v2-sandbox.smartonlineorders.com/v2/public/check-eticket/\(ticketNumber)"
        let endpoint2 = "https://api-v2.smartonlineorders.com/v2/public/check-eticket/\(ticketNumber)"
        
        self.fetchTicket(from: endpoint1) { [weak self] result in
            switch result {
            case .success(let event):
                completion(.success(event))
            case .failure:
                self?.fetchTicket(from: endpoint2) { result in
                    switch result {
                    case .success(let event):
                        completion(.success(event))
                    case .failure(let error):
                        completion(.failure(error))
                    }
                }
            }
        }
    }
    
    func cancelCurrentRequest() {
        if let task = currentTask {
            task.cancel()
            print("Cancelled task: \(task)")
        }
        currentTask = nil
    }
    
    func fetchTicket(from urlString: String, completion: @escaping (Result<(Event, String), Error>) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(.failure(NSError(domain: "Invalid URL", code: -1, userInfo: nil)))
            return
        }
        
        currentTask = URLSession.shared.dataTask(with: url) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(NSError(domain: "NoDataError", code: 0, userInfo: nil)))
                return
            }

            do {
                let event = try JSONDecoder().decode(Event.self, from: data)
                completion(.success((event, urlString)))
            } catch {
                completion(.failure(error))
            }
        }
        
        currentTask?.resume()
    }
    
}
