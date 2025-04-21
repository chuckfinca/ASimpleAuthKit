import Foundation

internal protocol SecureStorageProtocol {
    func saveLastUserID(_ userID: String) throws
    func getLastUserID() -> String?
    func clearLastUserID() throws
}