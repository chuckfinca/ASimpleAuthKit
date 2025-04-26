import Foundation

@MainActor
internal protocol SecureStorageProtocol {
    // NOTE: These could be made async throws for better practice
    func saveLastUserID(_ userID: String) throws
    func getLastUserID() -> String?
    func clearLastUserID() throws
}
