import Foundation

@MainActor
internal protocol SecureStorageProtocol {
    /// Saves the last successfully signed-in non-anonymous user ID securely.
    /// - Parameter userID: The user ID string to save.
    /// - Throws: An `AuthError.keychainError` if saving fails.
    func saveLastUserID(_ userID: String) async throws

    /// Retrieves the last saved user ID.
    /// - Returns: The user ID string if found, otherwise `nil`.
    func getLastUserID() async -> String?

    /// Clears the last saved user ID.
    /// - Throws: An `AuthError.keychainError` if clearing fails (excluding item not found).
    func clearLastUserID() async throws
}
