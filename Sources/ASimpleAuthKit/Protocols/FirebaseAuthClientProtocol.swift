//
//  FirebaseAuthClientProtocol.swift
//  ASimpleAuthKit
//
//  Created by Charles Feinn on 6/8/25.
//

import Foundation
import FirebaseAuth

@MainActor
internal protocol FirebaseAuthClientProtocol {
    var currentUser: FirebaseAuth.User? { get }

    func addStateDidChangeListener(_ listener: @escaping (FirebaseAuth.Auth, FirebaseAuth.User?) -> Void) -> AuthStateDidChangeListenerHandle
    func removeStateDidChangeListener(_ handle: AuthStateDidChangeListenerHandle)

    func signOut() throws

    // Mirror methods from FirebaseAuthenticator's usage
    func signIn(withEmail email: String, password: String) async throws -> AuthDataResult
    func createUser(withEmail email: String, password: String) async throws -> AuthDataResult
    func sendPasswordReset(withEmail email: String) async throws
    func signIn(with credential: AuthCredential) async throws -> AuthDataResult
    
    // Note: These methods are on the User object, but we can abstract them here
    func link(user: FirebaseAuth.User, with credential: AuthCredential) async throws -> AuthDataResult
    func sendEmailVerification(for user: FirebaseAuth.User) async throws
}
