//
//  LiveFirebaseAuthClient.swift
//  ASimpleAuthKit
//
//  Created by Charles Feinn on 6/8/25.
//

import Foundation
import FirebaseAuth

@MainActor
internal class LiveFirebaseAuthClient: FirebaseAuthClientProtocol {
    var currentUser: FirebaseAuth.User? {
        Auth.auth().currentUser
    }

    func addStateDidChangeListener(_ listener: @escaping (FirebaseAuth.Auth, FirebaseAuth.User?) -> Void) -> AuthStateDidChangeListenerHandle {
        Auth.auth().addStateDidChangeListener(listener)
    }

    func removeStateDidChangeListener(_ handle: AuthStateDidChangeListenerHandle) {
        Auth.auth().removeStateDidChangeListener(handle)
    }

    func signOut() throws {
        try Auth.auth().signOut()
    }

    func signIn(withEmail email: String, password: String) async throws -> AuthDataResult {
        try await Auth.auth().signIn(withEmail: email, password: password)
    }

    func createUser(withEmail email: String, password: String) async throws -> AuthDataResult {
        try await Auth.auth().createUser(withEmail: email, password: password)
    }

    func sendPasswordReset(withEmail email: String) async throws {
        try await Auth.auth().sendPasswordReset(withEmail: email)
    }

    func signIn(with credential: AuthCredential) async throws -> AuthDataResult {
        try await Auth.auth().signIn(with: credential)
    }

    func link(user: FirebaseAuth.User, with credential: AuthCredential) async throws -> AuthDataResult {
        try await user.link(with: credential)
    }
    
    func sendEmailVerification(for user: FirebaseAuth.User) async throws {
        try await user.sendEmailVerification()
    }
}
