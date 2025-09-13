//
//  LiveFirebaseAuthClient.swift
//  ASimpleAuthKit
//
//  Created by Charles Feinn on 6/8/25.
//

import Foundation
import FirebaseAuth
import FirebaseCore

@MainActor
internal class LiveFirebaseAuthClient: FirebaseAuthClientProtocol {

    internal let auth: Auth
    
    init(app: FirebaseApp? = nil) {
        if let app = app {
            // If an app is provided, get the Auth instance for THAT app
            self.auth = Auth.auth(app: app)
            print("LiveFirebaseAuthClient: Initialized with custom FirebaseApp.")
        } else {
            // Otherwise, fall back to the default global singleton
            self.auth = Auth.auth()
            print("LiveFirebaseAuthClient: Initialized with default FirebaseApp.")
        }
    }
    
    var currentUser: FirebaseAuth.User? {
        self.auth.currentUser
    }

    func addStateDidChangeListener(_ listener: @escaping (FirebaseAuth.Auth, FirebaseAuth.User?) -> Void) -> AuthStateDidChangeListenerHandle {
        self.auth.addStateDidChangeListener(listener)
    }

    func removeStateDidChangeListener(_ handle: AuthStateDidChangeListenerHandle) {
        self.auth.removeStateDidChangeListener(handle)
    }

    func signOut() throws {
        try self.auth.signOut()
    }

    func signIn(withEmail email: String, password: String) async throws -> AuthDataResult {
        try await self.auth.signIn(withEmail: email, password: password)
    }

    func createUser(withEmail email: String, password: String) async throws -> AuthDataResult {
        try await self.auth.createUser(withEmail: email, password: password)
    }

    func sendPasswordReset(withEmail email: String) async throws {
        try await self.auth.sendPasswordReset(withEmail: email)
    }

    func signIn(with credential: AuthCredential) async throws -> AuthDataResult {
        try await self.auth.signIn(with: credential)
    }

    func link(user: FirebaseAuth.User, with credential: AuthCredential) async throws -> AuthDataResult {
        try await user.link(with: credential)
    }

    func sendEmailVerification(for user: FirebaseAuth.User) async throws {
        try await user.sendEmailVerification()
    }

    func getIDToken(for user: FirebaseAuth.User, forcingRefresh: Bool = false) async throws -> String {
        try await user.getIDTokenResult(forcingRefresh: forcingRefresh).token
    }
}
