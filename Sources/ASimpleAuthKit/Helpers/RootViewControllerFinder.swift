// Sources/AuthKit/Helpers/RootViewControllerFinder.swift
import UIKit

// Helper extension to find the most appropriate view controller for presenting modals.
public extension UIViewController {
    /// Finds the topmost view controller in the hierarchy.
    /// Useful for presenting modals from anywhere in the app.
    func topMostViewController() -> UIViewController {
        // If the view controller is presenting something, find the top view controller from the presented controller.
        if let presentedViewController = self.presentedViewController {
            return presentedViewController.topMostViewController()
        }

        // If the view controller is a UINavigationController, find the top view controller from its visible controller.
        if let navigationController = self as? UINavigationController {
            // Ensure visibleViewController exists and isn't the navigation controller itself before recursing
            if let visibleViewController = navigationController.visibleViewController, visibleViewController != navigationController {
                 return visibleViewController.topMostViewController()
            } else {
                 // Handle edge case: empty navigation controller or only nav controller itself visible
                 return navigationController
            }
        }

        // If the view controller is a UITabBarController, find the top view controller from its selected controller.
        if let tabBarController = self as? UITabBarController {
             // Ensure selectedViewController exists and isn't the tab bar controller itself before recursing
            if let selectedViewController = tabBarController.selectedViewController, selectedViewController != tabBarController {
                return selectedViewController.topMostViewController()
            } else {
                 // Handle edge case: no selection or only tab bar controller itself visible
                 return tabBarController
            }
        }

        // Otherwise, the view controller itself is the top one in its branch.
        return self
    }
}

// Helper function to get the root view controller from the key window
public func findKeyWindowRootViewController() -> UIViewController? {
    return UIApplication.shared.connectedScenes
        // Keep only active scenes, onscreen and visible to the user
        .filter { $0.activationState == .foregroundActive }
        // Keep only the first `UIWindowScene`
        .first(where: { $0 is UIWindowScene })
        // Get its associated windows
        .flatMap({ $0 as? UIWindowScene })?.windows
        // Keep only the key window
        .first(where: \.isKeyWindow)?
        .rootViewController
}

// Combined helper to get the absolute top-most VC in the app
public func findTopMostViewController() -> UIViewController? {
    return findKeyWindowRootViewController()?.topMostViewController()
}