// Sources/AuthKit/Helpers/RootViewControllerFinder.swift
import UIKit

public extension UIViewController {
    @MainActor
    func topMostViewController() -> UIViewController {
        if let p = self.presentedViewController {
            return p.topMostViewController()
        }
        if let n = self as? UINavigationController {
            if let v = n.visibleViewController, v != n {
                return v.topMostViewController()
            } else {
                return n
            }
        }
        if let t = self as? UITabBarController {
            if let s = t.selectedViewController, s != t {
                return s.topMostViewController()
            } else {
                return t
            }
        }
        return self
    }
}

@MainActor
public func findKeyWindowRootViewController() -> UIViewController? {
    return UIApplication.shared.connectedScenes
        .filter { $0.activationState == .foregroundActive }
        .first(where: { $0 is UIWindowScene })
        .flatMap({ $0 as? UIWindowScene })?.windows
        .first(where: \.isKeyWindow)?
        .rootViewController
}

@MainActor
public func findTopMostViewController() -> UIViewController? {
    return findKeyWindowRootViewController()?.topMostViewController()
}
