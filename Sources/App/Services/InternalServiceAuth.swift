//
// InternalServiceAuth.swift
//

import Vapor

/// A shared secret trusted server-to-server callers (currently only `admin-web`) present
/// instead of an end-user Auth0 bearer token, for the `/api/admin/*` routes in
/// `RolesController`. Exists because `admin-web` deliberately never holds an Auth0 access token
/// of its own - it reads the shared session `auth-web` established (see platform's
/// `add-user-api-authn-authz` change) and trusts that session's already-verified `admin` role
/// rather than re-authenticating with Auth0. `RolesController` still needs *some* caller
/// authentication, so this shared secret is the trust boundary in place of a per-request Auth0
/// token: whoever holds `INTERNAL_SERVICE_TOKEN` is trusted to have already verified the acting
/// user is an admin, which is exactly what `admin-web`'s `AuthRequiredMiddleware` does before
/// ever reaching this client.
enum InternalServiceAuth {
  static let headerName = "X-Internal-Service-Token"
}

extension Application {
  private struct InternalServiceTokenKey: StorageKey {
    typealias Value = String
  }

  /// `nil` when `INTERNAL_SERVICE_TOKEN` is unset - the internal-auth path is then permanently
  /// disabled (every request falls through to the Auth0 bearer-token check), not silently
  /// trusting an empty token.
  var internalServiceToken: String? {
    get {
      if let cached = storage[InternalServiceTokenKey.self] {
        return cached
      }
      guard let token = Environment.get("INTERNAL_SERVICE_TOKEN"), !token.isEmpty else {
        return nil
      }
      storage[InternalServiceTokenKey.self] = token
      return token
    }
    set { storage[InternalServiceTokenKey.self] = newValue }
  }
}

extension Request {
  /// Whether this request presented the correct internal service token. Always `false` when
  /// `INTERNAL_SERVICE_TOKEN` is unset.
  var hasValidInternalServiceToken: Bool {
    guard let expected = application.internalServiceToken,
      let presented = headers.first(name: InternalServiceAuth.headerName)
    else { return false }
    return constantTimeEquals(expected, presented)
  }
}

/// Avoids a short-circuiting `==` on secret comparison, which leaks timing information about
/// how many leading characters matched.
private func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
  let lhsBytes = Array(lhs.utf8)
  let rhsBytes = Array(rhs.utf8)
  guard lhsBytes.count == rhsBytes.count else { return false }
  var diff: UInt8 = 0
  for (l, r) in zip(lhsBytes, rhsBytes) {
    diff |= l ^ r
  }
  return diff == 0
}
