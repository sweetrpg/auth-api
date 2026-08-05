//
// Auth0Config.swift
//

import JWT
import Vapor

struct Auth0Config {
  let domain: String
  let audience: String

  var issuer: String {
    "https://\(self.domain)/"
  }

  var jwksURL: URI {
    URI(string: "https://\(self.domain)/.well-known/jwks.json")
  }

  static func fromEnvironment() -> Auth0Config {
    guard let domain = Environment.get("AUTH0_DOMAIN") else {
      fatalError("AUTH0_DOMAIN is not set in environment")
    }
    guard let audience = Environment.get("AUTH0_AUDIENCE") else {
      fatalError("AUTH0_AUDIENCE is not set in environment")
    }
    return Auth0Config(domain: domain, audience: audience)
  }
}

extension Application {
  private struct Auth0ConfigKey: StorageKey {
    typealias Value = Auth0Config
  }

  var auth0Config: Auth0Config {
    get {
      guard let config = self.storage[Auth0ConfigKey.self] else {
        let config = Auth0Config.fromEnvironment()
        self.storage[Auth0ConfigKey.self] = config
        return config
      }
      return config
    }
    set {
      self.storage[Auth0ConfigKey.self] = newValue
    }
  }
}

extension Request {
  var auth0Config: Auth0Config {
    self.application.auth0Config
  }

  /// Verifies a bearer access token against Auth0's JWKS, refetching once on an unknown `kid`.
  func verifyAuth0Token(_ token: String) -> EventLoopFuture<Auth0AccessTokenPayload> {
    self.application.jwksCache.verify(token, client: self.client, config: self.auth0Config)
  }
}
