//
// JWKSCache.swift
//

import Foundation
import JWT
import NIOConcurrencyHelpers
import Vapor

/// Fetches and caches Auth0's JWKS, keyed by `kid`. A verification attempt against a `kid`
/// not in the cache triggers exactly one refetch (Auth0 rotates signing keys occasionally;
/// a cache built before a rotation shouldn't reject a token signed with the new key) before
/// failing as `invalid_token`.
///
/// Membership is checked against the raw JWKS's `kid` list rather than relying on
/// `JWTSigners.verify` to throw `JWTError.unknownKID` - `JWTSigners` treats the first key it
/// loads as a fallback "default" signer, so an unrecognized `kid` silently falls back to that
/// default (and fails signature verification, not `unknownKID`) once any key has ever been
/// cached.
final class JWKSCache: @unchecked Sendable {
  private let lock: NIOLock
  private var jwks: JWKS?
  private var signers: JWTSigners?

  init() {
    self.lock = NIOLock()
  }

  private func cached() -> (jwks: JWKS, signers: JWTSigners)? {
    self.lock.withLock {
      guard let jwks = self.jwks, let signers = self.signers else { return nil }
      return (jwks, signers)
    }
  }

  private func store(_ jwks: JWKS, _ signers: JWTSigners) {
    self.lock.withLockVoid {
      self.jwks = jwks
      self.signers = signers
    }
  }

  private func fetch(client: Client, config: Auth0Config) -> EventLoopFuture<
    (jwks: JWKS, signers: JWTSigners)
  > {
    client.get(config.jwksURL).flatMapThrowing { response in
      guard response.status == .ok, var body = response.body else {
        throw Abort(.badGateway, reason: "failed to fetch Auth0 JWKS")
      }
      guard let json = body.readString(length: body.readableBytes) else {
        throw Abort(.badGateway, reason: "empty Auth0 JWKS response")
      }
      let jwks = try JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
      let signers = JWTSigners()
      try signers.use(jwks: jwks)
      self.store(jwks, signers)
      return (jwks, signers)
    }
  }

  /// Verifies `token`, refetching the JWKS once if its `kid` isn't in the current cache.
  func verify(_ token: String, client: Client, config: Auth0Config) -> EventLoopFuture<
    Auth0AccessTokenPayload
  > {
    guard let kid = Self.extractKID(from: token) else {
      return client.eventLoop.makeFailedFuture(JWTError.missingKIDHeader)
    }

    let cachedFuture: EventLoopFuture<(jwks: JWKS, signers: JWTSigners)>
    if let cached = self.cached(), cached.jwks.find(identifier: kid)?.isEmpty == false {
      cachedFuture = client.eventLoop.makeSucceededFuture(cached)
    } else {
      cachedFuture = self.fetch(client: client, config: config)
    }

    return cachedFuture.flatMapThrowing { jwks, signers in
      guard jwks.find(identifier: kid)?.isEmpty == false else {
        throw JWTError.unknownKID(JWKIdentifier(string: kid))
      }
      let payload = try signers.verify(token, as: Auth0AccessTokenPayload.self)
      try payload.verifyIssuerAndAudience(config: config)
      return payload
    }
  }

  private static func extractKID(from token: String) -> String? {
    let parts = token.split(separator: ".")
    guard parts.count == 3,
      let headerData = Data(base64URLEncoded: String(parts[0])),
      let header = try? JSONDecoder().decode(JWTHeaderKID.self, from: headerData)
    else {
      return nil
    }
    return header.kid
  }
}

private struct JWTHeaderKID: Decodable {
  let kid: String?
}

extension Data {
  fileprivate init?(base64URLEncoded string: String) {
    var base64 = string.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 {
      base64 += "="
    }
    self.init(base64Encoded: base64)
  }
}

extension Application {
  private struct JWKSCacheKey: StorageKey {
    typealias Value = JWKSCache
  }

  var jwksCache: JWKSCache {
    if let existing = self.storage[JWKSCacheKey.self] {
      return existing
    }
    let new = JWKSCache()
    self.storage[JWKSCacheKey.self] = new
    return new
  }
}
