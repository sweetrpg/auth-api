//
// Auth0AccessTokenPayload.swift
//

import JWT
import Vapor

/// Claims verified from an Auth0-issued access token. Roles and per-service access are not
/// Auth0 claims - they're owned by users-api's own store (see design.md) and looked up
/// separately by `sub` once the token itself is confirmed authentic.
struct Auth0AccessTokenPayload: JWTPayload {
  enum CodingKeys: String, CodingKey {
    case subject = "sub"
    case expiration = "exp"
    case issuer = "iss"
    case audience = "aud"
  }

  let subject: SubjectClaim
  let expiration: ExpirationClaim
  let issuer: IssuerClaim
  let audience: AudienceClaim

  func verify(using signer: JWTSigner) throws {
    try self.expiration.verifyNotExpired()
  }

  /// Claim checks that need the expected issuer/audience, which JWTPayload.verify(using:)
  /// doesn't have access to - called explicitly by the verifier after signature verification.
  func verifyIssuerAndAudience(config: Auth0Config) throws {
    guard self.issuer.value == config.issuer else {
      throw JWTError.claimVerificationFailure(
        name: "iss", reason: "expected \(config.issuer), got \(self.issuer.value)")
    }
    try self.audience.verifyIntendedAudience(includes: config.audience)
  }
}
