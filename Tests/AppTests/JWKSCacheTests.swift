//
// JWKSCacheTests.swift
//

import JWT
import XCTVapor
import XCTest

@testable import App

/// Test fixture RSA key (from JWTKit's own test suite - a public, non-secret test key, not
/// used anywhere in production).
private let testModulus =
  "mSfWGBcXRBPgnwnL_ymDCkBaL6vcMcLpBEomzf-wZPajcQFiq4n4MHScyo85Te6GU-YuErVvHKK0D72JhMNWAQXbiF5Hh7swSYX9QsycWwHBgOBNfp51Fm_HTU7ikDBEdSonrmSep8wNqi_PX2_jVBsoxYNeiCQyDLFLHOAAcbIE4Y6lpJy76GpdHJscMO2RsUznjv5VPOQVa_BlQRIIZ0YoSsq9EEZna9O370wZy8jnOthQIXoegQ7sItS1JMKk4X5DdoRenIfbfWLy88XxKOPlIHA5ekT8TyzeI2Uqkg3YMETTDPrSROVO1Qdl2W1uMdfIZ94DgKpZN2VW-w0fLw"
private let testExponent = "AQAB"
private let testPrivateExponent =
  "awDmF9aqLqokmXjiydda8mKboArWwP2Ih7K3Ad3Og_u9nUp2gZrXiCMxGGSQiN5Jg3yiW_ffNYaHfyfRWKyQ_g31n4UfPLmPtw6iL3V9GChV5ZDRE9HpxE88U8r1h__xFFrrdnBeWKW8NldI70jg7vY6uiRae4uuXCfSbs4iAUxmRVKWCnV7JE6sObQKUV_EJkBcyND5Y97xsmWD0nPmXCnloQ84gF-eTErJoZBvQhJ4BhmBeUlREHmDKssaxVOCK4l335DKHD1vbuPk9e49M71BK7r2y4Atqk3TEetnwzMs3u-L9RqHaGIBw5u324uGweY7QeD7HFdAUtpjOq_MQQ"

private let testConfig = Auth0Config(domain: "test.auth0.dev", audience: "test-audience")

private func jwksJSON(kid: String) -> String {
  """
  {
      "keys": [
          {
              "kty": "RSA",
              "use": "sig",
              "kid": "\(kid)",
              "n": "\(testModulus)",
              "e": "\(testExponent)"
          }
      ]
  }
  """
}

private func signedToken(
  kid: String, subject: String = "auth0|abc123",
  expiration: Date = Date().addingTimeInterval(3600),
  issuer: String = testConfig.issuer, audience: String = testConfig.audience
) throws -> String {
  let key = RSAKey(
    modulus: testModulus, exponent: testExponent, privateExponent: testPrivateExponent)!
  let signer = JWTSigner.rs256(key: key)
  let payload = Auth0AccessTokenPayload(
    subject: SubjectClaim(value: subject),
    expiration: ExpirationClaim(value: expiration),
    issuer: IssuerClaim(value: issuer),
    audience: AudienceClaim(value: [audience])
  )
  return try signer.sign(payload, kid: JWKIdentifier(string: kid))
}

/// Returns a fixed JWKS response for every request, tracking how many times it was called.
private final class StubClient: Client, @unchecked Sendable {
  let eventLoop: EventLoop
  var callCount = 0
  var respondWithKID: String

  init(eventLoop: EventLoop, respondWithKID: String) {
    self.eventLoop = eventLoop
    self.respondWithKID = respondWithKID
  }

  func delegating(to eventLoop: EventLoop) -> Client {
    self
  }

  func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
    self.callCount += 1
    var buffer = ByteBufferAllocator().buffer(capacity: 0)
    buffer.writeString(jwksJSON(kid: self.respondWithKID))
    return self.eventLoop.makeSucceededFuture(ClientResponse(status: .ok, body: buffer))
  }
}

final class JWKSCacheTests: XCTestCase {
  func testVerifySucceedsOnFirstFetch() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let token = try signedToken(kid: "key-1")

    let payload = try JWKSCache().verify(token, client: client, config: testConfig).wait()

    XCTAssertEqual(payload.subject.value, "auth0|abc123")
    XCTAssertEqual(client.callCount, 1)
  }

  func testSecondVerifyUsesCacheWithoutRefetching() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let cache = JWKSCache()
    let token = try signedToken(kid: "key-1")

    _ = try cache.verify(token, client: client, config: testConfig).wait()
    _ = try cache.verify(token, client: client, config: testConfig).wait()

    XCTAssertEqual(client.callCount, 1)
  }

  func testUnknownKIDTriggersExactlyOneRefetch() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let cache = JWKSCache()

    // Prime the cache with a JWKS that doesn't contain "key-2".
    _ = try cache.verify(try signedToken(kid: "key-1"), client: client, config: testConfig).wait()
    XCTAssertEqual(client.callCount, 1)

    // Simulate Auth0 rotating to a new key: the stub now serves "key-2".
    client.respondWithKID = "key-2"
    let payload = try cache.verify(
      try signedToken(kid: "key-2"), client: client, config: testConfig
    ).wait()

    XCTAssertEqual(payload.subject.value, "auth0|abc123")
    XCTAssertEqual(client.callCount, 2)
  }

  func testUnknownKIDStillMissingAfterRefetchFails() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let cache = JWKSCache()

    XCTAssertThrowsError(
      try cache.verify(
        try signedToken(kid: "key-does-not-exist"), client: client, config: testConfig
      )
      .wait()
    ) { error in
      guard case JWTError.unknownKID = error else {
        return XCTFail("expected JWTError.unknownKID, got \(error)")
      }
    }
    XCTAssertEqual(client.callCount, 1)
  }

  func testExpiredTokenIsRejected() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let token = try signedToken(kid: "key-1", expiration: Date().addingTimeInterval(-3600))

    XCTAssertThrowsError(try JWKSCache().verify(token, client: client, config: testConfig).wait())
  }

  func testWrongAudienceIsRejected() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let token = try signedToken(kid: "key-1", audience: "someone-elses-audience")

    XCTAssertThrowsError(try JWKSCache().verify(token, client: client, config: testConfig).wait())
  }

  func testWrongIssuerIsRejected() throws {
    let app = Application(.testing)
    defer { app.shutdown() }

    let client = StubClient(eventLoop: app.eventLoopGroup.next(), respondWithKID: "key-1")
    let token = try signedToken(kid: "key-1", issuer: "https://not-our-tenant.auth0.com/")

    XCTAssertThrowsError(try JWKSCache().verify(token, client: client, config: testConfig).wait())
  }
}
