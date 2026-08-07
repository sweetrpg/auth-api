//
// InternalServiceAuthTests.swift
//

import XCTVapor

@testable import App

/// Doesn't call `configure(_:)` (which requires a reachable MongoDB) - these
/// only exercise the internal-service-token comparison itself, via the storage-backed setter
/// rather than the `INTERNAL_SERVICE_TOKEN` environment variable.
final class InternalServiceAuthTests: XCTestCase {
  func testMatchingTokenIsValid() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    app.internalServiceToken = "expected-secret"

    let req = Request(
      application: app, method: .GET, url: "/", on: app.eventLoopGroup.next())
    req.headers.replaceOrAdd(name: InternalServiceAuth.headerName, value: "expected-secret")

    XCTAssertTrue(req.hasValidInternalServiceToken)
  }

  func testMismatchedTokenIsInvalid() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    app.internalServiceToken = "expected-secret"

    let req = Request(
      application: app, method: .GET, url: "/", on: app.eventLoopGroup.next())
    req.headers.replaceOrAdd(name: InternalServiceAuth.headerName, value: "wrong-secret")

    XCTAssertFalse(req.hasValidInternalServiceToken)
  }

  func testMissingHeaderIsInvalid() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    app.internalServiceToken = "expected-secret"

    let req = Request(application: app, method: .GET, url: "/", on: app.eventLoopGroup.next())

    XCTAssertFalse(req.hasValidInternalServiceToken)
  }

  func testDisabledWhenTokenUnset() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    // app.internalServiceToken left unset (nil).

    let req = Request(
      application: app, method: .GET, url: "/", on: app.eventLoopGroup.next())
    req.headers.replaceOrAdd(name: InternalServiceAuth.headerName, value: "anything")

    XCTAssertFalse(req.hasValidInternalServiceToken)
  }
}
