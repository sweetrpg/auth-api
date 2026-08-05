//
// RolesControllerAuditTests.swift
//

import XCTVapor

@testable import App

/// Doesn't call `configure(_:)` (which requires a reachable MongoDB via `DATABASE_URL`) - only
/// exercises the request-validation path that runs *before* any database access, same
/// constraint as `InternalServiceAuthTests`. `RolesController.verifyAdminRole` requires
/// `X-Acting-User-Sub` for internal-service-token callers before it ever reaches a query or an
/// audit-log write - this confirms that gate rejects the request early, not that a real audit
/// log entry gets written (which needs the full app + a real database; see
/// `RolesController.performAudited`'s doc comment for the fail-closed contract that path
/// implements).
final class RolesControllerAuditTests: XCTestCase {
  func testMissingActingUserSubIsRejectedBeforeAnyDatabaseAccess() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    app.internalServiceToken = "test-internal-token"
    try app.register(collection: RolesController())

    try app.testable().test(
      .POST, "api/admin/roles/auth0%7Cabc123",
      beforeRequest: { req in
        req.headers.replaceOrAdd(name: "X-Internal-Service-Token", value: "test-internal-token")
        try req.content.encode(["role": "admin"])
      },
      afterResponse: { res in
        XCTAssertEqual(res.status, .badRequest)
      })
  }

  func testMismatchedInternalTokenIsUnauthorizedBeforeAnyDatabaseAccess() throws {
    let app = Application(.testing)
    defer { app.shutdown() }
    app.internalServiceToken = "test-internal-token"
    try app.register(collection: RolesController())

    try app.testable().test(
      .POST, "api/admin/roles/auth0%7Cabc123",
      beforeRequest: { req in
        req.headers.replaceOrAdd(name: "X-Internal-Service-Token", value: "wrong-token")
        try req.content.encode(["role": "admin"])
      },
      afterResponse: { res in
        XCTAssertEqual(res.status, .unauthorized)
      })
  }
}
