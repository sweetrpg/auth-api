//
// AdminActionAuditLog.swift
//

import Fluent
import Vapor

/// Every mutating action `RolesController` performs (grant/revoke a role, add/remove a
/// service deny entry) gets one of these, written *before* the action is attempted and updated
/// *after* it completes - see `RolesController.performAudited(...)`. If the "before" write
/// fails, the action is not performed at all: an audit trail that can silently fail to exist is
/// not an audit trail. Both `actingUserSub` and `targetSubject` are raw Auth0 `sub` strings, not
/// foreign keys - `auth-api` holds no profile data to key against, and every caller
/// (internal-service-token or bearer-token) already has the raw subject string on hand
/// regardless.
final class AdminActionAuditLog: Model, Content {
  static let schema = "admin_action_audit_logs"

  enum Status: String, Codable {
    case attempted
    case succeeded
    case failed
  }

  @ID
  var id: UUID?

  @Field(key: "actingUserSub")
  var actingUserSub: String

  /// e.g. "add_role", "remove_role", "add_deny_entry", "remove_deny_entry".
  @Field(key: "action")
  var action: String

  @Field(key: "targetSubject")
  var targetSubject: String

  /// The role name or service name the action applied to.
  @Field(key: "detail")
  var detail: String

  @Field(key: "status")
  var status: Status

  @Timestamp(key: "attemptedAt", on: .create)
  var attemptedAt: Date?

  @OptionalField(key: "completedAt")
  var completedAt: Date?

  @OptionalField(key: "errorMessage")
  var errorMessage: String?

  init() {}

  init(actingUserSub: String, action: String, targetSubject: String, detail: String) {
    self.actingUserSub = actingUserSub
    self.action = action
    self.targetSubject = targetSubject
    self.detail = detail
    self.status = .attempted
  }
}
