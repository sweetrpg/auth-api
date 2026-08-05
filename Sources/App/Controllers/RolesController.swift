//
// RolesController.swift
//

import AuthModel
import Fluent
import Vapor

struct SubjectRolesSummary: Content {
  let subject: String
  let roles: [String]
  let deniedServices: [String]
}

struct RoleAssignmentRequest: Content {
  let role: String
}

struct DenyEntryRequest: Content {
  let service: String
}

/// Subject-keyed role/deny-entry admin routes. `auth-api` has no user list of its own to serve
/// (no `email`, no profile data) - `admin-web` composes `users-api`'s user list with the bulk
/// lookup here (`GET /admin/roles?subjects=...`), joined by Auth0 subject, rather than this
/// service returning a combined user+roles summary the way `users-api`'s old `RolesController`
/// did. See `sweetrpg/platform`'s `split-authz-into-auth-api` change design.md.
struct RolesController: RouteCollection {
  static let endpointPath: PathComponent = "admin"

  func boot(routes: RoutesBuilder) throws {
    let group = routes.grouped(Constants.apiPath, Self.endpointPath)

    // Bulk lookup for a set of subjects - the primary way admin-web builds its user list view.
    group.get("roles", use: self.listRoles)

    // Get a specific subject's roles and deny entries.
    group.get("roles", ":subject", use: self.getSubject)

    // Add a role to a subject.
    group.post("roles", ":subject", use: self.addRole)

    // Remove a role from a subject.
    group.delete("roles", ":subject", ":role", use: self.removeRole)

    // Add a service deny entry for a subject.
    group.post("deny-entries", ":subject", use: self.addDenyEntry)

    // Remove a service deny entry for a subject.
    group.delete("deny-entries", ":subject", ":service", use: self.removeDenyEntry)
  }

  /// `GET /api/admin/roles?subjects=sub1,sub2,...` - bulk roles/deny-entries for a set of
  /// subjects, in one round trip, so `admin-web`'s user list doesn't do a per-row call.
  private func listRoles(req: Request) throws -> EventLoopFuture<[SubjectRolesSummary]> {
    return self.verifyAdminRole(req: req)
      .flatMapThrowing { _ -> [String] in
        guard let raw = try? req.query.get(String.self, at: "subjects"), !raw.isEmpty else {
          throw Abort(.badRequest, reason: "subjects query parameter is required")
        }
        return raw.split(separator: ",").map { String($0) }
      }
      .flatMap { subjects in
        subjects.map { subject in self.buildSummary(subject: subject, on: req) }
          .flatten(on: req.eventLoop)
      }
  }

  private func getSubject(req: Request) throws -> EventLoopFuture<SubjectRolesSummary> {
    return self.verifyAdminRole(req: req)
      .flatMapThrowing { _ -> String in
        guard let subject = req.parameters.get("subject"), !subject.isEmpty else {
          throw Abort(.badRequest, reason: "Invalid subject")
        }
        return subject
      }
      .flatMap { subject in self.buildSummary(subject: subject, on: req) }
  }

  private func addRole(req: Request) throws -> EventLoopFuture<HTTPStatus> {
    return self.verifyAdminRole(req: req)
      .flatMap { actingUserSub in
        req.eventLoop.makeCompletedFuture {
          guard let subject = req.parameters.get("subject"), !subject.isEmpty else {
            throw Abort(.badRequest, reason: "Invalid subject")
          }
          let request = try req.content.decode(RoleAssignmentRequest.self)
          guard let role = Role(rawValue: request.role) else {
            throw Abort(.badRequest, reason: "Invalid role")
          }
          return (actingUserSub, subject, role)
        }
      }
      .flatMap { actingUserSub, subject, role in
        self.performAudited(
          req: req, actingUserSub: actingUserSub, action: "add_role", targetSubject: subject,
          detail: role.rawValue
        ) {
          UserRole.query(on: req.db)
            .filter(\.$subject == subject)
            .filter(\.$role == role)
            .first()
            .flatMap { existing in
              if existing != nil {
                return req.eventLoop.makeSucceededFuture(.noContent)
              }
              let userRole = UserRole(subject: subject, role: role)
              return userRole.save(on: req.db)
                .map { .created }
            }
        }
      }
  }

  private func removeRole(req: Request) throws -> EventLoopFuture<HTTPStatus> {
    return self.verifyAdminRole(req: req)
      .flatMap { actingUserSub in
        req.eventLoop.makeCompletedFuture {
          guard let subject = req.parameters.get("subject"), !subject.isEmpty else {
            throw Abort(.badRequest, reason: "Invalid subject")
          }
          guard let roleString = req.parameters.get("role"),
            let role = Role(rawValue: roleString)
          else {
            throw Abort(.badRequest, reason: "Invalid role")
          }
          return (actingUserSub, subject, role)
        }
      }
      .flatMap { actingUserSub, subject, role in
        self.performAudited(
          req: req, actingUserSub: actingUserSub, action: "remove_role", targetSubject: subject,
          detail: role.rawValue
        ) {
          UserRole.query(on: req.db)
            .filter(\.$subject == subject)
            .filter(\.$role == role)
            .delete()
            .map { _ in .noContent }
        }
      }
  }

  private func addDenyEntry(req: Request) throws -> EventLoopFuture<HTTPStatus> {
    return self.verifyAdminRole(req: req)
      .flatMap { actingUserSub in
        req.eventLoop.makeCompletedFuture {
          guard let subject = req.parameters.get("subject"), !subject.isEmpty else {
            throw Abort(.badRequest, reason: "Invalid subject")
          }
          let request = try req.content.decode(DenyEntryRequest.self)
          return (actingUserSub, subject, request.service)
        }
      }
      .flatMap { actingUserSub, subject, service in
        self.performAudited(
          req: req, actingUserSub: actingUserSub, action: "add_deny_entry",
          targetSubject: subject, detail: service
        ) {
          ServiceDenyEntry.query(on: req.db)
            .filter(\.$subject == subject)
            .filter(\.$service == service)
            .first()
            .flatMap { existing in
              if existing != nil {
                return req.eventLoop.makeSucceededFuture(.noContent)
              }
              let denyEntry = ServiceDenyEntry(subject: subject, service: service)
              return denyEntry.save(on: req.db)
                .map { .created }
            }
        }
      }
  }

  private func removeDenyEntry(req: Request) throws -> EventLoopFuture<HTTPStatus> {
    return self.verifyAdminRole(req: req)
      .flatMap { actingUserSub in
        req.eventLoop.makeCompletedFuture {
          guard let subject = req.parameters.get("subject"), !subject.isEmpty else {
            throw Abort(.badRequest, reason: "Invalid subject")
          }
          guard let service = req.parameters.get("service") else {
            throw Abort(.badRequest, reason: "Invalid service")
          }
          return (actingUserSub, subject, service)
        }
      }
      .flatMap { actingUserSub, subject, service in
        self.performAudited(
          req: req, actingUserSub: actingUserSub, action: "remove_deny_entry",
          targetSubject: subject, detail: service
        ) {
          ServiceDenyEntry.query(on: req.db)
            .filter(\.$subject == subject)
            .filter(\.$service == service)
            .delete()
            .map { _ in .noContent }
        }
      }
  }

  /// Writes an `AdminActionAuditLog` row *before* running `operation`, and fails closed - never
  /// calling `operation` at all - if that write itself fails: an admin action that can't be
  /// logged must not be performed. Updates the same row to `.succeeded`/`.failed` after
  /// `operation` completes; that post-write is best-effort (logged on failure, but doesn't
  /// retroactively undo an action that already happened - the pre-write is the hard gate, not
  /// the post-write).
  private func performAudited(
    req: Request, actingUserSub: String, action: String, targetSubject: String, detail: String,
    operation: @escaping () -> EventLoopFuture<HTTPStatus>
  ) -> EventLoopFuture<HTTPStatus> {
    let log = AdminActionAuditLog(
      actingUserSub: actingUserSub, action: action, targetSubject: targetSubject, detail: detail)

    return log.save(on: req.db)
      .flatMapError { error in
        req.logger.error(
          "Refusing to perform admin action \(action) - audit log write failed: \(error)")
        return req.eventLoop.makeFailedFuture(
          Abort(.internalServerError, reason: "Could not record audit log; action not performed"))
      }
      .flatMap { _ -> EventLoopFuture<HTTPStatus> in
        operation()
          .flatMap { status in
            log.status = .succeeded
            log.completedAt = Date()
            return log.save(on: req.db)
              .flatMapErrorThrowing { error in
                req.logger.warning(
                  "Failed to record success for audit log \(log.id?.uuidString ?? "?"): \(error)"
                )
              }
              .map { status }
          }
          .flatMapError { error in
            log.status = .failed
            log.completedAt = Date()
            log.errorMessage = String(describing: error)
            return log.save(on: req.db)
              .flatMapErrorThrowing { saveError in
                req.logger.warning(
                  "Failed to record failure for audit log \(log.id?.uuidString ?? "?"): \(saveError)"
                )
              }
              .flatMap { req.eventLoop.makeFailedFuture(error) }
          }
      }
  }

  private func buildSummary(subject: String, on req: Request) -> EventLoopFuture<
    SubjectRolesSummary
  > {
    let rolesFuture = UserRole.query(on: req.db)
      .filter(\.$subject == subject)
      .all()

    let denialsFuture = ServiceDenyEntry.query(on: req.db)
      .filter(\.$subject == subject)
      .all()

    return rolesFuture.and(denialsFuture).map { roles, denials in
      let roleNames = roles.isEmpty ? [Role.user.rawValue] : roles.map { $0.role.rawValue }
      let deniedServices = denials.map { $0.service }
      return SubjectRolesSummary(subject: subject, roles: roleNames, deniedServices: deniedServices)
    }
  }

  /// Trusts a valid `X-Internal-Service-Token` outright (see `InternalServiceAuth.swift` for
  /// why `admin-web` uses this instead of an Auth0 bearer token) - but still requires an
  /// `X-Acting-User-Sub` header identifying who initiated the action, since every mutating
  /// route needs that for its audit log (see `performAudited`). Falls through to verifying an
  /// Auth0 bearer token's `admin` role otherwise, using the verified token's own subject as the
  /// acting user. Returns the resolved acting user's `sub` on success.
  private func verifyAdminRole(req: Request) -> EventLoopFuture<String> {
    if req.hasValidInternalServiceToken {
      guard let actingUserSub = req.headers.first(name: "X-Acting-User-Sub"), !actingUserSub.isEmpty
      else {
        return req.eventLoop.makeFailedFuture(
          Abort(.badRequest, reason: "X-Acting-User-Sub header is required"))
      }
      return req.eventLoop.makeSucceededFuture(actingUserSub)
    }

    guard let token = req.headers.bearerAuthorization?.token else {
      return req.eventLoop.makeFailedFuture(Abort(.unauthorized))
    }

    return req.verifyAuth0Token(token)
      .flatMap { payload in
        UserRole.query(on: req.db)
          .filter(\.$subject == payload.subject.value)
          .all()
          .flatMapThrowing { roles -> String in
            let hasAdminRole = roles.contains { $0.role == .admin }
            if !hasAdminRole {
              throw Abort(.forbidden, reason: "Admin role required")
            }
            return payload.subject.value
          }
      }
      .flatMapError { _ in
        req.eventLoop.makeFailedFuture(Abort(.unauthorized))
      }
  }
}
