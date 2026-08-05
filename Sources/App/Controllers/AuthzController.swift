//
// AuthzController.swift
//

import AuthModel
import Fluent
import Vapor

struct AuthzCheckRequest: Content {
  let service: String
  let action: String?
}

struct AuthzAllowedResponse: Content {
  let allowed: Bool
  let roles: [String]
  let sub: String
}

struct AuthzDeniedResponse: Content {
  let allowed: Bool
  let reason: String
}

struct AuthzErrorResponse: Content {
  let error: String
}

struct AuthzController: RouteCollection {
  static let endpointPath: PathComponent = "authz"

  func boot(routes: RoutesBuilder) throws {
    let group = routes.grouped(Self.endpointPath)
    group.post("check", use: self.check)
  }

  func check(req: Request) throws -> EventLoopFuture<Response> {
    let checkRequest = try req.content.decode(AuthzCheckRequest.self)

    guard let token = req.headers.bearerAuthorization?.token else {
      return self.invalidTokenResponse(req)
    }

    return req.verifyAuth0Token(token)
      .flatMap { payload in
        self.authorize(subject: payload.subject.value, service: checkRequest.service, req: req)
      }
      .flatMapError { _ in
        self.invalidTokenResponse(req)
      }
  }

  private func authorize(subject: String, service: String, req: Request)
    -> EventLoopFuture<Response>
  {
    let rolesFuture = UserRole.query(on: req.db)
      .filter(\.$subject == subject)
      .all()
    let denyFuture = ServiceDenyEntry.query(on: req.db)
      .filter(\.$subject == subject)
      .filter(\.$service == service)
      .first()

    return rolesFuture.and(denyFuture).flatMapThrowing { roles, deny in
      let response = Response(status: .ok)
      if deny != nil {
        try response.content.encode(AuthzDeniedResponse(allowed: false, reason: "service_denied"))
        return response
      }
      let roleNames = roles.isEmpty ? [Role.user.rawValue] : roles.map { $0.role.rawValue }
      try response.content.encode(
        AuthzAllowedResponse(allowed: true, roles: roleNames, sub: subject))
      return response
    }
  }

  private func invalidTokenResponse(_ req: Request) -> EventLoopFuture<Response> {
    let response = Response(status: .unauthorized)
    do {
      try response.content.encode(AuthzErrorResponse(error: "invalid_token"))
    } catch {
      return req.eventLoop.makeFailedFuture(error)
    }
    return req.eventLoop.makeSucceededFuture(response)
  }
}
