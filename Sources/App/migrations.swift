//
// migrations.swift
//

import Fluent
import Vapor

public func migrations(_ app: Application) throws {
  app.migrations.add(CreateUserRoleTable())
  app.migrations.add(CreateServiceDenyEntryTable())
  app.migrations.add(CreateAdminActionAuditLogTable())
}
