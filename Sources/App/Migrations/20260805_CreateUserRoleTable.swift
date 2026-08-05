//
// 20260805_CreateUserRoleTable.swift
//

import AuthModel
import Fluent

struct CreateUserRoleTable: Migration {
  func prepare(on database: Database) -> EventLoopFuture<Void> {
    database.schema(UserRole.v20260805.schemaName)
      .id()
      .field(UserRole.v20260805.createdAt, .datetime, .required)
      .field(UserRole.v20260805.subject, .string, .required)
      .field(UserRole.v20260805.role, .string, .required)
      .create()
  }

  func revert(on database: Database) -> EventLoopFuture<Void> {
    database.schema(UserRole.v20260805.schemaName)
      .delete()
  }
}
