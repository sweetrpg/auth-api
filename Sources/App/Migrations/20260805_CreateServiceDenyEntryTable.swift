//
// 20260805_CreateServiceDenyEntryTable.swift
//

import AuthModel
import Fluent

struct CreateServiceDenyEntryTable: Migration {
  func prepare(on database: Database) -> EventLoopFuture<Void> {
    database.schema(ServiceDenyEntry.v20260805.schemaName)
      .id()
      .field(ServiceDenyEntry.v20260805.createdAt, .datetime, .required)
      .field(ServiceDenyEntry.v20260805.subject, .string, .required)
      .field(ServiceDenyEntry.v20260805.service, .string, .required)
      .create()
  }

  func revert(on database: Database) -> EventLoopFuture<Void> {
    database.schema(ServiceDenyEntry.v20260805.schemaName)
      .delete()
  }
}
