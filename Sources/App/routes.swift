//
// routes.swift
//

import Fluent
import Vapor

func routes(_ app: Application) throws {
  app.get("status", "ping") { req -> [String: String] in
    ["status": "ok", "hostname": Environment.get("HOSTNAME") ?? "unknown"]
  }

  try app.register(collection: AuthzController())
  try app.register(collection: RolesController())
}
