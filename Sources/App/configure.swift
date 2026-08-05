//
// configure.swift
//

import Fluent
import FluentMongoDriver
import Vapor

public func configure(_ app: Application) throws {
  app.logger.logLevel = app.environment == .development ? .debug : .info

  app.middleware.use(SentryMiddleware())

  guard let dbUrl = Environment.get("DATABASE_URL") else {
    fatalError("DATABASE_URL is not set in environment")
  }
  app.logger.debug("DATABASE_URL: \(dbUrl)")
  try app.databases.use(.mongo(connectionString: dbUrl), as: .mongo)

  try migrations(app)

  try routes(app)

  try app.autoMigrate().wait()
}
