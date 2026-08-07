//
// configure.swift
//

import Fluent
import FluentMongoDriver
import Vapor

public func configure(_ app: Application) throws {
  app.logger.logLevel = app.environment == .development ? .debug : .info

  app.middleware.use(SentryMiddleware())

  // DB_URI is a direct override (local dev, no-auth Mongo - see kubernetes/overlays/local's
  // secrets.yaml). Otherwise built from parts (DB_SCHEME/DB_HOST/DB_USER/DB_NAME/DB_OPTS from
  // the configmap, DB_PW from the Akeyless-sourced secret) rather than one opaque DATABASE_URL -
  // same pattern as users-api's own configure.swift, since only the password is sensitive.
  let dbUrl: String
  if let dbUri = Environment.get("DB_URI") {
    dbUrl = dbUri
  } else {
    guard let dbScheme = Environment.get("DB_SCHEME"),
      let dbHost = Environment.get("DB_HOST"),
      let dbUser = Environment.get("DB_USER"),
      let dbPassword = Environment.get("DB_PW"),
      let dbName = Environment.get("DB_NAME")
    else {
      fatalError(
        "DB_URI, or DB_SCHEME/DB_HOST/DB_USER/DB_PW/DB_NAME, must be set in environment")
    }
    let encodedUser = dbUser.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? dbUser
    let encodedPassword =
      dbPassword.addingPercentEncoding(withAllowedCharacters: .urlPasswordAllowed) ?? dbPassword
    var url = "\(dbScheme)://\(encodedUser):\(encodedPassword)@\(dbHost)/\(dbName)"
    if let dbOpts = Environment.get("DB_OPTS"), !dbOpts.isEmpty {
      url += "?\(dbOpts)"
    }
    dbUrl = url
  }
  try app.databases.use(.mongo(connectionString: dbUrl), as: .mongo)

  try migrations(app)

  try routes(app)

  try app.autoMigrate().wait()
}
