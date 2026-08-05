//
// Application+Testable.swift
// Copyright (c) 2021 Paul Schifferer.
//

import App
import XCTVapor

extension Application {
  static func testable() throws -> Application {
    let app = Application(.testing)
    try configure(app)

    try app.autoRevert().wait()
    try app.autoMigrate().wait()

    return app
  }
}
