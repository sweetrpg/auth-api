//
// main.swift
// Copyright (c) 2021 Paul Schifferer.
//

import App
import Vapor

var env = try Environment.detect()
//print(env)
try LoggingSystem.bootstrap(from: &env)
let app = Application(env)
defer {
  app.shutdown()
}
try configure(app)

// Configure custom hostname.
app.http.server.configuration.hostname = Environment.get("BIND_ADDRESS") ?? "0.0.0.0"
app.http.server.configuration.port = Int(Environment.get("PORT") ?? "8080") ?? 8080
try app.run()
