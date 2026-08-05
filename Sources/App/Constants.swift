//
// Constants.swift
// Copyright (c) 2021 Paul Schifferer.
//

import Foundation
import Vapor

struct Constants {
  static let apiPath: PathComponent = "api"
  static let oauthLoginDataKey = "oauth_login"
  static let serviceName = "auth-api"
  static let serviceIdBase = "auth-api-"
}
