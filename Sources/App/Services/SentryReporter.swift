import Foundation
import Vapor

/// Minimal Sentry error reporter using their HTTP envelope ingestion API directly, rather than
/// the official `sentry-cocoa` SDK - that package ships ~230MB of Apple-platform-only
/// XCFrameworks (crash reporting binaries meaningless on a Linux server), which is a poor fit
/// for a Docker-deployed Vapor app. This covers the actual need (report unhandled errors) with
/// a plain HTTPS POST, matching the Go services' use of Sentry (docs/service-conventions.md's
/// Telemetry section) without the SDK weight. Ported from catalog-web's own SentryReporter.
struct SentryReporter: Sendable {
  private let publicKey: String
  private let host: String
  private let projectID: String
  private let environment: String
  private let release: String?

  init?(dsn: String, environment: String, release: String?) {
    // DSN shape: https://{publicKey}@{host}/{projectID}
    guard let url = URL(string: dsn),
      let host = url.host,
      let publicKey = url.user
    else { return nil }
    let projectID = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    guard !projectID.isEmpty else { return nil }

    self.publicKey = publicKey
    self.host = host
    self.projectID = projectID
    self.environment = environment
    self.release = release
  }

  func report(_ error: Error, on client: Client) {
    let eventID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    let timestamp = ISO8601DateFormatter().string(from: Date())

    var event: [String: Any] = [
      "event_id": eventID,
      "timestamp": timestamp,
      "platform": "other",
      "environment": environment,
      "level": "error",
      "exception": [
        "values": [
          [
            "type": String(describing: type(of: error)),
            "value": String(describing: error),
          ]
        ]
      ],
    ]
    if let release { event["release"] = release }

    guard let eventData = try? JSONSerialization.data(withJSONObject: event),
      let header = try? JSONSerialization.data(withJSONObject: [
        "event_id": eventID, "sent_at": timestamp,
      ]),
      let itemHeader = try? JSONSerialization.data(withJSONObject: [
        "type": "event", "length": eventData.count,
      ])
    else { return }

    var envelope = Data()
    envelope.append(header)
    envelope.append(contentsOf: [0x0A])
    envelope.append(itemHeader)
    envelope.append(contentsOf: [0x0A])
    envelope.append(eventData)

    let authHeader =
      "Sentry sentry_version=7, sentry_client=users-api/1.0, sentry_key=\(publicKey)"

    // Fire-and-forget: error reporting must never become the reason a request hangs or
    // fails. Logged, not propagated, if Sentry itself is unreachable.
    Task {
      do {
        _ = try await client.post(
          URI(string: "https://\(host)/api/\(projectID)/envelope/"),
          headers: ["X-Sentry-Auth": authHeader, "Content-Type": "application/x-sentry-envelope"]
        ) { req in
          req.body = .init(data: envelope)
        }
      } catch {
        // Deliberately not using the app logger's error level here - a Sentry delivery
        // failure reported at `error` could recursively trigger this same reporting
        // path if it's ever wired to also report logged errors.
      }
    }
  }
}

extension Application {
  private struct SentryReporterKey: StorageKey {
    typealias Value = SentryReporter?
  }

  var sentryReporter: SentryReporter? {
    get {
      if let cached = storage[SentryReporterKey.self] { return cached }
      let reporter = Environment.get("SENTRY_DSN").flatMap {
        SentryReporter(
          dsn: $0,
          environment: Environment.get("ENV") ?? "dev",
          release: Environment.get("VERSION")
        )
      }
      storage[SentryReporterKey.self] = reporter
      return reporter
    }
    set { storage[SentryReporterKey.self] = newValue }
  }
}
