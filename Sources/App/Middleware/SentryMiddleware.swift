import Vapor

/// Reports any error the responder chain throws to Sentry, then rethrows unchanged - Vapor's
/// own `ErrorMiddleware` (registered by default) still turns it into the actual HTTP response.
/// This only observes; it never changes behavior.
struct SentryMiddleware: AsyncMiddleware {
  func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
    do {
      return try await next.respond(to: request)
    } catch {
      request.application.sentryReporter?.report(error, on: request.client)
      throw error
    }
  }
}
