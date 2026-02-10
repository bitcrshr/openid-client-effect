import { Data } from "effect";

/**
 * Base error type for all OpenID client failures.
 */
export type OpenIdClientError =
  | DiscoveryError
  | MissingEndpointError
  | HttpRequestError
  | OAuthErrorResponse
  | SchemaValidationError
  | IdTokenVerificationError;

/**
 * Raised when OpenID Provider discovery fails.
 */
export class DiscoveryError extends Data.TaggedError("DiscoveryError")<{
  readonly issuer: string;
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Raised when provider metadata does not include a required endpoint.
 */
export class MissingEndpointError extends Data.TaggedError("MissingEndpointError")<{
  readonly endpoint: string;
  readonly message: string;
}> {}

/**
 * Raised when an HTTP request fails before a usable protocol response is obtained.
 */
export class HttpRequestError extends Data.TaggedError("HttpRequestError")<{
  readonly operation: string;
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Raised when an OAuth / OIDC endpoint returns an explicit error payload.
 */
export class OAuthErrorResponse extends Data.TaggedError("OAuthErrorResponse")<{
  readonly operation: string;
  readonly error: string;
  readonly errorDescription?: string;
  readonly errorUri?: string;
}> {}

/**
 * Raised when response payloads fail Effect Schema validation.
 */
export class SchemaValidationError extends Data.TaggedError("SchemaValidationError")<{
  readonly operation: string;
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Raised when JOSE-level ID token verification fails.
 */
export class IdTokenVerificationError extends Data.TaggedError("IdTokenVerificationError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}
