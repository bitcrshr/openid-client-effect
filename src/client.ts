import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "@effect/platform";
import { Effect, ParseResult, Schema } from "effect";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  DiscoveryError,
  HttpRequestError,
  IdTokenVerificationError,
  MissingEndpointError,
  OAuthErrorResponse,
  SchemaValidationError,
  type OpenIdClientError
} from "./errors";
import {
  AuthorizationRequest,
  IdTokenClaims,
  IntrospectionResponse,
  Jwks,
  OpenIdProviderMetadata,
  TokenEndpointError,
  TokenEndpointSuccess,
  UserInfoResponse,
  type AuthorizationRequest as AuthorizationRequestType,
  type IdTokenClaims as IdTokenClaimsType,
  type IntrospectionResponse as IntrospectionResponseType,
  type Jwks as JwksType,
  type OpenIdProviderMetadata as OpenIdProviderMetadataType,
  type TokenEndpointError as TokenEndpointErrorType,
  type TokenEndpointSuccess as TokenEndpointSuccessType,
  type UserInfoResponse as UserInfoResponseType
} from "./schemas";

/**
 * Configuration for constructing an {@link OpenIdClient}.
 */
export interface OpenIdClientConfig {
  /** Issuer URL, for example `https://accounts.example.com`. */
  readonly issuer: string;
  /** OAuth client identifier. */
  readonly clientId: string;
  /** Optional OAuth client secret (used for basic auth at token-ish endpoints). */
  readonly clientSecret?: string;
  /** Optional default redirect URI for authorization-code flows. */
  readonly redirectUri?: string;
  /** Optional default requested scopes. */
  readonly defaultScopes?: string;
  /** Optional clock tolerance in seconds for ID token verification. */
  readonly clockToleranceSeconds?: number;
  /** Optional custom fetch implementation (useful for tests or custom runtimes). */
  readonly fetch?: typeof fetch;
}

/**
 * Options for ID token verification.
 */
export interface VerifyIdTokenOptions {
  /** Expected nonce, validated against token claims when provided. */
  readonly nonce?: string;
}

const decodeWithSchema = (
  schema: Schema.Schema<any, any, any>,
  operation: string,
  value: unknown
): Effect.Effect<any, SchemaValidationError> =>
  (Schema.decodeUnknown(schema as any)(value) as Effect.Effect<any, any, never>).pipe(
    Effect.mapError((cause) =>
      new SchemaValidationError({
        operation,
        message: ParseResult.TreeFormatter.formatErrorSync(cause),
        cause
      })
    )
  );

const parseJsonResponse = (response: HttpClientResponse.HttpClientResponse, operation: string) =>
  response.json.pipe(
    Effect.mapError(
      (cause) =>
        new HttpRequestError({
          operation,
          message: `Failed to decode JSON response (status ${response.status})`,
          cause
        })
    )
  );

const ensureEndpoint = (value: string | undefined, endpoint: string): Effect.Effect<string, MissingEndpointError> =>
  value
    ? Effect.succeed(value)
    : Effect.fail(
        new MissingEndpointError({
          endpoint,
          message: `Provider metadata does not contain ${endpoint}`
        })
      );

/**
 * Fully-featured OpenID Connect client powered by Effect and Effect Platform HTTP Client.
 */
export class OpenIdClient {
  /** Normalized issuer URL. */
  readonly issuer: string;
  /** OAuth client identifier. */
  readonly clientId: string;
  /** Optional OAuth client secret. */
  readonly clientSecret?: string;
  /** Optional default redirect URI. */
  readonly redirectUri?: string;
  /** Default scopes used by authorization URLs. */
  readonly defaultScopes: string;
  /** ID token verification clock tolerance in seconds. */
  readonly clockToleranceSeconds: number;
  /** OpenID provider metadata from discovery. */
  readonly metadata: OpenIdProviderMetadataType;

  private readonly fetchImpl: typeof fetch;
  private readonly jwkSet: ReturnType<typeof createRemoteJWKSet>;

  private constructor(config: OpenIdClientConfig, metadata: OpenIdProviderMetadataType) {
    this.issuer = config.issuer;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.defaultScopes = config.defaultScopes ?? "openid profile email";
    this.clockToleranceSeconds = config.clockToleranceSeconds ?? 15;
    this.metadata = metadata;
    this.fetchImpl = config.fetch ?? fetch;
    this.jwkSet = createRemoteJWKSet(new URL(metadata.jwks_uri));
  }

  /**
   * Discovers provider metadata from `/.well-known/openid-configuration`.
   */
  static discover(config: OpenIdClientConfig): Effect.Effect<OpenIdClient, DiscoveryError | HttpRequestError | SchemaValidationError> {
    const normalizedIssuer = config.issuer.replace(/\/$/, "");
    const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;

    return HttpClient.get(discoveryUrl).pipe(
      Effect.flatMap((response) => parseJsonResponse(response, "provider discovery")),
      Effect.flatMap((json) => decodeWithSchema(OpenIdProviderMetadata as any, "provider discovery metadata", json)),
      Effect.map((metadata) => new OpenIdClient({ ...config, issuer: normalizedIssuer }, metadata as OpenIdProviderMetadataType)),
      Effect.mapError((error) => {
        if (error instanceof HttpRequestError || error instanceof SchemaValidationError) {
          return new DiscoveryError({ issuer: normalizedIssuer, message: error.message, cause: error });
        }
        return new DiscoveryError({ issuer: normalizedIssuer, message: "Provider discovery failed", cause: error });
      }),
      (effect) => OpenIdClient.provideHttp(effect, config.fetch ?? fetch)
    );
  }

  /**
   * Builds an authorization URL including standard OIDC parameters.
   */
  createAuthorizationUrl(
    input: Omit<AuthorizationRequestType, "redirect_uri"> & {
      /** Override redirect URI for this request only. */
      readonly redirect_uri?: string;
      /** Additional custom query parameters. */
      readonly additionalParameters?: Record<string, string | number | boolean>;
    }
  ): Effect.Effect<string, SchemaValidationError | MissingEndpointError> {
    const redirectUri = input.redirect_uri ?? this.redirectUri;
    if (!redirectUri) {
      return Effect.fail(
        new SchemaValidationError({
          operation: "create authorization URL",
          message: "redirect_uri is required (either in client config or request)",
          cause: undefined
        })
      );
    }

    return decodeWithSchema(AuthorizationRequest as any, "authorization request", {
      ...input,
      redirect_uri: redirectUri,
      response_type: input.response_type ?? "code",
      scope: input.scope ?? this.defaultScopes
    }).pipe(
      Effect.flatMap((validatedRaw) =>
        ensureEndpoint(this.metadata.authorization_endpoint, "authorization_endpoint").pipe(
          Effect.map((endpoint) => {
            const url = new URL(endpoint);
            const params = new URLSearchParams({
              client_id: this.clientId,
              ...Object.fromEntries(
                Object.entries(validatedRaw as Record<string, unknown>)
                  .filter(([, value]) => value !== undefined)
                  .map(([key, value]) => [key, String(value)])
              ),
              ...Object.fromEntries(
                Object.entries(input.additionalParameters ?? {}).map(([key, value]) => [key, String(value)])
              )
            });
            url.search = params.toString();
            return url.toString();
          })
        )
      )
    );
  }

  /**
   * Exchanges an authorization code for tokens.
   */
  exchangeAuthorizationCode(params: {
    /** Authorization code obtained from callback. */
    readonly code: string;
    /** Optional request-level redirect URI override. */
    readonly redirectUri?: string;
    /** Optional PKCE code verifier. */
    readonly codeVerifier?: string;
  }): Effect.Effect<TokenEndpointSuccessType, OpenIdClientError> {
    const redirectUri = params.redirectUri ?? this.redirectUri;
    if (!redirectUri) {
      return Effect.fail(
        new SchemaValidationError({
          operation: "authorization_code exchange",
          message: "redirect_uri is required for authorization_code exchange",
          cause: undefined
        })
      );
    }

    return this.callTokenEndpoint("authorization_code exchange", {
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: redirectUri,
      code_verifier: params.codeVerifier,
      client_id: this.clientId
    });
  }

  /**
   * Uses a refresh token to obtain fresh access credentials.
   */
  refreshToken(refreshToken: string, scope?: string): Effect.Effect<TokenEndpointSuccessType, OpenIdClientError> {
    return this.callTokenEndpoint("refresh token", {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope,
      client_id: this.clientId
    });
  }

  /**
   * Retrieves UserInfo claims using a bearer access token.
   */
  fetchUserInfo(accessToken: string): Effect.Effect<UserInfoResponseType, OpenIdClientError> {
    return ensureEndpoint(this.metadata.userinfo_endpoint, "userinfo_endpoint").pipe(
      Effect.flatMap((endpoint) =>
        this.executeRequest(HttpClient.get(endpoint, { headers: { Authorization: `Bearer ${accessToken}` } }), "userinfo call")
      ),
      Effect.flatMap((response) => this.decodeResponse(response, UserInfoResponse as any, "userinfo payload"))
    );
  }

  /**
   * Fetches the provider JWKS document.
   */
  fetchJwks(): Effect.Effect<JwksType, OpenIdClientError> {
    return this.executeRequest(HttpClient.get(this.metadata.jwks_uri), "jwks fetch").pipe(
      Effect.flatMap((response) => this.decodeResponse(response, Jwks as any, "jwks payload"))
    );
  }

  /**
   * Introspects an OAuth token.
   */
  introspectToken(token: string, tokenTypeHint?: string): Effect.Effect<IntrospectionResponseType, OpenIdClientError> {
    return ensureEndpoint(this.metadata.introspection_endpoint, "introspection_endpoint").pipe(
      Effect.flatMap((endpoint) =>
        this.executeRequest(
          HttpClientRequest.post(endpoint).pipe(
            HttpClientRequest.setHeaders(this.authHeaders()),
            HttpClientRequest.bodyUrlParams({ token, token_type_hint: tokenTypeHint, client_id: this.clientId })
          ).pipe(HttpClient.execute),
          "token introspection"
        )
      ),
      Effect.flatMap((response) => this.decodeResponse(response, IntrospectionResponse as any, "token introspection payload"))
    );
  }

  /**
   * Revokes an OAuth token.
   */
  revokeToken(token: string, tokenTypeHint?: string): Effect.Effect<void, OpenIdClientError> {
    return ensureEndpoint(this.metadata.revocation_endpoint, "revocation_endpoint").pipe(
      Effect.flatMap((endpoint) =>
        this.executeRequest(
          HttpClientRequest.post(endpoint).pipe(
            HttpClientRequest.setHeaders(this.authHeaders()),
            HttpClientRequest.bodyUrlParams({ token, token_type_hint: tokenTypeHint, client_id: this.clientId })
          ).pipe(HttpClient.execute),
          "token revocation"
        )
      ),
      Effect.asVoid
    );
  }

  /**
   * Builds RP-initiated logout URL for providers exposing `end_session_endpoint`.
   */
  endSessionUrl(params: {
    /** Optional ID token hint. */
    readonly idTokenHint?: string;
    /** Optional post logout redirect URI. */
    readonly postLogoutRedirectUri?: string;
    /** Optional CSRF state for logout redirect. */
    readonly state?: string;
  } = {}): Effect.Effect<string, MissingEndpointError> {
    return ensureEndpoint(this.metadata.end_session_endpoint, "end_session_endpoint").pipe(
      Effect.map((endpoint) => {
        const url = new URL(endpoint);
        const query = new URLSearchParams();
        if (params.idTokenHint) query.set("id_token_hint", params.idTokenHint);
        if (params.postLogoutRedirectUri) query.set("post_logout_redirect_uri", params.postLogoutRedirectUri);
        if (params.state) query.set("state", params.state);
        url.search = query.toString();
        return url.toString();
      })
    );
  }

  /**
   * Verifies ID token signature and core claims (`iss`, `aud`, `exp`, etc.).
   */
  verifyIdToken(idToken: string, options: VerifyIdTokenOptions = {}): Effect.Effect<IdTokenClaimsType, OpenIdClientError> {
    return Effect.tryPromise({
      try: async () =>
        jwtVerify(idToken, this.jwkSet, {
          issuer: this.metadata.issuer,
          audience: this.clientId,
          clockTolerance: this.clockToleranceSeconds
        }),
      catch: (cause) => new IdTokenVerificationError({ message: "Failed to verify ID token", cause })
    }).pipe(
      Effect.flatMap((verified) => decodeWithSchema(IdTokenClaims as any, "id token claims", verified.payload)),
      Effect.flatMap((claimsRaw) => {
        const claims = claimsRaw as IdTokenClaimsType;
        if (options.nonce && claims.nonce !== options.nonce) {
          return Effect.fail(new IdTokenVerificationError({ message: "ID token nonce does not match" }));
        }
        return Effect.succeed(claims as IdTokenClaimsType);
      })
    );
  }

  private callTokenEndpoint(
    operation: string,
    body: Record<string, string | undefined>
  ): Effect.Effect<TokenEndpointSuccessType, OpenIdClientError> {
    return ensureEndpoint(this.metadata.token_endpoint, "token_endpoint").pipe(
      Effect.flatMap((endpoint) =>
        this.executeRaw(
          HttpClientRequest.post(endpoint).pipe(
            HttpClientRequest.setHeaders(this.authHeaders()),
            HttpClientRequest.bodyUrlParams(body),
            HttpClient.execute
          ),
          operation
        )
      ),
      Effect.flatMap((response) =>
        parseJsonResponse(response, operation).pipe(
          Effect.flatMap((json) => {
            if (response.status < 200 || response.status >= 300) {
              return decodeWithSchema(TokenEndpointError as any, `${operation} error payload`, json).pipe(
                Effect.flatMap((oauthRaw) => {
                  const oauth = oauthRaw as TokenEndpointErrorType;
                  return Effect.fail(
                    new OAuthErrorResponse({
                      operation,
                      error: oauth.error,
                      errorDescription: oauth.error_description,
                      errorUri: oauth.error_uri
                    })
                  );
                }),
                Effect.catchTag("SchemaValidationError", (error) =>
                  Effect.fail(
                    new HttpRequestError({
                      operation,
                      message: `Endpoint returned status ${response.status} with non-OAuth payload`,
                      cause: error
                    })
                  )
                )
              );
            }

            return decodeWithSchema(TokenEndpointSuccess as any, `${operation} success payload`, json).pipe(
              Effect.map((x) => x as TokenEndpointSuccessType),
              Effect.mapError((error) => new HttpRequestError({ operation, message: "Invalid token success payload", cause: error }))
            );
          })
        )
      )
    );
  }

  private decodeResponse<A>(
    response: HttpClientResponse.HttpClientResponse,
    schema: Schema.Schema<A, any, any>,
    operation: string
  ): Effect.Effect<A, OpenIdClientError> {
    if (response.status < 200 || response.status >= 300) {
      return parseJsonResponse(response, operation).pipe(
        Effect.flatMap((json) =>
          decodeWithSchema(TokenEndpointError as any, `${operation} oauth error`, json).pipe(
            Effect.flatMap((payloadRaw) => {
              const payload = payloadRaw as TokenEndpointErrorType;
              return Effect.fail(
                new OAuthErrorResponse({
                  operation,
                  error: payload.error,
                  errorDescription: payload.error_description,
                  errorUri: payload.error_uri
                })
              );
            }),
            Effect.catchTag("SchemaValidationError", (error) =>
              Effect.fail(
                new HttpRequestError({ operation, message: `Unexpected non-2xx response (${response.status})`, cause: error })
              )
            )
          )
        )
      );
    }

    return parseJsonResponse(response, operation).pipe(Effect.flatMap((json) => decodeWithSchema(schema as any, operation, json)));
  }

  private executeRequest(
    effect: Effect.Effect<HttpClientResponse.HttpClientResponse, unknown, any>,
    operation: string
  ): Effect.Effect<HttpClientResponse.HttpClientResponse, HttpRequestError> {
    return this.executeRaw(effect, operation).pipe(
      Effect.flatMap((response) =>
        response.status >= 200 && response.status < 300
          ? Effect.succeed(response)
          : Effect.fail(new HttpRequestError({ operation, message: `Request failed with status ${response.status}` }))
      )
    );
  }

  private executeRaw<E>(
    effect: Effect.Effect<HttpClientResponse.HttpClientResponse, E, any>,
    operation: string
  ): Effect.Effect<HttpClientResponse.HttpClientResponse, HttpRequestError> {
    return OpenIdClient.provideHttp(effect, this.fetchImpl).pipe(
      Effect.mapError((cause) =>
        new HttpRequestError({
          operation,
          message: "HTTP client execution failed",
          cause
        })
      )
    );
  }

  private authHeaders(): Record<string, string> {
    if (!this.clientSecret) {
      return { "content-type": "application/x-www-form-urlencoded" };
    }

    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    return {
      Authorization: `Basic ${basic}`,
      "content-type": "application/x-www-form-urlencoded"
    };
  }

  private static provideHttp<A, E, R>(effect: Effect.Effect<A, E, R>, fetchImpl: typeof fetch): Effect.Effect<A, E, never> {
    return effect.pipe(Effect.provide(FetchHttpClient.layer), Effect.provideService(FetchHttpClient.Fetch, fetchImpl)) as Effect.Effect<A, E, never>;
  }
}
