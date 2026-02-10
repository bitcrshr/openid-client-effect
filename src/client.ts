import { Effect, ParseResult, Schema } from "effect";
import { createRemoteJWKSet, jwtVerify } from "jose";
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
  type TokenEndpointSuccess as TokenEndpointSuccessType,
  type UserInfoResponse as UserInfoResponseType
} from "./schemas";

export interface OpenIdClientConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  defaultScopes?: string;
  clockToleranceSeconds?: number;
  fetch?: typeof fetch;
}

export interface VerifyIdTokenOptions {
  nonce?: string;
}

const parseOrThrow = (schema: Schema.Schema<any, any, any>, value: unknown): any => {
  const either = Schema.decodeUnknownEither(schema as any)(value);
  if (either._tag === "Left") {
    throw new Error(ParseResult.TreeFormatter.formatErrorSync(either.left));
  }

  return either.right;
};

const queryFromObject = (params: Record<string, string | number | boolean | undefined>): URLSearchParams => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      query.set(key, String(value));
    }
  }
  return query;
};

const assertEndpoint = (value: string | undefined, endpoint: string): string => {
  if (!value) {
    throw new Error(`Provider metadata does not contain ${endpoint}`);
  }
  return value;
};

export class OpenIdClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly redirectUri?: string;
  readonly defaultScopes: string;
  readonly clockToleranceSeconds: number;
  readonly metadata: OpenIdProviderMetadataType;

  private readonly doFetch: typeof fetch;
  private readonly jwkSet: ReturnType<typeof createRemoteJWKSet>;

  private constructor(config: OpenIdClientConfig, metadata: OpenIdProviderMetadataType) {
    this.issuer = config.issuer;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.defaultScopes = config.defaultScopes ?? "openid profile email";
    this.clockToleranceSeconds = config.clockToleranceSeconds ?? 15;
    this.metadata = metadata;
    this.doFetch = config.fetch ?? fetch;
    this.jwkSet = createRemoteJWKSet(new URL(metadata.jwks_uri));
  }

  static discover(config: OpenIdClientConfig): Effect.Effect<OpenIdClient, Error> {
    return Effect.tryPromise({
      try: async () => {
        const normalizedIssuer = config.issuer.replace(/\/$/, "");
        const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;
        const response = await (config.fetch ?? fetch)(discoveryUrl);
        if (!response.ok) {
          throw new Error(`Failed to fetch openid-configuration: ${response.status} ${response.statusText}`);
        }

        const json = await response.json();
        const metadata = parseOrThrow(OpenIdProviderMetadata, json) as OpenIdProviderMetadataType;
        return new OpenIdClient({ ...config, issuer: normalizedIssuer }, metadata);
      },
      catch: (error) => (error instanceof Error ? error : new Error(String(error)))
    });
  }

  createAuthorizationUrl(
    input: Omit<AuthorizationRequestType, "redirect_uri"> & {
      redirect_uri?: string;
      additionalParameters?: Record<string, string | number | boolean>;
    }
  ): string {
    const redirectUri = input.redirect_uri ?? this.redirectUri;
    if (!redirectUri) {
      throw new Error("redirect_uri is required (either in config or request)");
    }

    const parsedInput = parseOrThrow(AuthorizationRequest, {
      ...input,
      redirect_uri: redirectUri,
      scope: input.scope ?? this.defaultScopes,
      response_type: input.response_type ?? "code"
    });

    const query = queryFromObject({
      client_id: this.clientId,
      ...parsedInput,
      ...input.additionalParameters
    });

    const url = new URL(this.metadata.authorization_endpoint);
    url.search = query.toString();
    return url.toString();
  }

  async exchangeAuthorizationCode(params: {
    code: string;
    redirectUri?: string;
    codeVerifier?: string;
  }): Promise<TokenEndpointSuccessType> {
    const redirectUri = params.redirectUri ?? this.redirectUri;
    if (!redirectUri) {
      throw new Error("redirect_uri is required for authorization_code exchange");
    }

    return this.callTokenEndpoint({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: redirectUri,
      code_verifier: params.codeVerifier,
      client_id: this.clientId
    });
  }

  async refreshToken(refreshToken: string, scope?: string): Promise<TokenEndpointSuccessType> {
    return this.callTokenEndpoint({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope,
      client_id: this.clientId
    });
  }

  async fetchUserInfo(accessToken: string): Promise<UserInfoResponseType> {
    const userInfoEndpoint = assertEndpoint(this.metadata.userinfo_endpoint, "userinfo_endpoint");
    const response = await this.doFetch(userInfoEndpoint, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!response.ok) {
      throw await this.toError(response, "userinfo call failed");
    }

    return parseOrThrow(UserInfoResponse, await response.json()) as UserInfoResponseType;
  }

  async fetchJwks(): Promise<JwksType> {
    const response = await this.doFetch(this.metadata.jwks_uri);
    if (!response.ok) {
      throw await this.toError(response, "jwks fetch failed");
    }

    return parseOrThrow(Jwks, await response.json()) as JwksType;
  }

  async introspectToken(token: string, tokenTypeHint?: string): Promise<IntrospectionResponseType> {
    const introspectionEndpoint = assertEndpoint(this.metadata.introspection_endpoint, "introspection_endpoint");
    const response = await this.doFetch(introspectionEndpoint, {
      method: "POST",
      headers: {
        ...this.authHeaders(),
        "content-type": "application/x-www-form-urlencoded"
      },
      body: queryFromObject({ token, token_type_hint: tokenTypeHint, client_id: this.clientId }).toString()
    });

    if (!response.ok) {
      throw await this.toError(response, "token introspection failed");
    }

    return parseOrThrow(IntrospectionResponse, await response.json()) as IntrospectionResponseType;
  }

  async revokeToken(token: string, tokenTypeHint?: string): Promise<void> {
    const revocationEndpoint = assertEndpoint(this.metadata.revocation_endpoint, "revocation_endpoint");
    const response = await this.doFetch(revocationEndpoint, {
      method: "POST",
      headers: {
        ...this.authHeaders(),
        "content-type": "application/x-www-form-urlencoded"
      },
      body: queryFromObject({ token, token_type_hint: tokenTypeHint, client_id: this.clientId }).toString()
    });

    if (!response.ok) {
      throw await this.toError(response, "token revocation failed");
    }
  }

  endSessionUrl(params: {
    idTokenHint?: string;
    postLogoutRedirectUri?: string;
    state?: string;
  } = {}): string {
    const endpoint = assertEndpoint(this.metadata.end_session_endpoint, "end_session_endpoint");
    const url = new URL(endpoint);
    url.search = queryFromObject({
      id_token_hint: params.idTokenHint,
      post_logout_redirect_uri: params.postLogoutRedirectUri,
      state: params.state
    }).toString();
    return url.toString();
  }

  async verifyIdToken(idToken: string, options: VerifyIdTokenOptions = {}): Promise<IdTokenClaimsType> {
    const verified = await jwtVerify(idToken, this.jwkSet, {
      issuer: this.metadata.issuer,
      audience: this.clientId,
      clockTolerance: this.clockToleranceSeconds
    });

    const claims = parseOrThrow(IdTokenClaims, verified.payload) as IdTokenClaimsType;

    if (options.nonce && claims.nonce !== options.nonce) {
      throw new Error("ID token nonce does not match");
    }

    return claims;
  }

  private async callTokenEndpoint(body: Record<string, string | undefined>): Promise<TokenEndpointSuccessType> {
    const tokenEndpoint = assertEndpoint(this.metadata.token_endpoint, "token_endpoint");
    const response = await this.doFetch(tokenEndpoint, {
      method: "POST",
      headers: {
        ...this.authHeaders(),
        "content-type": "application/x-www-form-urlencoded"
      },
      body: queryFromObject(body).toString()
    });

    const json = await response.json();

    if (!response.ok) {
      throw this.decodeOAuthError(json, `token endpoint returned ${response.status}`);
    }

    return parseOrThrow(TokenEndpointSuccess, json) as TokenEndpointSuccessType;
  }

  private authHeaders(): HeadersInit {
    if (!this.clientSecret) {
      return {};
    }

    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    return { Authorization: `Basic ${basic}` };
  }

  private decodeOAuthError(data: unknown, fallback: string): Error {
    try {
      const parsed = parseOrThrow(TokenEndpointError, data) as { error: string; error_description?: string };
      return new Error(parsed.error_description ?? parsed.error);
    } catch {
      return new Error(fallback);
    }
  }

  private async toError(response: Response, fallback: string): Promise<Error> {
    try {
      return this.decodeOAuthError(await response.json(), fallback);
    } catch {
      return new Error(`${fallback}: ${response.status} ${response.statusText}`);
    }
  }
}
