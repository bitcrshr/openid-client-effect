import { Schema } from "effect";

/** OIDC scope string (`openid profile email`, etc.). */
export const Scope = Schema.String.pipe(
  Schema.pattern(/^[\w:./-]+(?:\s+[\w:./-]+)*$/),
  Schema.annotations({ identifier: "Scope" })
);

/** Supported token endpoint client authentication methods. */
export const ClientAuthenticationMethod = Schema.Literal("client_secret_basic", "client_secret_post", "none");

/** OpenID Provider metadata returned from discovery. */
export const OpenIdProviderMetadata = Schema.Struct({
  issuer: Schema.String,
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.optional(Schema.String),
  userinfo_endpoint: Schema.optional(Schema.String),
  jwks_uri: Schema.String,
  registration_endpoint: Schema.optional(Schema.String),
  scopes_supported: Schema.optional(Schema.Array(Schema.String)),
  response_types_supported: Schema.Array(Schema.String),
  response_modes_supported: Schema.optional(Schema.Array(Schema.String)),
  grant_types_supported: Schema.optional(Schema.Array(Schema.String)),
  subject_types_supported: Schema.Array(Schema.String),
  id_token_signing_alg_values_supported: Schema.Array(Schema.String),
  token_endpoint_auth_methods_supported: Schema.optional(Schema.Array(ClientAuthenticationMethod)),
  claims_supported: Schema.optional(Schema.Array(Schema.String)),
  code_challenge_methods_supported: Schema.optional(Schema.Array(Schema.String)),
  introspection_endpoint: Schema.optional(Schema.String),
  revocation_endpoint: Schema.optional(Schema.String),
  end_session_endpoint: Schema.optional(Schema.String)
});

/** Authorization request model (core + common optional parameters). */
export const AuthorizationRequest = Schema.Struct({
  redirect_uri: Schema.String,
  scope: Scope,
  response_type: Schema.optional(Schema.String),
  state: Schema.optional(Schema.String),
  nonce: Schema.optional(Schema.String),
  code_challenge: Schema.optional(Schema.String),
  code_challenge_method: Schema.optional(Schema.Literal("S256", "plain")),
  prompt: Schema.optional(Schema.String),
  login_hint: Schema.optional(Schema.String),
  acr_values: Schema.optional(Schema.String),
  max_age: Schema.optional(Schema.Number),
  audience: Schema.optional(Schema.String)
});

/** Successful token endpoint response. */
export const TokenEndpointSuccess = Schema.Struct({
  access_token: Schema.String,
  token_type: Schema.String,
  expires_in: Schema.optional(Schema.Number),
  refresh_token: Schema.optional(Schema.String),
  scope: Schema.optional(Scope),
  id_token: Schema.optional(Schema.String)
});

/** OAuth error payload shape returned from token-like endpoints. */
export const TokenEndpointError = Schema.Struct({
  error: Schema.String,
  error_description: Schema.optional(Schema.String),
  error_uri: Schema.optional(Schema.String)
});

/** OIDC userinfo response claims model. */
export const UserInfoResponse = Schema.Struct({
  sub: Schema.String,
  name: Schema.optional(Schema.String),
  given_name: Schema.optional(Schema.String),
  family_name: Schema.optional(Schema.String),
  middle_name: Schema.optional(Schema.String),
  nickname: Schema.optional(Schema.String),
  preferred_username: Schema.optional(Schema.String),
  profile: Schema.optional(Schema.String),
  picture: Schema.optional(Schema.String),
  website: Schema.optional(Schema.String),
  email: Schema.optional(Schema.String),
  email_verified: Schema.optional(Schema.Boolean),
  gender: Schema.optional(Schema.String),
  birthdate: Schema.optional(Schema.String),
  zoneinfo: Schema.optional(Schema.String),
  locale: Schema.optional(Schema.String),
  phone_number: Schema.optional(Schema.String),
  phone_number_verified: Schema.optional(Schema.Boolean),
  address: Schema.optional(Schema.Unknown),
  updated_at: Schema.optional(Schema.Number)
});

/** Token introspection response model. */
export const IntrospectionResponse = Schema.Struct({
  active: Schema.Boolean,
  scope: Schema.optional(Scope),
  client_id: Schema.optional(Schema.String),
  username: Schema.optional(Schema.String),
  token_type: Schema.optional(Schema.String),
  exp: Schema.optional(Schema.Number),
  iat: Schema.optional(Schema.Number),
  nbf: Schema.optional(Schema.Number),
  sub: Schema.optional(Schema.String),
  aud: Schema.optional(Schema.Union(Schema.String, Schema.Array(Schema.String))),
  iss: Schema.optional(Schema.String),
  jti: Schema.optional(Schema.String)
});

/** JSON Web Key (single key) model. */
export const Jwk = Schema.Struct({
  kty: Schema.String,
  use: Schema.optional(Schema.String),
  key_ops: Schema.optional(Schema.Array(Schema.String)),
  alg: Schema.optional(Schema.String),
  kid: Schema.optional(Schema.String),
  x5u: Schema.optional(Schema.String),
  x5c: Schema.optional(Schema.Array(Schema.String)),
  x5t: Schema.optional(Schema.String),
  "x5t#S256": Schema.optional(Schema.String),
  crv: Schema.optional(Schema.String),
  x: Schema.optional(Schema.String),
  y: Schema.optional(Schema.String),
  d: Schema.optional(Schema.String),
  n: Schema.optional(Schema.String),
  e: Schema.optional(Schema.String)
});

/** JSON Web Key Set model. */
export const Jwks = Schema.Struct({ keys: Schema.Array(Jwk) });

/** ID token claims model validated after JOSE verification. */
export const IdTokenClaims = Schema.Struct({
  iss: Schema.String,
  sub: Schema.String,
  aud: Schema.Union(Schema.String, Schema.Array(Schema.String)),
  exp: Schema.Number,
  iat: Schema.Number,
  nonce: Schema.optional(Schema.String),
  auth_time: Schema.optional(Schema.Number),
  azp: Schema.optional(Schema.String),
  at_hash: Schema.optional(Schema.String),
  c_hash: Schema.optional(Schema.String),
  s_hash: Schema.optional(Schema.String),
  email: Schema.optional(Schema.String),
  email_verified: Schema.optional(Schema.Boolean),
  name: Schema.optional(Schema.String),
  preferred_username: Schema.optional(Schema.String)
});

/** Runtime type for {@link OpenIdProviderMetadata}. */
export type OpenIdProviderMetadata = Schema.Schema.Type<typeof OpenIdProviderMetadata>;
/** Runtime type for {@link AuthorizationRequest}. */
export type AuthorizationRequest = Schema.Schema.Type<typeof AuthorizationRequest>;
/** Runtime type for {@link TokenEndpointSuccess}. */
export type TokenEndpointSuccess = Schema.Schema.Type<typeof TokenEndpointSuccess>;
/** Runtime type for {@link TokenEndpointError}. */
export type TokenEndpointError = Schema.Schema.Type<typeof TokenEndpointError>;
/** Runtime type for {@link UserInfoResponse}. */
export type UserInfoResponse = Schema.Schema.Type<typeof UserInfoResponse>;
/** Runtime type for {@link IntrospectionResponse}. */
export type IntrospectionResponse = Schema.Schema.Type<typeof IntrospectionResponse>;
/** Runtime type for {@link Jwks}. */
export type Jwks = Schema.Schema.Type<typeof Jwks>;
/** Runtime type for {@link IdTokenClaims}. */
export type IdTokenClaims = Schema.Schema.Type<typeof IdTokenClaims>;
