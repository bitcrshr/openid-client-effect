# openid-client-effect

A fully-featured OpenID Connect client for **Bun** with runtime-safe modeling powered by **Effect Schema**.

## ⚠️ AI-generated project notice

This project was authored with AI assistance and is provided as-is.

Before using it in production, you should:

- Perform a full security review (including token handling, key management, and dependency auditing).
- Validate behavior against the OpenID Connect / OAuth 2.0 specs and your provider-specific requirements.
- Add integration tests for your exact identity provider and deployment environment.
- Review and harden error handling, logging, and operational controls.

Use this library with caution until it has been thoroughly reviewed and tested by humans in your context.

## Features

- OpenID Provider Discovery (`/.well-known/openid-configuration`)
- Authorization URL creation (PKCE and standard OIDC params)
- Token exchange and refresh flows
- UserInfo retrieval
- Token introspection and revocation
- RP-initiated logout URL generation
- JWKS retrieval
- ID Token signature and claim verification (via `jose`)
- End-to-end runtime validation for all protocol payloads using `effect/Schema`

## Install

```bash
bun install
```

## Quick start

```ts
import { Effect } from "effect";
import { OpenIdClient } from "openid-client-effect";

const client = await Effect.runPromise(
  OpenIdClient.discover({
    issuer: "https://your-issuer.example.com",
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
    redirectUri: "https://your-app.example.com/callback"
  })
);

const authorizationUrl = client.createAuthorizationUrl({
  scope: "openid profile email",
  state: crypto.randomUUID(),
  nonce: crypto.randomUUID(),
  code_challenge_method: "S256",
  code_challenge: "..."
});

// After callback:
const token = await client.exchangeAuthorizationCode({
  code: "returned-code",
  codeVerifier: "original-pkce-verifier"
});

const claims = await client.verifyIdToken(token.id_token!);
const userInfo = await client.fetchUserInfo(token.access_token);
```

## API overview

- `OpenIdClient.discover(config)` -> `Effect<OpenIdClient, Error>`
- `createAuthorizationUrl(params)` -> `string`
- `exchangeAuthorizationCode(params)` -> token response
- `refreshToken(refreshToken, scope?)` -> token response
- `fetchUserInfo(accessToken)` -> user info claims
- `fetchJwks()` -> JWK Set
- `verifyIdToken(idToken, options?)` -> validated claims
- `introspectToken(token, hint?)` -> introspection response
- `revokeToken(token, hint?)` -> `void`
- `endSessionUrl(params?)` -> logout URL

## Type safety and runtime safety

All key OIDC payloads are modeled with `effect/Schema` in `src/schemas.ts`, including:

- Provider metadata
- Token success and error responses
- UserInfo response
- Introspection response
- JWK Set
- ID Token claims

This ensures invalid provider responses fail fast with descriptive parsing errors.
