# openid-client-effect

A fully-featured OpenID Connect client for **Bun**, built with **Effect**, **Effect Platform HTTP Client**, and **Effect Schema**.

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
- Effect Platform HTTP Client for all protocol HTTP calls
- Runtime-safe OIDC modeling with `effect/Schema`
- Custom typed error classes for excellent DX
- Authorization URL creation (PKCE + standard OIDC params)
- Token exchange and refresh flows
- UserInfo retrieval
- Token introspection and revocation
- RP-initiated logout URL generation
- JWKS retrieval and ID token verification (`jose`)

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

const authorizationUrl = await Effect.runPromise(
  client.createAuthorizationUrl({
    scope: "openid profile email",
    state: crypto.randomUUID(),
    nonce: crypto.randomUUID(),
    code_challenge_method: "S256",
    code_challenge: "..."
  })
);

const token = await Effect.runPromise(
  client.exchangeAuthorizationCode({
    code: "returned-code",
    codeVerifier: "original-pkce-verifier"
  })
);

const claims = await Effect.runPromise(client.verifyIdToken(token.id_token!));
const userInfo = await Effect.runPromise(client.fetchUserInfo(token.access_token));
```

## Error handling

All client methods return `Effect` values with rich custom errors from `src/errors.ts`, including:

- `DiscoveryError`
- `MissingEndpointError`
- `HttpRequestError`
- `OAuthErrorResponse`
- `SchemaValidationError`
- `IdTokenVerificationError`

This enables precise pattern matching and ergonomic recovery for consumer applications.

## API docs (GitHub Pages)

API docs are generated from JSDoc using TypeDoc and published from the `docs/` directory.

Build docs locally:

```bash
bun run docs:build
```

Then publish `docs/` via GitHub Pages (Settings → Pages → Deploy from branch, `/docs` folder).

This repository also includes a GitHub Actions workflow at `.github/workflows/docs.yml` that builds and deploys `docs/` to GitHub Pages on pushes to `main`.
