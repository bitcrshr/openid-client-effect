import { describe, expect, it } from "bun:test";
import { Effect } from "effect";
import { OpenIdClient } from "../src/client";

const metadata = {
  issuer: "https://issuer.example.com",
  authorization_endpoint: "https://issuer.example.com/oauth2/authorize",
  token_endpoint: "https://issuer.example.com/oauth2/token",
  userinfo_endpoint: "https://issuer.example.com/oauth2/userinfo",
  jwks_uri: "https://issuer.example.com/oauth2/jwks",
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  introspection_endpoint: "https://issuer.example.com/oauth2/introspect",
  revocation_endpoint: "https://issuer.example.com/oauth2/revoke",
  end_session_endpoint: "https://issuer.example.com/logout"
};

const fetchFor = (routes: Record<string, { status?: number; body: unknown }>): typeof fetch => {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const route = routes[url];

    if (!route) {
      return new Response(JSON.stringify({ error: "not_found", url, method: init?.method }), {
        status: 404,
        headers: { "content-type": "application/json" }
      });
    }

    return new Response(JSON.stringify(route.body), {
      status: route.status ?? 200,
      headers: { "content-type": "application/json" }
    });
  }) as typeof fetch;
};

describe("OpenIdClient", () => {
  it("discovers metadata and creates authorization URLs", async () => {
    const client = await Effect.runPromise(
      OpenIdClient.discover({
        issuer: "https://issuer.example.com",
        clientId: "my-client",
        redirectUri: "https://app.example.com/callback",
        fetch: fetchFor({
          "https://issuer.example.com/.well-known/openid-configuration": { body: metadata }
        })
      })
    );

    const url = new URL(
      client.createAuthorizationUrl({
        scope: "openid profile email",
        state: "abc",
        nonce: "nonce"
      })
    );

    expect(url.origin + url.pathname).toBe("https://issuer.example.com/oauth2/authorize");
    expect(url.searchParams.get("client_id")).toBe("my-client");
    expect(url.searchParams.get("state")).toBe("abc");
  });

  it("handles code exchange, userinfo and introspection", async () => {
    const client = await Effect.runPromise(
      OpenIdClient.discover({
        issuer: "https://issuer.example.com",
        clientId: "my-client",
        clientSecret: "my-secret",
        redirectUri: "https://app.example.com/callback",
        fetch: fetchFor({
          "https://issuer.example.com/.well-known/openid-configuration": { body: metadata },
          "https://issuer.example.com/oauth2/token": {
            body: {
              access_token: "access-token",
              token_type: "Bearer",
              expires_in: 3600,
              refresh_token: "refresh-token"
            }
          },
          "https://issuer.example.com/oauth2/userinfo": {
            body: {
              sub: "123",
              email: "user@example.com",
              email_verified: true
            }
          },
          "https://issuer.example.com/oauth2/introspect": {
            body: {
              active: true,
              sub: "123",
              client_id: "my-client"
            }
          },
          "https://issuer.example.com/oauth2/revoke": {
            status: 200,
            body: {}
          }
        })
      })
    );

    const token = await client.exchangeAuthorizationCode({ code: "code" });
    expect(token.access_token).toBe("access-token");

    const user = await client.fetchUserInfo(token.access_token);
    expect(user.sub).toBe("123");

    const introspected = await client.introspectToken(token.access_token);
    expect(introspected.active).toBe(true);

    await client.revokeToken(token.access_token);
    expect(client.endSessionUrl({ state: "bye" })).toContain("state=bye");
  });
});
