/** @vitest-environment node */
import { createHash, createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  TELEGRAM_OIDC_ISSUER,
  TELEGRAM_OIDC_JWKS_URI,
  TELEGRAM_OIDC_TOKEN_ENDPOINT,
} from "./constants";
import { telegram } from "./index";

const baseURL = "http://localhost:3000";
const clientId = "123456789";

function cookies(response: Response) {
  return response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
}

interface TestDatabase {
  account: Record<string, unknown>[];
  session: Record<string, unknown>[];
  user: Record<string, unknown>[];
  verification: Record<string, unknown>[];
  [model: string]: Record<string, unknown>[];
}

function createTestAuth(database: TestDatabase, allowDifferentEmails = false) {
  return betterAuth({
    baseURL,
    secret: "integration-test-secret-at-least-32-characters",
    database: memoryAdapter(database),
    account: {
      accountLinking: {
        enabled: true,
        trustedProviders: ["telegram-oidc"],
        allowDifferentEmails,
      },
    },
    plugins: [
      telegram({
        botToken: `${clientId}:test-token`,
        botUsername: "integration_test_bot",
        miniApp: { enabled: true },
        oidc: { enabled: true, clientId, clientSecret: "integration-secret" },
      }),
    ],
  });
}

describe("Better Auth 1.7 Telegram OAuth callback integration", () => {
  let keys: Awaited<ReturnType<typeof generateKeyPair>>;
  let idToken: string;
  let database: TestDatabase;
  let auth: ReturnType<typeof createTestAuth>;

  beforeEach(async () => {
    keys = await generateKeyPair("RS256");
    const jwk = {
      ...(await exportJWK(keys.publicKey)),
      kid: "integration-key",
      alg: "RS256",
      use: "sig",
    };
    database = { user: [], account: [], session: [], verification: [] };
    auth = createTestAuth(database);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        let url: string;
        if (typeof input === "string") {
          url = input;
        } else if (input instanceof URL) {
          url = input.href;
        } else {
          url = input.url;
        }
        if (url === TELEGRAM_OIDC_TOKEN_ENDPOINT) {
          return Promise.resolve(
            Response.json({
              access_token: "test-access-token",
              token_type: "Bearer",
              id_token: idToken,
            })
          );
        }
        if (url === TELEGRAM_OIDC_JWKS_URI) {
          return Promise.resolve(Response.json({ keys: [jwk] }));
        }
        throw new Error(`Unexpected external request: ${url}`);
      })
    );
  });

  afterEach(() => vi.unstubAllGlobals());

  async function login(
    subject: string,
    overrides: Record<string, unknown> = {},
    sessionCookie = "",
    linking = false
  ) {
    const start = await auth.handler(
      new Request(
        `${baseURL}/api/auth/${linking ? "link-social" : "sign-in/social"}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: baseURL,
            cookie: sessionCookie,
          },
          body: JSON.stringify({
            provider: "telegram-oidc",
            callbackURL: `${baseURL}/done`,
          }),
        }
      )
    );
    expect(start.status).toBe(200);
    const authorizationURL = new URL((await start.json()).url);
    const nonce = authorizationURL.searchParams.get("nonce");
    expect(nonce).toBeTruthy();
    expect(authorizationURL.searchParams.get("code_challenge_method")).toBe(
      "S256"
    );
    idToken = await new SignJWT({
      sub: subject,
      id: 987654321,
      name: "Telegram User",
      iss: TELEGRAM_OIDC_ISSUER,
      aud: clientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce,
      ...overrides,
    })
      .setProtectedHeader({ alg: "RS256", kid: "integration-key" })
      .sign(keys.privateKey);
    const callback = new URL(`${baseURL}/api/auth/callback/telegram-oidc`);
    callback.searchParams.set("code", "test-authorization-code");
    callback.searchParams.set(
      "state",
      authorizationURL.searchParams.get("state")!
    );
    const response = await auth.handler(
      new Request(callback, {
        headers: { cookie: `${cookies(start)}; ${sessionCookie}` },
      })
    );
    return response;
  }

  it("accepts signed widget login and Mini App login with the same user", async () => {
    const botToken = `${clientId}:test-token`;
    const widget = {
      id: 987654321,
      first_name: "Widget User",
      username: "widget_user",
      auth_date: Math.floor(Date.now() / 1000),
    };
    const widgetCheck = Object.entries(widget)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");
    const widgetHash = createHmac(
      "sha256",
      createHash("sha256").update(botToken).digest()
    )
      .update(widgetCheck)
      .digest("hex");
    const widgetResponse = await auth.handler(
      new Request(`${baseURL}/api/auth/telegram/signin`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: baseURL },
        body: JSON.stringify({ ...widget, hash: widgetHash }),
      })
    );
    expect(widgetResponse.status).toBe(200);
    const widgetSession = await auth.api.getSession({
      headers: new Headers({ cookie: cookies(widgetResponse) }),
    });
    expect(widgetSession?.user.name).toBe("Widget User");
    const initData = new URLSearchParams({
      auth_date: String(widget.auth_date),
      user: JSON.stringify({
        id: widget.id,
        first_name: "Mini App User",
        username: widget.username,
      }),
    });
    const initCheck = [...initData]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");
    const miniAppKey = createHmac("sha256", "WebAppData")
      .update(botToken)
      .digest();
    initData.set(
      "hash",
      createHmac("sha256", miniAppKey).update(initCheck).digest("hex")
    );
    const miniAppResponse = await auth.handler(
      new Request(`${baseURL}/api/auth/telegram/miniapp/signin`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: baseURL },
        body: JSON.stringify({ initData: initData.toString() }),
      })
    );
    expect(miniAppResponse.status).toBe(200);
    const miniAppSession = await auth.api.getSession({
      headers: new Headers({ cookie: cookies(miniAppResponse) }),
    });
    expect(miniAppSession?.user.id).toBe(widgetSession?.user.id);
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
  });

  it("creates a session and reuses the same account on the next login", async () => {
    const first = await login("stable-oidc-subject");
    expect(first.headers.get("location")).toBe(`${baseURL}/done`);
    const session = await auth.api.getSession({
      headers: new Headers({ cookie: cookies(first) }),
    });
    expect(session?.user.name).toBe("Telegram User");
    expect(database.account).toHaveLength(1);
    expect(database.account[0]?.accountId).toBe("stable-oidc-subject");
    expect(database.account[0]?.accountId).not.toBe("987654321");
    const second = await login("stable-oidc-subject");
    expect(second.headers.get("location")).toBe(`${baseURL}/done`);
    const nextSession = await auth.api.getSession({
      headers: new Headers({ cookie: cookies(second) }),
    });
    expect(nextSession?.user.id).toBe(session?.user.id);
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(1);
  });

  it("links another subject only when different-email linking is explicitly allowed", async () => {
    auth = createTestAuth(database, true);
    const first = await login("first-subject");
    const sessionCookie = cookies(first);
    const linked = await login("linked-subject", {}, sessionCookie, true);
    expect(linked.headers.get("location")).toBe(`${baseURL}/done`);
    expect(database.user).toHaveLength(1);
    expect(database.account).toHaveLength(2);
    expect(database.account[0]?.userId).toBe(database.account[1]?.userId);
  });

  it("rejects linking a different Telegram identity by default", async () => {
    const first = await login("first-subject");
    const linked = await login("linked-subject", {}, cookies(first), true);
    expect(linked.headers.get("location")).toContain("email_does_not_match");
    expect(database.account).toHaveLength(1);
    expect(database.user).toHaveLength(1);
  });

  it.each([
    ["nonce", { nonce: "wrong-nonce" }],
    ["audience", { aud: "another-app" }],
    ["issuer", { iss: "https://untrusted.example" }],
    ["expiry", { exp: 1 }],
    ["subject", { sub: "" }],
  ])("rejects invalid %s without creating a session", async (_name, overrides) => {
    const response = await login("stable-oidc-subject", overrides);
    expect(response.headers.get("location")).toContain("error=");
    expect(database.user).toHaveLength(0);
    expect(database.account).toHaveLength(0);
    expect(database.session).toHaveLength(0);
  });
});
