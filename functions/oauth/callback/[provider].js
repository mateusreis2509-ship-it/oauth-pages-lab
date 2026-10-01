import {
    getCookie,
    sessionCookie,
    clearOAuthTransactionCookie
} from "../../_shared/cookies.js";

import {
    sha256Base64Url,
    randomBase64Url
} from "../../_shared/crypto.js";

import { getProviderConfig } from "../../_shared/providers.js";

import { validateGoogleIdToken } from "../../_shared/oidc.js";

function unauthorized() {
    return new Response("Unauthorized", {
        status: 401,
        headers: {
            "Cache-Control": "no-store"
        }
    });
}

function badRequest() {
    return new Response("Bad Request", {
        status: 400,
        headers: {
            "Cache-Control": "no-store"
        }
    });
}

export async function onRequestGet(context) {
    const { request, env, params } = context;
    const provider = params.provider;

    const url = new URL(request.url);
    const error = url.searchParams.get("error");
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (error || !code || !state) {
        return badRequest();
    }

    const transactionCookie = getCookie(request, "__Host-oauth-tx");

    if (!transactionCookie) {
        return unauthorized();
    }

    const transactionIdHash =
        await sha256Base64Url(transactionCookie);

    const now = Math.floor(Date.now() / 1000);

    const transaction = await env.DB
        .prepare(`
            SELECT
                provider,
                state_hash,
                nonce,
                code_verifier,
                expires_at
            FROM oauth_transactions
            WHERE id_hash = ?
              AND expires_at > ?
        `)
        .bind(transactionIdHash, now)
        .first();

    if (!transaction) {
        return unauthorized();
    }

    if (transaction.provider !== provider) {
        return unauthorized();
    }

    const stateHash = await sha256Base64Url(state);

    if (stateHash !== transaction.state_hash) {
        return unauthorized();
    }

    await env.DB
        .prepare(`
            DELETE FROM oauth_transactions
            WHERE id_hash = ?
        `)
        .bind(transactionIdHash)
        .run();

    const config = getProviderConfig(provider, env);

    if (!config || !config.clientId || !config.clientSecret) {
        return new Response("Server configuration error", {
            status: 500,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }

    let identity;

    try {
        if (provider === "google") {
            identity = await handleGoogleCallback(
                code,
                transaction.code_verifier,
                transaction.nonce,
                config
            );
        } else if (provider === "github") {
            identity = await handleGithubCallback(
                code,
                transaction.code_verifier,
                config
            );
        }
    } catch (error) {
        return new Response(error.message, {
            status: 500,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }

    if (!identity) {
        return unauthorized();
    }

    const sessionValue = randomBase64Url(32);
    const sessionIdHash =
        await sha256Base64Url(sessionValue);

    const sessionExpiresAt = now + 28800;

    await env.DB
        .prepare(`
            INSERT INTO sessions (
                id_hash,
                issuer,
                subject,
                email,
                display_name,
                expires_at,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            sessionIdHash,
            identity.issuer,
            identity.subject,
            identity.email,
            identity.displayName,
            sessionExpiresAt,
            now
        )
        .run();

    const headers = new Headers();

    headers.set(
        "Location",
        env.PUBLIC_BASE_URL
    );

    headers.append(
        "Set-Cookie",
        sessionCookie(sessionValue)
    );

    headers.append(
        "Set-Cookie",
        clearOAuthTransactionCookie()
    );

    headers.set(
        "Cache-Control",
        "no-store"
    );

    return new Response(null, {
        status: 302,
        headers
    });
}

async function handleGoogleCallback(
    code,
    codeVerifier,
    nonce,
    config
) {
    const body = new URLSearchParams();

    body.set("client_id", config.clientId);
    body.set("client_secret", config.clientSecret);
    body.set("code", code);
    body.set("grant_type", "authorization_code");
    body.set("redirect_uri", config.redirectUri);
    body.set("code_verifier", codeVerifier);

    const response = await fetch(config.tokenUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        },
        body
    });

    if (!response.ok) {
        const errorBody = await response.text();

        throw new Error(
            `Google token exchange failed: ${response.status} ${errorBody}`
        );
    }

    const tokenResponse = await response.json();

    if (!tokenResponse.id_token) {
        throw new Error(
            "Google did not return an id_token"
        );
    }

    try {
        return await validateGoogleIdToken(
            tokenResponse.id_token,
            config.clientId,
            nonce
        );
    } catch {
        throw new Error(
            "Google ID token validation failed"
        );
    }
}

async function handleGithubCallback(
    code,
    codeVerifier,
    config
) {
    const body = new URLSearchParams();

    body.set("client_id", config.clientId);
    body.set("client_secret", config.clientSecret);
    body.set("code", code);
    body.set("redirect_uri", config.redirectUri);
    body.set("code_verifier", codeVerifier);

    const tokenResponse = await fetch(config.tokenUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        },
        body
    });

    if (!tokenResponse.ok) {
        return null;
    }

    const tokenData = await tokenResponse.json();

    if (
        typeof tokenData.access_token !== "string" ||
        typeof tokenData.token_type !== "string" ||
        tokenData.token_type.toLowerCase() !== "bearer"
    ) {
        return null;
    }

    const accessToken = tokenData.access_token;

    const userResponse = await fetch(
        "https://api.github.com/user",
        {
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "oauth-pages-lab"
            }
        }
    );

    if (!userResponse.ok) {
        throw new Error(
            `GitHub profile request failed: ${userResponse.status}`
        );
    }

    const githubUser = await userResponse.json();

    if (!Number.isInteger(githubUser.id)) {
        return null;
    }

    const revokeBody = JSON.stringify({
        access_token: accessToken
    });

    const basicCredentials = btoa(
        `${config.clientId}:${config.clientSecret}`
    );

    const revokeResponse = await fetch(
        `https://api.github.com/applications/${config.clientId}/grant`,
        {
            method: "DELETE",
            headers: {
                "Authorization": `Basic ${basicCredentials}`,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "Content-Type": "application/json",
                "User-Agent": "oauth-pages-lab"
            },
            body: revokeBody
        }
    );

    if (revokeResponse.status !== 204) {
        throw new Error(
            `GitHub revoke failed: ${revokeResponse.status}`
        );
    }

    return {
        issuer: "https://github.com",
        subject: String(githubUser.id),
        email:
            typeof githubUser.email === "string"
                ? githubUser.email
                : null,
        displayName:
            typeof githubUser.name === "string"
                ? githubUser.name
                : typeof githubUser.login === "string"
                    ? githubUser.login
                    : null
    };
}