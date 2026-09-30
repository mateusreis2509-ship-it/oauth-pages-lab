import { randomBase64Url, sha256Base64Url } from "../../_shared/crypto.js";
import { oauthTransactionCookie } from "../../_shared/cookies.js";
import { getProviderConfig } from "../../_shared/providers.js";

export async function onRequestGet(context) {
    const { request, env, params } = context;
    const provider = params.provider;

    if (provider !== "google" && provider !== "github") {
        return new Response("Not Found", {
            status: 404,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }

    const config = getProviderConfig(provider, env);

    if (!config || !config.clientId || !config.clientSecret) {
        return new Response("Server configuration error", {
            status: 500,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }

    const transactionId = randomBase64Url(32);
    const state = randomBase64Url(32);
    const codeVerifier = randomBase64Url(32);

    const transactionIdHash = await sha256Base64Url(transactionId);
    const stateHash = await sha256Base64Url(state);
    const codeVerifierHash = await sha256Base64Url(codeVerifier);

    let nonce = null;

    if (provider === "google") {
        nonce = randomBase64Url(32);
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 600;

    await env.DB
        .prepare(`
            INSERT INTO oauth_transactions (
                id_hash,
                provider,
                state_hash,
                nonce,
                code_verifier,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `)
        .bind(
            transactionIdHash,
            provider,
            stateHash,
            nonce,
            codeVerifier,
            expiresAt
        )
        .run();

    const url = new URL(request.url);

    const authUrl = new URL(
        provider === "google"
            ? "https://accounts.google.com/o/oauth2/v2/auth"
            : "https://github.com/login/oauth/authorize"
    );

    authUrl.searchParams.set(
        "client_id",
        config.clientId
    );

    authUrl.searchParams.set(
        "redirect_uri",
        config.redirectUri
    );

    authUrl.searchParams.set(
        "response_type",
        "code"
    );

    authUrl.searchParams.set(
        "state",
        state
    );

    authUrl.searchParams.set(
        "code_challenge",
        codeVerifierHash
    );

    authUrl.searchParams.set(
        "code_challenge_method",
        "S256"
    );

    if (provider === "google") {
        authUrl.searchParams.set(
            "scope",
            "openid email profile"
        );

        authUrl.searchParams.set(
            "nonce",
            nonce
        );
    }

    const headers = new Headers();

    headers.set(
        "Location",
        authUrl.toString()
    );

    headers.set(
        "Set-Cookie",
        oauthTransactionCookie(transactionId)
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