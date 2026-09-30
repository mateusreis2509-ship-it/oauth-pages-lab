const GOOGLE_ISSUER = "https://accounts.google.com";
const GOOGLE_DISCOVERY_URL =
    "https://accounts.google.com/.well-known/openid-configuration";

function base64UrlToUint8Array(value) {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const base64 = value
        .replace(/-/g, "+")
        .replace(/_/g, "/") + padding;

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function decodeBase64UrlJson(value) {
    return JSON.parse(
        new TextDecoder().decode(base64UrlToUint8Array(value))
    );
}

async function getGoogleDiscovery() {
    const response = await fetch(GOOGLE_DISCOVERY_URL, {
        headers: {
            "Accept": "application/json"
        }
    });

    if (!response.ok) {
        throw new Error("Google OIDC discovery failed");
    }

    const discovery = await response.json();

    if (discovery.issuer !== GOOGLE_ISSUER) {
        throw new Error("Invalid Google issuer");
    }

    if (!discovery.jwks_uri) {
        throw new Error("Google JWKS URI missing");
    }

    return discovery;
}

async function getGoogleJwks(jwksUri) {
    const response = await fetch(jwksUri, {
        headers: {
            "Accept": "application/json"
        }
    });

    if (!response.ok) {
        throw new Error("Google JWKS request failed");
    }

    return response.json();
}

export async function validateGoogleIdToken(idToken, expectedAudience, expectedNonce) {
    if (typeof idToken !== "string") {
        throw new Error("Missing id_token");
    }

    const parts = idToken.split(".");

    if (parts.length !== 3) {
        throw new Error("Invalid JWT format");
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    const header = decodeBase64UrlJson(encodedHeader);
    const payload = decodeBase64UrlJson(encodedPayload);

    if (header.alg !== "RS256") {
        throw new Error("Invalid JWT algorithm");
    }

    if (!header.kid) {
        throw new Error("Missing JWT kid");
    }

    const discovery = await getGoogleDiscovery();
    const jwks = await getGoogleJwks(discovery.jwks_uri);

    const jwk = jwks.keys?.find((key) => key.kid === header.kid);

    if (!jwk) {
        throw new Error("Google signing key not found");
    }

    const publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256"
        },
        false,
        ["verify"]
    );

    const signingInput = new TextEncoder().encode(
        `${encodedHeader}.${encodedPayload}`
    );

    const signature = base64UrlToUint8Array(encodedSignature);

    const validSignature = await crypto.subtle.verify(
        {
            name: "RSASSA-PKCS1-v1_5"
        },
        publicKey,
        signature,
        signingInput
    );

    if (!validSignature) {
        throw new Error("Invalid Google JWT signature");
    }

    const now = Math.floor(Date.now() / 1000);

    if (payload.iss !== GOOGLE_ISSUER) {
        throw new Error("Invalid Google issuer");
    }

    if (payload.aud !== expectedAudience) {
        throw new Error("Invalid Google audience");
    }

    if (!Number.isInteger(payload.exp) || payload.exp <= now) {
        throw new Error("Expired Google ID token");
    }

    if (!Number.isInteger(payload.iat) || payload.iat > now) {
        throw new Error("Invalid Google issued-at time");
    }

    if (payload.nonce !== expectedNonce) {
        throw new Error("Invalid Google nonce");
    }

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
        throw new Error("Missing Google subject");
    }

    return {
        issuer: GOOGLE_ISSUER,
        subject: payload.sub,
        email: typeof payload.email === "string" ? payload.email : null,
        displayName: typeof payload.name === "string" ? payload.name : null
    };
}