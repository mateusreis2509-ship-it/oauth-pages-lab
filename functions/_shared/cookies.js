export function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie") || "";

    for (const part of cookieHeader.split(";")) {
        const [key, ...valueParts] = part.trim().split("=");

        if (key === name) {
            return valueParts.join("=");
        }
    }

    return null;
}

export function sessionCookie(value) {
    return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

export function clearSessionCookie() {
    return "__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

export function oauthTransactionCookie(value) {
    return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

export function clearOAuthTransactionCookie() {
    return "__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}