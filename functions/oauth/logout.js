import { getCookie, clearSessionCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestPost(context) {
    const { request, env } = context;

    const origin = request.headers.get("Origin");

    if (origin !== env.PUBLIC_BASE_URL) {
        return new Response("Forbidden", {
            status: 403,
            headers: {
                "Cache-Control": "no-store"
            }
        });
    }

    const sessionCookie = getCookie(request, "__Host-session");

    if (sessionCookie) {
        const sessionIdHash = await sha256Base64Url(sessionCookie);

        await env.DB
            .prepare(`
                DELETE FROM sessions
                WHERE id_hash = ?
            `)
            .bind(sessionIdHash)
            .run();
    }

    return new Response(null, {
        status: 204,
        headers: {
            "Set-Cookie": clearSessionCookie(),
            "Cache-Control": "no-store"
        }
    });
}