import { getCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestGet(context) {
    const { request, env } = context;

    const sessionCookie = getCookie(request, "__Host-session");

    if (!sessionCookie) {
        return Response.json(
            { authenticated: false },
            {
                status: 401,
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );
    }

    const sessionIdHash = await sha256Base64Url(sessionCookie);

    const now = Math.floor(Date.now() / 1000);

    const session = await env.DB
        .prepare(`
            SELECT
                issuer,
                subject,
                email,
                display_name,
                expires_at
            FROM sessions
            WHERE id_hash = ?
              AND expires_at > ?
        `)
        .bind(sessionIdHash, now)
        .first();

    if (!session) {
        return Response.json(
            { authenticated: false },
            {
                status: 401,
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );
    }

    return Response.json(
        {
            authenticated: true,
            user: {
                issuer: session.issuer,
                subject: session.subject,
                email: session.email,
                displayName: session.display_name
            }
        },
        {
            headers: {
                "Cache-Control": "no-store"
            }
        }
    );
}