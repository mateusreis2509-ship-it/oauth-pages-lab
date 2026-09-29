// Helper: Gera 32 bytes aleatórios e codifica em Base64URL sem preenchimento
function generateRandomBase64Url() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const base64 = btoa(String.fromCharCode.apply(null, array));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Helper: Calcula o resumo (hash) SHA-256 e codifica em Base64URL
async function sha256Base64Url(plainText) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plainText);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    const base64 = btoa(String.fromCharCode.apply(null, hashArray));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function onRequestGet(context) {
    const provider = context.params.provider;

    // 1. Aceitar somente google ou github
    if (provider !== 'google' && provider !== 'github') {
        return new Response('Not Found', { status: 404 });
    }

    // 2. Gerar valores aleatórios (transação, state, code_verifier, nonce)
    const txId = generateRandomBase64Url();
    const state = generateRandomBase64Url();
    const codeVerifier = generateRandomBase64Url();
    const nonce = provider === 'google' ? generateRandomBase64Url() : null;

    // 3. Calcular os resumos com SHA-256
    const txIdHash = await sha256Base64Url(txId);
    const stateHash = await sha256Base64Url(state);
    const codeChallenge = await sha256Base64Url(codeVerifier);

    // 4. Gravar no D1 (expiração de 10 minutos = 600 segundos)
    const expiresAt = Math.floor(Date.now() / 1000) + 600;

    await context.env.DB.prepare(
        `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(txIdHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

    // 5. Montar o pedido de autorização e URLs
    const baseUrl = context.env.PUBLIC_BASE_URL;
    const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
    let authUrl;

    if (provider === 'google') {
        const clientId = context.env.GOOGLE_CLIENT_ID;
        const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            scope: 'openid email profile',
            nonce: nonce
        });
        authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    } else if (provider === 'github') {
        const clientId = context.env.GITHUB_CLIENT_ID;
        const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        authUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
    }

    // 6. Criar o cookie e redirecionar (302)
    const cookie = `__Host-oauth-tx=${txId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

    return new Response(null, {
        status: 302,
        headers: {
            'Location': authUrl,
            'Set-Cookie': cookie,
            'Cache-Control': 'no-store'
        }
    });
}