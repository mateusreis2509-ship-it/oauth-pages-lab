export async function onRequest(context) {
    const { request, env } = context;

    // 1. Extrai todos os cookies enviados pelo navegador
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = Object.fromEntries(
        cookieHeader.split(';').map(c => {
            const [key, ...val] = c.trim().split('=');
            return [key, val.join('=')];
        })
    );

    // 2. Obtém o token do cookie (procura por __Host-session ou session)
    const sessionToken = cookies['__Host-session'] || cookies['session'];

    if (!sessionToken) {
        return Response.json({ loggedIn: false }, { status: 401 });
    }

    try {
        // 3. Consulta a base de dados D1 para encontrar o utilizador associado à sessão
        if (env.DB) {
            const user = await env.DB.prepare(
                "SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.id = ?"
            ).bind(sessionToken).first();

            if (user) {
                return Response.json(user);
            }
        }
    } catch (error) {
        console.error("Erro ao validar sessão no D1:", error);
    }

    // Se a sessão não existir ou tiver expirado na base de dados
    return Response.json({ loggedIn: false }, { status: 401 });
}