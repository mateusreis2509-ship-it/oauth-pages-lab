export async function onRequest(context) {
    const { request, env } = context;

    // Coloque aqui a sua lógica existente para recuperar a sessão/utilizador
    // Exemplo: const user = await obterUsuarioDaSessao(request, env);

    if (typeof user !== 'undefined' && user) {
        return Response.json(user);
    }

    return Response.json({ loggedIn: false }, { status: 401 });
}