export async function onRequest(context) {
    const { request, env } = context;

    const cookieHeader = request.headers.get("Cookie") || "";

    return Response.json({
        cookieRecebido: cookieHeader,
        temBancoD1: !!env.DB,
    });
}