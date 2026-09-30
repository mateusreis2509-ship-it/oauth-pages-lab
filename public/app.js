fetch('/api', {
    credentials: "same-origin"
})
    .then((response) => {
        const contentType = response.headers.get("content-type");
        
        // Só tenta ler JSON se a resposta for OK e o tipo for JSON
        if (response.ok && contentType && contentType.includes("application/json")) {
            return response.json();
        }

        return null;
    })
    .then((user) => {
        const status = document.getElementById("status");

        if (user) {
            status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
        } else {
            status.textContent = "Nenhuma sessão neste navegador.";
        }
    })
    .catch((err) => {
        console.error("Erro ao verificar sessão:", err);
    });
    export async function onRequest(context) {
    const { request, env } = context;

    // 1. Sua lógica existente que lê o cookie ou busca o usuário no D1:
    // const user = await obterUsuarioDaSessao(request, env);

    // 2. AQUI NO FINAL entram as linhas do Response.json:
    if (user) {
        return Response.json(user);
    }

    return Response.json({ loggedIn: false }, { status: 401 });
}