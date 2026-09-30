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