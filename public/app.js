JavaScript
fetch('/api/me', {
    credentials: "same-origin"
})
    .then((response) => {
        if (response.ok) {
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