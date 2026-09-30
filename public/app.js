async function loadSession() {
    const statusEl = document.getElementById("status");

    if (!statusEl) {
        return;
    }

    try {
        const response = await fetch("/api/me", {
            headers: {
                Accept: "application/json"
            },
            cache: "no-store"
        });
        const data = await response.json();

        if (!response.ok || !data.authenticated) {
            statusEl.textContent = "Não autenticado";
            return;
        }

        const user = data.user;
        statusEl.textContent = user?.displayName || user?.email || "Autenticado";
    } catch {
        statusEl.textContent = "Não foi possível verificar a sessão";
    }
}

loadSession();
