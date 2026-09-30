fetch('/api/me')
    .then(res => res.json())
    .then(data => {
        const statusEl = document.getElementById('status');
        if (statusEl) {
            statusEl.textContent = "COOKIE: " + data.cookieRecebido + " | BANCO D1: " + data.temBancoD1;
        }
    })
    .catch(err => {
        const statusEl = document.getElementById('status');
        if (statusEl) statusEl.textContent = "Erro ao carregar: " + err;
    });