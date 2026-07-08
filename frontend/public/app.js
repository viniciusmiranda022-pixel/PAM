// Portal minimo (Fase 1). Fluxo: login -> lista de assets -> criar sessao ->
// abrir noVNC contra o gateway usando o token efemero no subprotocolo WS.
// O cliente NUNCA conhece IP/host/porta nem a senha do asset (HR-01/05).
import RFB from "/novnc/core/rfb.js";

const $ = (id) => document.getElementById(id);
const views = {
  login: $("login-view"),
  assets: $("assets-view"),
  session: $("session-view"),
};
function show(name) {
  for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
    credentials: "same-origin",
  });
  return res;
}

let rfb = null;
let currentSessionId = null;

async function refreshAssets() {
  const res = await api("/api/v1/assets");
  if (res.status === 401) return show("login");
  const { items } = await res.json();
  const list = $("assets-list");
  list.innerHTML = "";
  if (items.length === 0) {
    list.innerHTML = '<li><div class="empty">Nenhum ativo autorizado.</div></li>';
  }
  for (const a of items) {
    // Cartao do ativo: nome + ambiente + affordance "Conectar". Sem IP, porta,
    // credencial ou token — o usuario comum nunca ve o destino tecnico (HR-01/05).
    const li = document.createElement("li");
    const card = document.createElement("button");
    card.className = "asset-card";
    card.onclick = () => startSession(a.id);

    const main = document.createElement("div");
    main.className = "asset-main";
    const name = document.createElement("span");
    name.className = "asset-name";
    name.textContent = a.name;
    main.append(name);
    if (a.description) {
      const d = document.createElement("span");
      d.className = "asset-desc";
      d.textContent = a.description;
      main.append(d);
    }

    const right = document.createElement("div");
    right.className = "asset-right";
    const env = document.createElement("span");
    env.className = "pill env";
    env.textContent = a.environment;
    const connect = document.createElement("span");
    connect.className = "connect";
    connect.textContent = "Conectar →";
    right.append(env, connect);

    card.append(main, right);
    li.append(card);
    list.append(li);
  }
  await refreshCatalog();
  show("assets");
}

async function startSession(assetId, justification) {
  // A API recebe assetId e, quando o asset exige, uma justificativa (HR-02).
  const body = { assetId };
  if (justification) body.justification = justification;
  const res = await api("/api/v1/sessions", { method: "POST", body: JSON.stringify(body) });
  if (res.status === 422 && !justification) {
    // Asset exige justificativa: pede e tenta de novo.
    const j = prompt("Este ativo exige uma justificativa de acesso:");
    if (j && j.trim().length >= 3) return startSession(assetId, j.trim());
    return;
  }
  if (!res.ok) {
    $("assets-error").textContent = `Falha ao abrir sessão (${res.status}).`;
    return;
  }
  const { sessionId, gatewayUrl, token } = await res.json();
  currentSessionId = sessionId;
  openVnc(gatewayUrl, token);
}

async function refreshCatalog() {
  const [catalog, requests] = await Promise.all([
    (await api("/api/v1/catalog")).json().then((d) => d.items ?? []).catch(() => []),
    (await api("/api/v1/access-requests")).json().then((d) => d.items ?? []).catch(() => []),
  ]);
  const cat = $("catalog-list");
  cat.innerHTML = catalog.length ? "" : "<li class='muted'>Nenhum ativo disponível para solicitação.</li>";
  for (const a of catalog) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = `Solicitar: ${a.name}`;
    btn.onclick = () => requestAccess(a.id, a.name);
    li.append(btn);
    cat.append(li);
  }
  const rl = $("requests-list");
  rl.innerHTML = requests.length ? "" : "<li class='muted'>Nenhuma solicitação.</li>";
  for (const r of requests) {
    const li = document.createElement("li");
    li.textContent = `${r.asset_name} — ${r.status}`;
    rl.append(li);
  }
}

async function requestAccess(assetId, name) {
  const justification = prompt(`Justificativa para solicitar acesso a "${name}":`);
  if (!justification || justification.trim().length < 3) return;
  const res = await api("/api/v1/access-requests", {
    method: "POST",
    body: JSON.stringify({ assetId, justification: justification.trim() }),
  });
  $("catalog-error").textContent = res.ok ? "" : `Falha ao solicitar (${res.status}).`;
  await refreshCatalog();
}

// Atualiza o texto do status e a cor da pill na barra da sessao.
function setSessionState(text, state) {
  $("session-status").textContent = text;
  const bar = document.querySelector("#session-view .session-bar");
  if (bar) bar.className = "session-bar" + (state ? ` ${state}` : "");
}

function openVnc(gatewayUrl, token) {
  show("session");
  setSessionState("conectando…", "");
  const screen = $("screen");
  screen.innerHTML = "";

  // O token viaja no subprotocolo WebSocket (nunca em URL). O gateway faz o
  // handshake None conosco: nao enviamos credencial nenhuma.
  rfb = new RFB(screen, gatewayUrl, {
    wsProtocols: ["binary", `pam.token.${token}`],
  });
  rfb.viewOnly = false;
  rfb.scaleViewport = true;

  rfb.addEventListener("connect", () => {
    setSessionState("conectado", "connected");
  });
  rfb.addEventListener("disconnect", (e) => {
    setSessionState(e.detail?.clean ? "sessão encerrada" : "desconectado", "ended");
  });
  rfb.addEventListener("securityfailure", () => {
    setSessionState("falha de segurança na sessão", "ended");
  });
}

async function endSession() {
  if (rfb) {
    rfb.disconnect();
    rfb = null;
  }
  if (currentSessionId) {
    await api(`/api/v1/sessions/${currentSessionId}`, { method: "DELETE" });
    currentSessionId = null;
  }
  await refreshAssets();
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-error").textContent = "";
  const body = { username: $("username").value, password: $("password").value };
  const totp = $("totp").value.trim();
  if (totp) body.totp = totp;
  const res = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify(body) });
  if (res.status === 204) {
    $("totp-label").hidden = true;
    $("totp").value = "";
    const me = await (await api("/api/v1/auth/me")).json();
    setUser(me);
    await refreshAssets();
    return;
  }
  const err = await res.json().catch(() => ({}));
  if (err.error?.code === "MFA_REQUIRED") {
    // Senha ok na primeira etapa: revela o campo TOTP e pede o código.
    $("totp-label").hidden = false;
    $("totp").focus();
    $("login-error").textContent = "Informe o código do autenticador.";
  } else {
    $("login-error").textContent = "Credenciais inválidas.";
  }
});

// ── MFA (Fase 5.2) ─────────────────────────────────────────────────────────
function renderMfa(enabled) {
  $("mfa-off").hidden = enabled;
  $("mfa-on").hidden = !enabled;
  $("mfa-pending").hidden = true;
  $("mfa-error").textContent = "";
}

$("mfa-setup").addEventListener("click", async () => {
  const res = await api("/api/v1/auth/mfa/setup", { method: "POST" });
  if (!res.ok) { $("mfa-error").textContent = "Falha ao iniciar o setup."; return; }
  const { secret, otpauthUrl } = await res.json();
  $("mfa-secret").textContent = secret;
  $("mfa-url").textContent = otpauthUrl;
  $("mfa-off").hidden = true;
  $("mfa-pending").hidden = false;
});

$("mfa-confirm").addEventListener("click", async () => {
  const res = await api("/api/v1/auth/mfa/enable", {
    method: "POST",
    body: JSON.stringify({ code: $("mfa-code").value.trim() }),
  });
  if (res.status === 204) renderMfa(true);
  else $("mfa-error").textContent = "Código inválido — tente novamente.";
});

$("mfa-disable").addEventListener("click", async () => {
  const res = await api("/api/v1/auth/mfa/disable", {
    method: "POST",
    body: JSON.stringify({ code: $("mfa-code-off").value.trim() }),
  });
  if (res.status === 204) renderMfa(false);
  else $("mfa-error").textContent = "Código inválido — tente novamente.";
});

function setUser(me) {
  $("who").textContent = me.displayName ?? me.username;
  $("admin-link").hidden = me.role !== "admin";
  renderMfa(Boolean(me.mfaEnabled));
}

$("logout").addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST" });
  $("who").textContent = "";
  $("admin-link").hidden = true;
  show("login");
});

$("end-session").addEventListener("click", endSession);

// Botão SSO: aparece só se o backend tiver OIDC configurado.
$("sso-btn").addEventListener("click", () => {
  location.href = "/api/v1/auth/oidc/login";
});
(async () => {
  const cfg = await api("/api/v1/auth/config").then((r) => r.json()).catch(() => ({}));
  $("sso-btn").hidden = !cfg.oidcEnabled;
})();

// Estado inicial: tenta retomar sessao de login existente.
(async () => {
  const res = await api("/api/v1/auth/me");
  if (res.ok) {
    setUser(await res.json());
    await refreshAssets();
  } else {
    show("login");
  }
})();
