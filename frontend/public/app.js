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
    list.innerHTML = "<li>Nenhum ativo autorizado.</li>";
  }
  for (const a of items) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = `${a.name} — ${a.environment}`;
    btn.onclick = () => startSession(a.id);
    li.append(btn);
    if (a.description) {
      const d = document.createElement("span");
      d.className = "muted";
      d.textContent = ` ${a.description}`;
      li.append(d);
    }
    list.append(li);
  }
  show("assets");
}

async function startSession(assetId) {
  // A API recebe SOMENTE o assetId (HR-02).
  const res = await api("/api/v1/sessions", {
    method: "POST",
    body: JSON.stringify({ assetId }),
  });
  if (!res.ok) {
    $("assets-error").textContent = `Falha ao abrir sessão (${res.status}).`;
    return;
  }
  const { sessionId, gatewayUrl, token } = await res.json();
  currentSessionId = sessionId;
  openVnc(gatewayUrl, token);
}

function openVnc(gatewayUrl, token) {
  show("session");
  $("session-status").textContent = "conectando…";
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
    $("session-status").textContent = "conectado";
  });
  rfb.addEventListener("disconnect", (e) => {
    $("session-status").textContent = e.detail?.clean ? "sessão encerrada" : "desconectado";
  });
  rfb.addEventListener("securityfailure", () => {
    $("session-status").textContent = "falha de segurança na sessão";
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
