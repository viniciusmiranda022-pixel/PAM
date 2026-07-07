// UI administrativa mínima (Fase 2). Consome as rotas /api/v1/admin/*.
// Sem framework: prioriza cobertura funcional, não estética.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const err = (m) => { $("#err").textContent = m || ""; };

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
    credentials: "same-origin",
  });
  return res;
}
async function getJson(path) {
  const r = await api(path);
  return r.ok ? (await r.json()).items ?? [] : [];
}

// Renderiza uma lista de objetos como tabela, com botão opcional de ação.
function table(el, rows, columns, action) {
  if (rows.length === 0) { el.innerHTML = '<p class="muted">vazio</p>'; return; }
  const head = columns.map((c) => `<th>${c.label}</th>`).join("") + (action ? "<th></th>" : "");
  const body = rows.map((row) => {
    const tds = columns.map((c) => `<td>${c.get(row) ?? ""}</td>`).join("");
    const act = action ? `<td><button data-act="${action.name}" data-id="${row[action.idKey]}">${action.label}</button></td>` : "";
    return `<tr>${tds}${act}</tr>`;
  }).join("");
  el.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  if (action) $$("button[data-act]", el).forEach((b) => (b.onclick = () => action.run(b.dataset.id)));
}

const state = { assets: [], users: [], groups: [] };

async function loadAssets() {
  state.assets = await getJson("/api/v1/admin/assets");
  table($('[data-list="assets"]'), state.assets, [
    { label: "Nome", get: (a) => a.name },
    { label: "Ambiente", get: (a) => a.environment },
    { label: "IP", get: (a) => a.ip_address },
    { label: "Porta", get: (a) => a.port },
    { label: "Status", get: (a) => a.status },
  ], { name: "del", label: "Remover", idKey: "id", run: async (id) => {
    if (await api(`/api/v1/admin/assets/${id}`, { method: "DELETE" }).then((r) => r.ok)) refreshAll();
  }});
  fillSelect('[data-select="assets"]', state.assets.map((a) => ({ v: a.id, t: a.name })));
}

async function loadUsers() {
  state.users = await getJson("/api/v1/admin/users");
  table($('[data-list="users"]'), state.users, [
    { label: "Usuário", get: (u) => u.username },
    { label: "Nome", get: (u) => u.display_name },
    { label: "Perfil", get: (u) => u.role },
    { label: "Status", get: (u) => u.status },
    { label: "MFA", get: (u) => (u.mfa_enabled ? "ativo" : "—") },
  ], { name: "mfa-reset", label: "Resetar MFA", idKey: "id", run: async (id) => {
    const r = await api(`/api/v1/admin/users/${id}`, { method: "PATCH", body: JSON.stringify({ mfaReset: true }) });
    if (r.ok) loadUsers(); else err("falha ao resetar MFA");
  }});
}

async function loadGroups() {
  state.groups = await getJson("/api/v1/admin/groups");
  table($('[data-list="groups"]'), state.groups, [
    { label: "Grupo", get: (g) => g.name },
    { label: "Descrição", get: (g) => g.description ?? "" },
    { label: "Membros", get: (g) => g.members },
  ], { name: "del", label: "Remover", idKey: "id", run: async (id) => {
    if (await api(`/api/v1/admin/groups/${id}`, { method: "DELETE" }).then((r) => r.ok)) refreshAll();
  }});
}

async function loadPermissions() {
  const perms = await getJson("/api/v1/admin/permissions");
  table($('[data-list="permissions"]'), perms, [
    { label: "Ativo", get: (p) => p.asset_name },
    { label: "Concedido a", get: (p) => p.username ? `usuário ${p.username}` : `grupo ${p.group_name}` },
  ], { name: "del", label: "Revogar", idKey: "id", run: async (id) => {
    if (await api(`/api/v1/admin/permissions/${id}`, { method: "DELETE" }).then((r) => r.ok)) loadPermissions();
  }});
  updatePrincipals();
}

async function loadAccess() {
  const items = await getJson("/api/v1/admin/access-requests");
  const el = $('[data-list="access"]');
  if (items.length === 0) { el.innerHTML = '<p class="muted">nenhuma solicitação</p>'; return; }
  el.innerHTML = `<table><thead><tr><th>Usuário</th><th>Ativo</th><th>Justificativa</th><th>Status</th><th></th></tr></thead><tbody>${
    items.map((r) => `<tr><td>${r.username}</td><td>${r.asset_name}</td><td>${r.justification}</td><td>${r.status}</td><td>${
      r.status === "pending" ? `<button data-approve="${r.id}">Aprovar</button> <button data-deny="${r.id}">Negar</button>` : ""
    }</td></tr>`).join("")
  }</tbody></table>`;
  $$("button[data-approve]", el).forEach((b) => (b.onclick = async () => {
    const min = Number(prompt("Janela de acesso (minutos):", "60"));
    if (!min || min < 1) return;
    const res = await api(`/api/v1/admin/access-requests/${b.dataset.approve}/approve`, { method: "POST", body: JSON.stringify({ windowMinutes: min }) });
    if (res.ok) loadAccess(); else err("falha ao aprovar");
  }));
  $$("button[data-deny]", el).forEach((b) => (b.onclick = async () => {
    const note = prompt("Motivo (opcional):") ?? undefined;
    const res = await api(`/api/v1/admin/access-requests/${b.dataset.deny}/deny`, { method: "POST", body: JSON.stringify(note ? { note } : {}) });
    if (res.ok) loadAccess(); else err("falha ao negar");
  }));
}

async function loadPorts() {
  const ports = await getJson("/api/v1/admin/allowed-ports");
  table($('[data-list="ports"]'), ports, [
    { label: "Porta", get: (p) => p.port },
    { label: "Descrição", get: (p) => p.description },
  ], { name: "del", label: "Remover", idKey: "port", run: async (port) => {
    const r = await api(`/api/v1/admin/allowed-ports/${port}`, { method: "DELETE" });
    if (r.ok) loadPorts(); else err((await r.json()).error?.message ?? "falha");
  }});
}

async function loadSessions() {
  const sessions = await getJson("/api/v1/admin/sessions");
  table($('[data-list="sessions"]'), sessions, [
    { label: "Usuário", get: (s) => s.username },
    { label: "Ativo", get: (s) => s.asset_name },
    { label: "Status", get: (s) => s.status },
    { label: "Origem", get: (s) => s.client_ip ?? "" },
    { label: "Início", get: (s) => s.started_at ?? "" },
    { label: "Gravação", get: (s) => s.has_recording ? `<a class="link" target="_blank" href="/replay?sessionId=${s.id}">assistir</a>` : "" },
  ], { name: "kill", label: "Encerrar", idKey: "id", run: async (id) => {
    if (await api(`/api/v1/sessions/${id}`, { method: "DELETE" }).then((r) => r.ok)) loadSessions();
  }});
}

async function loadAudit() {
  const logs = await getJson("/api/v1/admin/audit-logs");
  table($('[data-list="audit"]'), logs, [
    { label: "Evento", get: (l) => l.event_type },
    { label: "Origem", get: (l) => l.source_ip ?? "" },
    { label: "Quando", get: (l) => l.created_at },
  ]);
}

function fillSelect(sel, items) {
  const el = $(sel);
  if (!el) return;
  el.innerHTML = items.map((i) => `<option value="${i.v}">${i.t}</option>`).join("");
}
function updatePrincipals() {
  const type = $('[name="principalType"]').value;
  const items = type === "user"
    ? state.users.map((u) => ({ v: u.id, t: u.username }))
    : state.groups.map((g) => ({ v: g.id, t: g.name }));
  fillSelect('[data-select="principals"]', items);
}

async function refreshAll() {
  await Promise.all([loadAssets(), loadUsers(), loadGroups()]);
  await Promise.all([loadPermissions(), loadAccess(), loadPorts(), loadSessions(), loadAudit()]);
}

// Formulários -----------------------------------------------------------
function formData(form) {
  const o = {};
  new FormData(form).forEach((v, k) => (o[k] = v));
  return o;
}
async function submit(form, path, transform) {
  err("");
  const r = await api(path, { method: "POST", body: JSON.stringify(transform(formData(form))) });
  if (r.ok) { form.reset(); refreshAll(); }
  else err((await r.json().catch(() => ({}))).error?.message ?? `falha (${r.status})`);
}

function wireForms() {
  $('[data-form="asset"]').onsubmit = (e) => { e.preventDefault();
    submit(e.target, "/api/v1/admin/assets", (d) => ({
      name: d.name,
      description: d.description || undefined,
      environment: d.environment,
      ipAddress: d.ipAddress,
      port: Number(d.port),
      vncPassword: d.vncPassword,
      recordSessions: d.recordSessions === "on",
      requestable: d.requestable === "on",
      requireJustification: d.requireJustification === "on",
    })); };
  $('[data-form="user"]').onsubmit = (e) => { e.preventDefault();
    submit(e.target, "/api/v1/admin/users", (d) => d); };
  $('[data-form="group"]').onsubmit = (e) => { e.preventDefault();
    submit(e.target, "/api/v1/admin/groups", (d) => ({ name: d.name, description: d.description || undefined })); };
  $('[data-form="port"]').onsubmit = (e) => { e.preventDefault();
    submit(e.target, "/api/v1/admin/allowed-ports", (d) => ({ port: Number(d.port), description: d.description })); };
  $('[data-form="permission"]').onsubmit = (e) => { e.preventDefault();
    const d = formData(e.target);
    const body = d.principalType === "user" ? { assetId: d.assetId, userId: d.principalId } : { assetId: d.assetId, groupId: d.principalId };
    submit(e.target, "/api/v1/admin/permissions", () => body); };
  $('[name="principalType"]').onchange = updatePrincipals;
  $$("[data-refresh]").forEach((b) => (b.onclick = () => {
    if (b.dataset.refresh === "sessions") loadSessions();
    else if (b.dataset.refresh === "audit") loadAudit();
    else if (b.dataset.refresh === "access") loadAccess();
  }));
}

// Abas ------------------------------------------------------------------
function wireTabs() {
  $$("#tabs button").forEach((btn) => (btn.onclick = () => {
    $$("#tabs button").forEach((b) => b.classList.toggle("active", b === btn));
    $$("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== btn.dataset.tab));
  }));
}

(async () => {
  const me = await api("/api/v1/auth/me");
  if (!me.ok) { location.href = "/"; return; }
  const user = await me.json();
  if (user.role !== "admin") { $("#gate").hidden = false; return; }
  $("#who").textContent = user.displayName ?? user.username;
  $("#tabs").hidden = false;
  $("#panels").hidden = false;
  wireTabs();
  wireForms();
  await refreshAll();
})();
