"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const icon = (name, className = "") => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("aria-hidden", "true");
    if (className) svg.setAttribute("class", className);
    const use = document.createElementNS(svg.namespaceURI, "use");
    use.setAttribute("href", `/atlas-icons.svg#${name}`);
    svg.append(use);
    return svg;
  };
  const setIcon = (id, name) => $(id).querySelector("use").setAttribute("href", `/atlas-icons.svg#${name}`);
  const preference = (key, value) => { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (_) {} };
  const systemTheme = matchMedia("(prefers-color-scheme: dark)");
  function theme(dark) {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    setIcon("theme-toggle", dark ? "sun" : "moon");
    $("theme-toggle").setAttribute("aria-label", dark ? "Passer au thème clair" : "Passer au thème sombre");
    $("theme-toggle").title = $("theme-toggle").getAttribute("aria-label");
  }
  theme(preference("mysync-theme") ? preference("mysync-theme") === "dark" : systemTheme.matches);
  $("theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme !== "dark";
    preference("mysync-theme", dark ? "dark" : "light"); theme(dark);
  });
  systemTheme.addEventListener("change", event => { if (!preference("mysync-theme")) theme(event.matches); });
  function sidebar(closed) {
    document.body.classList.toggle("sidebar-collapsed", closed);
    $("sidebar").hidden = closed;
    $("sidebar-toggle").setAttribute("aria-expanded", String(!closed));
    $("sidebar-toggle").setAttribute("aria-label", closed ? "Afficher le menu" : "Masquer le menu");
    $("sidebar-toggle").title = $("sidebar-toggle").getAttribute("aria-label");
    setIcon("sidebar-toggle", closed ? "right" : "left");
  }
  sidebar(preference("mysync-sidebar") === "closed" || (matchMedia("(max-width: 1100px)").matches && preference("mysync-sidebar") !== "open"));
  $("sidebar-toggle").addEventListener("click", () => {
    const closed = !document.body.classList.contains("sidebar-collapsed");
    sidebar(closed); preference("mysync-sidebar", closed ? "closed" : "open");
  });
  const statusPage = location.pathname === "/status";
  const editorPage = location.pathname === "/editor";
  let codeEditor;
  document.body.classList.toggle("code-editor-page", editorPage);
  if (editorPage) sidebar(true);
  $(statusPage ? "status-nav" : "files-nav").setAttribute("aria-current", "page");
  $("status-panel").hidden = !statusPage;
  $("search-box").hidden = statusPage || editorPage;
  $("editor-navigation").hidden = !editorPage;
  $("toolbar-title").hidden = !statusPage;
  $("access").hidden = statusPage;
  document.title = `${statusPage ? "Statut local" : "Fichiers"} · MySyncFiles`;

  class Failure extends Error { constructor(code) { super(code); this.code = code; } }
  async function bytes(response, limit) {
    if (!response.body) throw new Failure("invalid_response");
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    try {
      for (;;) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) throw new Failure("invalid_response");
        chunks.push(value);
      }
      const value = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { value.set(chunk, offset); offset += chunk.length; }
      return value;
    } finally { await reader.cancel().catch(() => {}); }
  }
  async function request(url, {signal, local = false, limit = 4096, timeout = 15000, raw = false, ...options} = {}) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener("abort", abort, {once: true});
    const timer = setTimeout(abort, timeout);
    try {
      const response = await fetch(url, {cache: "no-store", redirect: "error", credentials: local ? "omit" : "same-origin", ...options,
        headers: local ? options.headers : {"X-MySync-Web": "1", ...options.headers}, signal: controller.signal});
      const body = await bytes(response, limit);
      if (raw && response.ok) return body;
      const data = JSON.parse(new TextDecoder().decode(body));
      if (!local && (!response.ok || response.status === 202)) throw new Failure(data.error || "invalid_response");
      return local ? {response, data} : data;
    } finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  const post = (url, signal) => request(url, {method: "POST", signal, headers: {"Content-Type": "application/json"}, body: "{}"});
  let session, expiry, renewalTimer, renewal, listingRequest, verification, transfer;
  const renewAhead = 5 * 60 * 1000;
  let automatic = preference("mysync-auto-access") !== "off";
  const autoAccess = () => automatic && preference("mysync-auto-access") !== "off";
  const setAutoAccess = enabled => { automatic = enabled; preference("mysync-auto-access", enabled ? "on" : "off"); };
  let upload, pickerContext, dragDepth = 0, dragCancelled = false;
  let directory = "", search = "", cursors = [""], pageIndex = 0, next;
  let displayedQuery, displayedEntries, retryView;
  let selected, selectedButton, menuEntry, menuButton, searchTimer, toastTimer, detailsTimer, folderAction, folderRequest;
  let epoch = 0;
  let channel;
  try { channel = new BroadcastChannel("mysync-files"); channel.onmessage = event => { if (event.data === "logout") { automatic = false; lock("expired"); } }; } catch (_) {}
  const menu = $("file-menu");
  const messages = {
    initial: ["Vérifier cet appareil", "Le client MySyncFiles doit être lancé sur ce PC. Le navigateur peut demander l’autorisation d’accéder à cet appareil.", "Vérifier cet appareil", "laptop"],
    expired: ["Session expirée", "L’accès automatique n’a pas pu être renouvelé. Vérifiez que le client MySyncFiles est lancé et que cet appareil est toujours autorisé.", "Réessayer", "clock"],
    denied: ["Permission d’accès local refusée", "Le navigateur a bloqué l’accès au client MySyncFiles sur ce PC. Autorisez l’accès à cet appareil dans les permissions du site, puis réessayez.", "Réessayer", "warning"],
    disabled: ["Lecture des fichiers non autorisée", "Autorisez la lecture web sur le client de cet appareil avec mysync web-files enable, puis relancez le daemon.", "Réessayer", "warning"],
    rejected: ["Vérification locale refusée", "Vérifiez que le client installé prend en charge la lecture web, puis redémarrez son service. Vérifiez aussi qu’il utilise le même serveur et que l’horloge du PC est correcte.", "Réessayer", "warning"],
    unavailable: ["Client local inaccessible", "Vérifiez que le daemon MySyncFiles est lancé, que le pont local est activé et que le navigateur autorise l’accès à cet appareil.", "Réessayer", "laptop"]
  };
  function access(state, message = "") {
    const [title, description, label, glyph] = messages[state] || messages.initial;
    $("access").dataset.state = state;
    $("access-title").textContent = title;
    $("access-description").textContent = description;
    $("file-verify").textContent = label;
    $("access-message").textContent = message;
    $("access-note").hidden = state === "expired" || state === "denied";
    $("access-help").hidden = state === "expired";
    setIcon("access-icon", glyph);
    $("access-icon").classList.remove("busy-icon");
    $("session-label").textContent = state === "expired" ? "Session expirée" : state === "denied" || state === "disabled" ? "Accès bloqué" : "Accès non vérifié";
    $("session-dot").className = `session-dot${state === "denied" || state === "disabled" ? " blocked" : ""}`;
  }
  function closeMenu(focus = false) {
    menu.hidden = true;
    menuButton?.setAttribute("aria-expanded", "false");
    if (focus && menuButton?.isConnected) menuButton.focus();
    menuEntry = undefined; menuButton = undefined;
  }
  function closeDetails(focus = false) {
    clearTimeout(detailsTimer);
    $("details").hidden = true;
    $("details-dismiss").hidden = true;
    document.querySelector(".file-list").inert = false;
    for (const id of ["detail-name", "detail-path", "detail-size", "detail-modified", "detail-revision", "detail-hash"]) $(id).textContent = "";
    document.querySelectorAll("tr.selected").forEach(row => row.classList.remove("selected"));
    selectedButton?.setAttribute("aria-expanded", "false");
    if (selected?.kind === "directory") selectedButton?.setAttribute("aria-pressed", "false");
    if (focus && selectedButton?.isConnected) selectedButton.focus();
    selected = undefined; selectedButton = undefined;
    updateUploadButton();
  }
  function hideToast() { clearTimeout(toastTimer); $("toast").hidden = true; $("toast-message").textContent = ""; }
  function lock(state = "initial", message = "") {
    epoch++;
    folderRequest?.abort(); $("folder-dialog").close(); folderAction = undefined;
    session = undefined;
    clearTimeout(expiry); clearTimeout(renewalTimer); clearTimeout(searchTimer);
    listingRequest?.abort(); verification?.abort(); renewal?.abort(); transfer?.abort(); upload?.abort();
    clearDrop(); dragCancelled = false; pickerContext = undefined; $("upload-input").value = "";
    $("upload-status").hidden = true; $("upload-results").replaceChildren();
    $("upload-message").textContent = ""; $("upload-destination").textContent = "";
    listingRequest = undefined; displayedQuery = undefined; displayedEntries = undefined; retryView = undefined;
    listingBusy(false);
    closeMenu(); closeDetails(); hideToast();
    $("rows").replaceChildren(); $("breadcrumbs").replaceChildren();
    $("count").textContent = ""; $("listing-title").textContent = "Tous les fichiers";
    $("listing-title").removeAttribute("title");
    $("listing-message").textContent = ""; $("listing-message").hidden = true;
    $("search").value = ""; $("search").disabled = true; $("clear-search").hidden = true;
    $("explorer").hidden = true; $("access").hidden = statusPage;
    $("logout").hidden = true; $("session-time").textContent = "";
    $("refresh").hidden = true;
    directory = ""; search = ""; cursors = [""]; pageIndex = 0; next = undefined;
    $("file-verify").disabled = false; $("file-cancel").hidden = true;
    access(state, message);
    if (editorPage && codeEditor) {
      const draft = codeEditor.lock();
      $("code-editor").hidden = !draft;
      if (draft) $("access").hidden = true;
    }
  }
  function acceptSession(value) {
    if (!Number.isSafeInteger(value.expires_at) || typeof value.device_name !== "string" || value.device_name.length > 512 ||
        value.chunk_bytes !== 8388608 || value.download_limit !== 268435456) throw new Failure("invalid_response");
    const remaining = Math.min(1800000, value.expires_at * 1000 - Date.now());
    if (remaining <= 0) throw new Failure("session_expired");
    session = value;
    clearTimeout(expiry); clearTimeout(renewalTimer);
    expiry = setTimeout(() => lock("expired"), remaining);
    const renewIn = Number.isSafeInteger(value.renew_at) ? value.renew_at * 1000 - Date.now() : remaining - renewAhead;
    if (!statusPage) renewalTimer = setTimeout(renewSession, Math.max(1000, Math.min(remaining - renewAhead, renewIn)));
    $("session-time").textContent = "Accès automatique";
    $("session-dot").className = "session-dot verified";
    $("session-label").textContent = "Appareil reconnu";
    $("logout").hidden = false;
    if (editorPage) { $("access").hidden = true; $("code-editor").hidden = false; }
    else if (!statusPage) { $("access").hidden = true; $("explorer").hidden = false; $("search").disabled = false; $("refresh").hidden = false; }
  }
  async function restore() {
    if (statusPage || !autoAccess()) return;
    const current = epoch;
    try {
      const value = await request("/v1/web/files/session");
      if (epoch !== current) return;
      acceptSession(value);
      if (editorPage) await codeEditor.open();
      else if (!statusPage) {
        const folder = new URLSearchParams(location.search).get("directory") || "";
        await load({...currentView(), directory: folder});
      }
    } catch (error) {
      if (epoch === current && autoAccess() && ["session_expired", "authentication_refused"].includes(error.code)) await verify();
    }
  }
  async function prove(base, signal) {
    const challenge = await post(`${base}/challenges`, signal);
    if (!/^[a-f0-9]{64}$/.test(challenge.challenge_id) || typeof challenge.ticket !== "string" || challenge.ticket.length > 2048) throw new Failure("invalid_response");
    let localError;
    try {
      const local = await request("http://127.0.0.1:47831/v1/status", {local: true, signal, timeout: 10000,
        headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": challenge.ticket}});
      if (!local.response.ok) localError = local.data.error;
    } catch (_) { /* A lost acknowledgement can follow a committed TPM proof. */ }
    if (signal.aborted) throw new Failure("cancelled");
    try { return await request(`${base}/challenges/${challenge.challenge_id}`, {signal, timeout: 3000}); }
    catch (error) {
      if (error.code === "pending" && localError) throw new Failure(localError === "invalid_challenge" ? "local_rejected" : localError);
      throw error;
    }
  }
  async function renewSession() {
    if (!session || renewal || verification || !autoAccess()) return;
    const controller = new AbortController(); renewal = controller;
    const {signal} = controller, current = epoch;
    const renew = async () => {
      // A sibling tab may already have renewed the shared cookie and grants.
      const value = await request("/v1/web/files/session", {signal});
      if (signal.aborted || current !== epoch || !autoAccess()) return;
      const renewAt = Number.isSafeInteger(value.renew_at) ? value.renew_at * 1000 : value.expires_at * 1000 - renewAhead;
      if (renewAt > Date.now() + 1000) { acceptSession(value); return; }
      const scopes = [];
      for (const base of ["/v1/web/files/write", "/v1/web/files/manage", "/v1/web/editor/edit", "/v1/web/editor/run"]) {
        try { await request(`${base}/session`, {signal}); scopes.push(base); }
        catch (error) {
          if (!["files_write_required", "files_manage_required", "files_edit_required", "code_run_required", "invalid_scope", "not_found"].includes(error.code)) throw error;
        }
      }
      const renewed = value.expires_at * 1000 - Date.now() <= renewAhead + 1000 ? await prove("/v1/web/files", signal) : value;
      if (signal.aborted || current !== epoch || !autoAccess()) return;
      acceptSession(renewed);
      // Each existing capability needs its own fresh proof. Read authority
      // alone never renews upload, management, editing or execution consent.
      let failure;
      for (const base of scopes) {
        if (signal.aborted || current !== epoch || !autoAccess()) return;
        try { await prove(base, signal); } catch (error) { failure ||= error; }
      }
      const complete = await request("/v1/web/files/session", {signal});
      if (!signal.aborted && current === epoch && autoAccess()) acceptSession(complete);
      if (failure) throw failure;
    };
    try {
      if (navigator.locks) await navigator.locks.request("mysync-files-renew", {signal}, renew);
      else await renew();
    } catch (error) {
      if (signal.aborted || current !== epoch) return;
      if (["session_expired", "authentication_refused"].includes(error.code)) { lock("expired"); return; }
      // Keep the still-authorized view and retry transient failures. The hard
      // server deadline and local expiry timer remain in force.
      clearTimeout(renewalTimer);
      renewalTimer = setTimeout(renewSession, 60000);
    } finally { if (renewal === controller) renewal = undefined; }
  }
  async function denied() {
    if (!navigator.permissions) return false;
    for (const name of ["loopback-network", "local-network-access"]) {
      try { if ((await navigator.permissions.query({name})).state === "denied") return true; } catch (_) {}
    }
    return false;
  }
  async function verify() {
    if (verification) return;
    const controller = new AbortController(); verification = controller;
    const current = epoch;
    let userCancelled = false, stage = "local";
    const cancel = () => { userCancelled = true; setAutoAccess(false); controller.abort(); };
    $("file-cancel").onclick = cancel;
    $("file-verify").disabled = true; $("file-verify").textContent = "Vérification…"; $("file-cancel").hidden = false;
    $("access-message").textContent = "Vérification en cours…";
    setIcon("access-icon", "spinner"); $("access-icon").classList.add("busy-icon");
    const waiting = setTimeout(() => { if (current === epoch) $("access-message").textContent = "En attente de l’accès local. Vérifiez les demandes d’autorisation du navigateur."; }, 3000);
    try {
      const localURL = "http://127.0.0.1:47831/v1/status";
      const probe = await request(localURL, {local: true, signal: controller.signal, timeout: 30000, headers: {"X-MySync-Bridge": "1"}});
      if (probe.response.status !== 401 || probe.data.error !== "challenge_required") throw new Failure("local_unverified");
      clearTimeout(waiting); stage = "server";
      await post("/v1/web/files/session", controller.signal);
      $("access-message").textContent = "Vérification de l’autorisation de lecture…";
      const value = await prove("/v1/web/files", controller.signal);
      if (current !== epoch || controller.signal.aborted) return;
      acceptSession(value);
      if (editorPage) await codeEditor.open();
      else await load({...currentView(), directory: new URLSearchParams(location.search).get("directory") || ""});
    } catch (error) {
      if (current !== epoch) return;
      if (userCancelled) {
        access("initial", "Vérification annulée.");
        await post("/v1/web/files/logout").catch(() => {});
      } else if (stage === "local" && await denied()) access("denied");
      else if (error.code === "files_read_disabled") access("disabled");
      else if (error.code === "local_rejected") access("rejected");
      else if (stage === "local") access("unavailable");
      else access("initial", error.code === "challenge_limit" || error.code === "status_busy" ? "Trop de vérifications rapprochées. Attendez une minute avant de réessayer." : "Autorisation non confirmée par le serveur. Vérifiez la connexion, l’approbation de l’appareil et l’activation de la lecture web.");
    } finally {
      clearTimeout(waiting);
      if (verification === controller) verification = undefined;
      if (current === epoch) {
        $("file-verify").disabled = false; $("file-cancel").hidden = true;
        $("file-verify").textContent = "Réessayer";
        $("access-icon").classList.remove("busy-icon");
        if ($("access-icon").querySelector("use").getAttribute("href").endsWith("#spinner")) setIcon("access-icon", "laptop");
      }
    }
  }
  $("file-verify").addEventListener("click", () => { setAutoAccess(true); verify(); });
  $("logout").addEventListener("click", async () => {
    setAutoAccess(false);
    lock("initial", "Déconnexion en cours…");
    $("file-verify").disabled = true;
    try { await post("/v1/web/files/logout"); channel?.postMessage("logout"); access("initial", "Vous êtes déconnecté."); }
    catch (_) { access("initial", "Déconnexion serveur non confirmée. Réessayez lorsque la connexion est rétablie."); $("logout").hidden = false; }
    finally { $("file-verify").disabled = false; }
  });
  const basename = path => path.split("/").pop();
  const kindIcon = entry => entry.kind === "directory" ? "directory" : /\.pdf$/i.test(entry.path) ? "pdf" : /\.(toml|json|lock|rs|js|ya?ml|xml)$/i.test(entry.path) ? "code" : "file";
  function size(value) {
    if (value === null) return "—";
    const units = ["o", "Ko", "Mo", "Go", "To", "Po"]; let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
    return `${new Intl.NumberFormat("fr-FR", {maximumFractionDigits: value < 10 && index ? 1 : 0}).format(value)} ${units[index]}`;
  }
  const dateFormat = new Intl.DateTimeFormat("fr-FR", {dateStyle: "short"});
  const hourFormat = new Intl.DateTimeFormat("fr-FR", {timeStyle: "short"});
  const fullDateFormat = new Intl.DateTimeFormat("fr-FR", {dateStyle: "long", timeStyle: "long"});
  function modifiedTime(value, full = false) {
    if (value == null) return document.createTextNode("—");
    const date = new Date(value * 1000);
    const time = document.createElement("time");
    time.dateTime = date.toISOString();
    time.title = `Enregistrée sur le serveur le ${fullDateFormat.format(date)}`;
    if (full) time.textContent = fullDateFormat.format(date);
    else {
      time.className = "modified-time";
      const day = document.createElement("span"); day.textContent = dateFormat.format(date);
      const hour = document.createElement("span"); hour.className = "modified-hour"; hour.textContent = hourFormat.format(date);
      time.append(day, " ", hour);
    }
    return time;
  }
  function highlighted(node, text) {
    const start = search ? text.toLocaleLowerCase("fr").indexOf(search.toLocaleLowerCase("fr")) : -1;
    if (start < 0) { node.textContent = text; return; }
    node.append(document.createTextNode(text.slice(0, start)));
    const mark = document.createElement("mark"); mark.textContent = text.slice(start, start + search.length);
    node.append(mark, document.createTextNode(text.slice(start + search.length)));
  }
  function breadcrumbs() {
    const root = $("breadcrumbs"); root.replaceChildren();
    const add = (name, path) => {
      if (root.childNodes.length) { const divider = document.createElement("span"); divider.textContent = "/"; divider.setAttribute("aria-hidden", "true"); root.append(divider); }
      const button = document.createElement("button"); button.type = "button"; button.textContent = name;
      button.title = path || "Tous les fichiers";
      button.addEventListener("click", () => navigate(path)); root.append(button);
    };
    add("Fichiers", "");
    if (search) { const label = document.createElement("span"); label.textContent = "/ Recherche"; root.append(label); }
    else { let path = ""; for (const part of directory.split("/").filter(Boolean)) { path += (path ? "/" : "") + part; add(part, path); } }
    root.lastElementChild.setAttribute("aria-current", "page");
    root.scrollLeft = root.scrollWidth;
  }
  function navigate(path) {
    clearTimeout(searchTimer);
    if (displayedQuery && path === directory && !search && !listingRequest && !retryView) return;
    $("search").value = ""; $("clear-search").hidden = true;
    load({directory: path, search: "", pageIndex: 0, cursors: [""]});
  }
  for (const link of [$("files-nav"), document.querySelector(".brand")]) link.addEventListener("click", event => {
    if (!statusPage && !editorPage && session && event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
      event.preventDefault(); navigate("");
    }
  });
  function validateEntry(entry) {
    return entry && ["directory", "file"].includes(entry.kind) && typeof entry.path === "string" && entry.path.length > 0 && entry.path.length <= 8192 &&
      (Number.isSafeInteger(entry.size) && entry.size >= 0 || entry.kind === "directory" && entry.size === null) &&
      (entry.updated_at == null || Number.isSafeInteger(entry.updated_at) && entry.updated_at >= 0 && entry.updated_at <= 8640000000000) &&
      (entry.kind === "directory" || (Number.isSafeInteger(entry.revision) && entry.revision > 0 && /^[a-f0-9]{64}$/.test(entry.sha256)));
  }
  const currentView = () => ({directory, search, pageIndex, cursors: [...cursors]});
  function listingBusy(busy) {
    clearDrop(); updateUploadButton();
    $("file-table").setAttribute("aria-busy", String(busy));
    $("refresh").setAttribute("aria-disabled", String(busy));
    $("previous-page").setAttribute("aria-disabled", String(busy)); $("next-page").setAttribute("aria-disabled", String(busy));
    if (!busy) { $("refresh").classList.remove("is-loading"); $("listing-status").textContent = ""; }
  }
  async function load(view = currentView()) {
    if (!session) return;
    clearTimeout(detailsTimer);
    listingRequest?.abort(); closeMenu();
    const controller = new AbortController(); listingRequest = controller;
    const current = epoch;
    retryView = view;
    listingBusy(true);
    if (!displayedQuery) { $("count").textContent = "Chargement des fichiers…"; $("empty").hidden = true; $("file-table").hidden = false; }
    const waiting = setTimeout(() => {
      if (listingRequest === controller && !controller.signal.aborted) {
        $("refresh").classList.add("is-loading"); $("listing-status").textContent = displayedQuery ? "Chargement des fichiers…" : "";
      }
    }, 180);
    try {
      const params = new URLSearchParams({directory: view.search ? "" : view.directory, search: view.search, after: view.cursors[view.pageIndex]});
      const query = params.toString();
      const value = await request(`/v1/web/files/entries?${params}`, {signal: controller.signal, limit: 12 * 1024 * 1024});
      if (current !== epoch || controller.signal.aborted) return;
      if (!Array.isArray(value.entries) || value.entries.length > 200 || !value.entries.every(validateEntry) || (value.next !== null && (typeof value.next !== "string" || value.next.length > 8194))) throw new Failure("invalid_response");
      const sameView = query === displayedQuery;
      const sameEntries = sameView && value.entries.length === displayedEntries.length && value.entries.every((entry, index) =>
        ["kind", "path", "size", "revision", "sha256", "updated_at"].every(key => entry[key] === displayedEntries[index][key]));
      const active = document.activeElement;
      const focusInListing = $("rows").contains(active) || $("breadcrumbs").contains(active);
      if (!sameView) closeDetails();
      ({directory, search, pageIndex, cursors} = view);
      next = value.next;
      retryView = undefined;
      $("search").value = search; $("clear-search").hidden = !search;
      if (!sameView) {
        breadcrumbs(); $("listing-title").textContent = search ? "Résultats de recherche" : directory ? basename(directory) : "Tous les fichiers";
        $("listing-title").title = search ? `Recherche : ${search}` : directory || "Tous les fichiers";
      }
      $("listing-message").hidden = true;
      const count = value.entries.length;
      $("count").textContent = `${count}${next ? "+" : ""} ${search ? `fichier${count === 1 ? "" : "s"} trouvé${count === 1 ? "" : "s"}` : `élément${count === 1 ? "" : "s"}`}${pageIndex ? ` · page ${pageIndex + 1}` : ""}`;
      if (!sameEntries) {
        const rows = document.createDocumentFragment();
        for (const entry of value.entries) {
          const row = document.createElement("tr");
          if (search) row.classList.add("search-row");
          const nameCell = document.createElement("td");
          const button = document.createElement("button"); button.type = "button"; button.className = "entry-button"; button.title = entry.path;
          button.setAttribute("aria-controls", "details"); button.setAttribute("aria-expanded", "false");
          if (entry.kind === "directory") button.setAttribute("aria-pressed", "false");
          const text = document.createElement("span"); text.className = "entry-text";
          const name = document.createElement("span"); name.className = "entry-name"; highlighted(name, basename(entry.path)); text.append(name);
          if (search) { const path = document.createElement("span"); path.className = "entry-path"; highlighted(path, entry.path); text.append(path); }
          button.append(icon(kindIcon(entry), `file-icon ${kindIcon(entry)}`), text);
          const selectEntry = event => {
            clearTimeout(detailsTimer);
            if (entry.kind === "directory") { selectDirectory(entry, button); return; }
            // Leave time for the second click before the narrow-screen details
            // overlay makes the file list inert. Keyboard activation is immediate.
            if (/\.(pdf|py|c)$/i.test(entry.path) && event.detail && matchMedia("(max-width: 1100px)").matches) {
              const current = epoch;
              detailsTimer = setTimeout(() => { if (current === epoch && session && button.isConnected) details(entry, button); }, 500);
            } else details(entry, button);
          };
          button.addEventListener("click", selectEntry);
          if (editable(entry)) row.addEventListener("dblclick", event => {
            if (!event.target.closest("button") || button.contains(event.target)) openEditor(entry);
          });
          if (entry.kind === "directory") {
            button.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); navigate(entry.path); } });
            row.addEventListener("dblclick", event => { if (!event.target.closest("button") || button.contains(event.target)) navigate(entry.path); });
          }
          row.addEventListener("click", event => { if (!event.target.closest("button") && !getSelection()?.toString()) selectEntry(event); });
          if (entry.kind === "file" && /\.pdf$/i.test(entry.path)) row.addEventListener("dblclick", event => {
            if (event.target.closest("button") && !button.contains(event.target)) return;
            clearTimeout(detailsTimer);
            if (!session) return;
            if (entry.size > session.download_limit) { toast("Ce fichier dépasse la limite web de 256 Mio. Retrouvez-le dans votre dossier synchronisé."); return; }
            const query = new URLSearchParams({path: entry.path, revision: String(entry.revision)});
            window.open(`/v1/web/files/pdf?${query}`, "_blank", "noopener,noreferrer");
          });
          nameCell.append(button); row.append(nameCell);
          const sizeCell = document.createElement("td"); sizeCell.textContent = size(entry.size);
          if (entry.kind === "directory") sizeCell.className = "folder-meta";
          const modifiedCell = document.createElement("td"); modifiedCell.append(modifiedTime(entry.updated_at));
          row.append(sizeCell, modifiedCell);
          const actions = document.createElement("td");
          {
            const more = document.createElement("button"); more.type = "button"; more.className = "more-button";
            more.setAttribute("aria-label", `Actions pour ${basename(entry.path)}`); more.setAttribute("aria-haspopup", "menu"); more.setAttribute("aria-expanded", "false"); more.setAttribute("aria-controls", "file-menu"); more.append(icon("more"));
            more.addEventListener("click", () => openMenu(entry, more)); actions.append(more);
          }
          row.append(actions); rows.append(row);
        }
        $("rows").replaceChildren(rows);
        if (selected) {
          const index = value.entries.findIndex(entry => entry.kind === selected.kind && entry.path === selected.path);
          if (index < 0) closeDetails();
          else if (selected.kind === "directory" && $("details").hidden) selectDirectory(value.entries[index], $("rows").children[index].querySelector(".entry-button"));
          else {
            const entry = value.entries[index], button = $("rows").children[index].querySelector(".entry-button");
            details(entry, button, false);
            if (entry.kind === "directory") {
              directoryInfo(entry).then(info => { if (current === epoch && selected?.path === entry.path && button.isConnected && !$("details").hidden) details({...entry, ...info}, button, false); }).catch(error => { if (current === epoch && error.code === "session_expired") lock("expired"); });
            }
          }
        }
      }
      displayedQuery = query;
      if (!sameEntries) displayedEntries = value.entries;
      $("file-table").hidden = !count;
      $("empty").hidden = Boolean(count);
      $("empty-title").textContent = search ? "Aucun résultat" : "Aucun fichier pour le moment";
      $("empty-description").textContent = search ? "Essayez un autre nom ou un autre chemin de fichier." : "Vos fichiers apparaîtront ici après la première synchronisation.";
      $("empty-reset").hidden = !search;
      $("previous-page").hidden = pageIndex === 0; $("next-page").hidden = !next;
      if (!sameView && (focusInListing || active?.closest(".pagination") && active.hidden)) $("listing-title").focus({preventScroll: true});
    } catch (error) {
      if (controller.signal.aborted || current !== epoch) return;
      if (error.code === "session_expired" || error.code === "authentication_refused") { lock("expired"); return; }
      if (!displayedQuery) $("count").textContent = "Liste indisponible";
      $("listing-message").hidden = false;
      $("listing-message").textContent = `Impossible de charger les fichiers.${displayedQuery ? " La liste précédente est conservée." : ""} Réessayez avec le bouton d’actualisation en haut de la page.`;
    } finally {
      clearTimeout(waiting);
      if (listingRequest === controller) { listingRequest = undefined; listingBusy(false); }
    }
  }
  function details(entry, button, focus = true) {
    closeMenu(); closeDetails(); selected = entry; selectedButton = button;
    button.closest("tr")?.classList.add("selected");
    button.setAttribute("aria-expanded", "true");
    const folder = entry.kind === "directory";
    if (folder) button.setAttribute("aria-pressed", "true");
    $("detail-heading").textContent = folder ? "Propriétés du dossier" : "Détails du fichier";
    $("detail-download").hidden = folder; $("detail-open").hidden = !folder;
    $("detail-edit").hidden = !editable(entry);
    $("detail-revision-row").hidden = folder; $("detail-hash-row").hidden = folder; $("detail-count-row").hidden = !folder;
    $("detail-count").textContent = entry.file_count ?? "—";
    $("detail-name").textContent = basename(entry.path); $("detail-path").textContent = entry.path;
    $("detail-size").textContent = size(entry.size); $("detail-revision").textContent = entry.revision ?? ""; $("detail-hash").textContent = entry.sha256 ?? "";
    $("detail-modified").replaceChildren(modifiedTime(entry.updated_at, true));
    $("detail-icon").setAttribute("class", `detail-icon ${kindIcon(entry)}`); setIcon("detail-icon", kindIcon(entry));
    $("details").hidden = false;
    detailsLayout();
    if (focus) { document.querySelector(".details-content").scrollTop = 0; $("details").focus({preventScroll: true}); }
  }
  function selectDirectory(entry, button) {
    closeDetails(); selected = entry; selectedButton = button;
    button.closest("tr")?.classList.add("selected"); button.setAttribute("aria-pressed", "true");
  }
  async function directoryInfo(entry, signal) {
    const value = await request(`/v1/web/files/directories?${new URLSearchParams({path: entry.path})}`, {signal, limit: 32768});
    if (value.path !== entry.path || !Number.isSafeInteger(value.size) || value.size < 0 || !Number.isSafeInteger(value.file_count) || value.file_count < 1 ||
        !Number.isSafeInteger(value.updated_at) || value.updated_at < 0 || value.updated_at > 8640000000000 || (value.snapshot !== null && !/^[a-f0-9]{64}$/.test(value.snapshot))) throw new Failure("invalid_response");
    return value;
  }
  function detailsLayout() {
    const overlay = !$("details").hidden && matchMedia("(max-width: 1100px)").matches;
    document.querySelector(".file-list").inert = overlay;
    $("details-dismiss").hidden = !overlay;
    clearDrop(); updateUploadButton();
  }
  function openMenu(entry, button) {
    if (menuButton === button) { closeMenu(true); return; }
    closeMenu(); menuEntry = entry; menuButton = button;
    const folder = entry.kind === "directory";
    if (folder) selectDirectory(entry, button.closest("tr").querySelector(".entry-button"));
    menu.setAttribute("aria-label", folder ? "Actions du dossier" : "Actions du fichier");
    for (const action of ["open", "rename", "delete"]) menu.querySelector(`[data-action="${action}"]`).hidden = !folder;
    menu.querySelector('[data-action="download"]').hidden = folder;
    menu.querySelector('[data-action="copy"]').hidden = folder;
    menu.querySelector('[data-action="edit"]').hidden = !editable(entry);
    menu.querySelector('[data-action="details"]').lastChild.textContent = folder ? "Propriétés" : "Voir les détails";
    for (const action of ["rename", "delete"]) { const control = menu.querySelector(`[data-action="${action}"]`); control.disabled = !session?.manage_limit; control.title = control.disabled ? "La gestion nécessite une mise à jour du serveur" : ""; }
    menu.hidden = false; button.setAttribute("aria-expanded", "true");
    const rect = button.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(innerWidth - menu.offsetWidth - 8, rect.right - menu.offsetWidth))}px`;
    menu.style.top = `${Math.max(8, rect.bottom + menu.offsetHeight + 8 > innerHeight ? rect.top - menu.offsetHeight - 4 : rect.bottom + 4)}px`;
    menu.querySelector("button:not([hidden]):not(:disabled)").focus();
  }
  menu.addEventListener("keydown", event => {
    const buttons = [...menu.querySelectorAll("button:not([hidden]):not(:disabled)")];
    const index = buttons.indexOf(document.activeElement);
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      buttons[event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
    } else if (event.key === "Tab") { event.preventDefault(); closeMenu(true); }
  });
  menu.addEventListener("click", async event => {
    const action = event.target.closest("button")?.dataset.action;
    const entry = menuEntry, button = menuButton;
    if (!entry || !action) return;
    closeMenu(true);
    if (action === "open") navigate(entry.path);
    if (action === "edit") openEditor(entry);
    if (action === "details") {
      const current = epoch;
      try {
        const info = entry.kind === "directory" ? await directoryInfo(entry) : {};
        if (current === epoch && session && button.isConnected && (entry.kind !== "directory" || selected?.path === entry.path)) details({...entry, ...info}, button.closest("tr").querySelector(".entry-button"));
      } catch (error) { if (current === epoch && session) { if (error.code === "session_expired") lock("expired"); else toast("Propriétés indisponibles. Actualisez la liste et réessayez."); } }
    }
    if (["rename", "delete"].includes(action)) editDirectory(entry, action);
    if (action === "download") download(entry);
    if (action === "copy") {
      const current = epoch;
      try { await navigator.clipboard.writeText(entry.path); if (current === epoch && session) toast("Chemin copié."); }
      catch (_) { if (current === epoch && session) { details(entry, button.closest("tr").querySelector(".entry-button")); toast("Copie indisponible. Le chemin complet est affiché dans les détails."); } }
    }
  });
  document.addEventListener("pointerdown", event => { if (!menu.contains(event.target) && !menuButton?.contains(event.target)) closeMenu(); });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    if (!menu.hidden) { closeMenu(true); event.preventDefault(); }
    else if (!$("details").hidden) { closeDetails(true); event.preventDefault(); }
    else if (matchMedia("(max-width: 760px)").matches && !$("sidebar").hidden) { sidebar(true); $("sidebar-toggle").focus(); }
  });
  addEventListener("resize", () => {
    closeMenu(true);
    detailsLayout();
  });
  addEventListener("scroll", () => closeMenu(), true);
  $("details-close").addEventListener("click", () => closeDetails(true));
  $("details-dismiss").addEventListener("click", () => closeDetails(true));
  $("detail-download").addEventListener("click", () => { if (selected) download(selected); });
  $("detail-open").addEventListener("click", () => { if (selected?.kind === "directory") navigate(selected.path); });
  $("detail-edit").addEventListener("click", () => { if (selected) openEditor(selected); });
  function editable(entry) { return entry?.kind === "file" && /\.(py|c)$/i.test(entry.path); }
  function openEditor(entry) {
    clearTimeout(detailsTimer);
    if (!session || !editable(entry)) return;
    if (upload || transfer) { toast("Attendez la fin du transfert avant d’ouvrir l’éditeur."); return; }
    if (entry.size > 262144) { toast("L’éditeur accepte les fichiers jusqu’à 256 Kio."); return; }
    location.assign(`/editor?${new URLSearchParams({path: entry.path, directory})}`);
  }
  $("refresh").addEventListener("click", () => { if (!listingRequest) { clearTimeout(searchTimer); load(retryView || currentView()); } });
  $("next-page").addEventListener("click", () => { if (next && !listingRequest) load({...currentView(), pageIndex: pageIndex + 1, cursors: [...cursors.slice(0, pageIndex + 1), next]}); });
  $("previous-page").addEventListener("click", () => { if (pageIndex && !listingRequest) load({...currentView(), pageIndex: pageIndex - 1}); });
  const searchChanged = () => {
    if (!session) return;
    clearTimeout(detailsTimer);
    clearTimeout(searchTimer); listingRequest?.abort(); closeMenu();
    const view = {directory, search: $("search").value.trim(), pageIndex: 0, cursors: [""]};
    $("clear-search").hidden = !$("search").value;
    retryView = view;
    clearDrop(); updateUploadButton();
    searchTimer = setTimeout(() => load(view), 180);
  };
  $("search").addEventListener("input", searchChanged);
  for (const id of ["clear-search", "empty-reset"]) $(id).addEventListener("click", () => { $("search").value = ""; searchChanged(); $("search").focus(); });
  function toast(message, ongoing = false) {
    clearTimeout(toastTimer); $("toast-message").textContent = message; $("toast").hidden = false;
    $("download-cancel").hidden = !ongoing; $("toast-close").hidden = ongoing;
    if (!ongoing) toastTimer = setTimeout(hideToast, 8000);
  }
  $("toast-close").addEventListener("click", hideToast);
  $("download-cancel").addEventListener("click", () => transfer?.abort());
  async function download(entry) {
    if (!session) return;
    if (upload) { toast("Attendez la fin de l’envoi ou annulez-le avant de télécharger."); return; }
    if (transfer) { toast("Un téléchargement est déjà en préparation.", true); return; }
    if (entry.size > session.download_limit) { toast("Ce fichier dépasse la limite web de 256 Mio. Retrouvez-le dans votre dossier synchronisé."); return; }
    const controller = new AbortController(); transfer = controller;
    updateUploadButton();
    const current = epoch; const limit = session.chunk_bytes;
    toast(`Préparation du téléchargement · ${basename(entry.path)}`, true);
    try {
      const data = new Uint8Array(entry.size);
      let offset = 0;
      do {
        const query = new URLSearchParams({path: entry.path, revision: String(entry.revision), offset: String(offset)});
        const part = await request(`/v1/web/files/chunk?${query}`, {signal: controller.signal, raw: true, limit, timeout: 30000});
        if (part.length !== Math.min(limit, entry.size - offset)) throw new Failure("invalid_response");
        data.set(part, offset); offset += part.length;
        toast(`Préparation du téléchargement · ${entry.size ? Math.floor(offset / entry.size * 100) : 100} %`, true);
      } while (offset < entry.size);
      const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(byte => byte.toString(16).padStart(2, "0")).join("");
      if (digest !== entry.sha256) throw new Failure("integrity_failed");
      await request("/v1/web/files/session", {signal: controller.signal});
      if (controller.signal.aborted || current !== epoch || !session) return;
      const url = URL.createObjectURL(new Blob([data], {type: "application/octet-stream"}));
      const link = document.createElement("a"); link.href = url; link.download = basename(entry.path); document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(`Téléchargement lancé · ${basename(entry.path)}`);
    } catch (error) {
      if (current !== epoch || !session) return;
      if (error.code === "session_expired" || error.code === "authentication_refused") { lock("expired"); return; }
      toast(controller.signal.aborted ? "Téléchargement annulé." : error.code === "revision_changed" ? "Ce fichier a changé. Actualisez la liste avant de réessayer." : error.code === "integrity_failed" ? "Le fichier reçu ne correspond pas à son empreinte. Téléchargement interrompu." : "Téléchargement interrompu. Vérifiez la connexion et réessayez.");
    } finally { if (transfer === controller) transfer = undefined; updateUploadButton(); }
  }
  function canUpload() {
    return !statusPage && session?.upload_limit === 268435456 && !upload && !transfer &&
      Boolean(displayedQuery) && !search && !$("search").value.trim() && !listingRequest && !retryView && !document.querySelector(".file-list").inert;
  }
  function updateUploadButton() {
    $("upload-add").disabled = !canUpload();
    $("upload-add").title = search || $("search").value.trim() ? "Ouvrez un dossier pour ajouter des fichiers" :
      session && !session.upload_limit ? "L’envoi nécessite une mise à jour du serveur" : "Ajouter des fichiers au dossier ouvert";
  }
  function clearDrop() { dragDepth = 0; $("drop-overlay").hidden = true; }
  function fileDrag(event) { return [...(event.dataTransfer?.types || [])].includes("Files"); }
  const dropTarget = $("drop-target");
  // Prevent the browser from navigating to a dropped file, even outside the target.
  document.addEventListener("dragover", event => {
    if (!fileDrag(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = canUpload() && !dragCancelled && dropTarget.contains(event.target) ? "copy" : "none";
  });
  document.addEventListener("drop", event => { if (fileDrag(event)) event.preventDefault(); clearDrop(); dragCancelled = false; });
  document.addEventListener("dragend", () => { clearDrop(); dragCancelled = false; });
  document.addEventListener("dragleave", event => { if (!event.relatedTarget && (event.target === document.documentElement || event.target === document)) { clearDrop(); dragCancelled = false; } });
  dropTarget.addEventListener("dragenter", event => {
    if (!fileDrag(event) || !canUpload() || dragCancelled) return;
    event.preventDefault(); dragDepth++;
    closeMenu();
    $("drop-description").textContent = directory ? `Ils seront ajoutés au dossier ${basename(directory)}` : "Ils seront ajoutés à Tous les fichiers";
    $("drop-path").textContent = `Fichiers${directory ? ` / ${directory.split("/").join(" / ")}` : ""}`;
    $("drop-overlay").hidden = false;
  });
  dropTarget.addEventListener("dragleave", event => {
    if (fileDrag(event) && --dragDepth <= 0) clearDrop();
  });
  dropTarget.addEventListener("drop", event => {
    if (!fileDrag(event)) return;
    event.preventDefault();
    const allowed = canUpload() && !dragCancelled;
    clearDrop();
    if (!allowed) return;
    const items = [...(event.dataTransfer.items || [])].filter(item => item.kind === "file");
    if (items.some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
      toast("Déposez des fichiers uniquement. L’envoi de dossiers n’est pas pris en charge."); return;
    }
    sendFiles([...event.dataTransfer.files], directory);
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !$("drop-overlay").hidden) { event.preventDefault(); event.stopImmediatePropagation(); clearDrop(); dragCancelled = true; }
  }, true);
  $("upload-add").addEventListener("click", () => {
    if (!canUpload()) return;
    pickerContext = {directory, epoch}; $("upload-input").value = ""; $("upload-input").click();
  });
  $("upload-input").addEventListener("change", event => {
    const files = [...event.target.files], context = pickerContext;
    event.target.value = ""; pickerContext = undefined;
    if (!files.length || !context || context.epoch !== epoch) return;
    if (!canUpload() || directory !== context.directory) { toast("Le dossier a changé. Sélectionnez à nouveau vos fichiers."); return; }
    sendFiles(files, context.directory);
  });
  $("upload-cancel").addEventListener("click", () => upload?.abort());
  $("upload-close").addEventListener("click", () => { $("upload-status").hidden = true; $("upload-results").replaceChildren(); });
  const uploadErrors = {
    file_exists: "Ce nom existe déjà. Le fichier existant a été conservé ; renommez le fichier à envoyer.",
    path_conflict: "Un fichier ou dossier occupe déjà ce chemin.",
    invalid_upload: "Nom ou taille de fichier non pris en charge.",
    integrity_failed: "Le contenu reçu ne correspond pas à son empreinte. Réessayez.",
    upload_limit: "Trop d’envois en attente. Réessayez après leur expiration.",
    files_write_disabled: "L’envoi n’est pas autorisé sur cet appareil.",
    files_read_disabled: "La lecture web doit être autorisée sur cet appareil.",
    local_rejected: "Le client local doit être mis à jour pour prendre en charge l’envoi.",
    pending: "L’autorisation d’envoi n’a pas été confirmée. Vérifiez le client local et réessayez.",
    files_write_required: "L’autorisation d’envoi a expiré. Réessayez.",
    invalid_response: "Réponse du serveur invalide. Actualisez la liste avant de réessayer."
  };
  async function authorizeUpload(signal, scope = "write") {
    try { await request(`/v1/web/files/${scope}/session`, {signal}); return; }
    catch (error) { if (error.code !== `files_${scope}_required`) throw error; }
    const challenge = await post(`/v1/web/files/${scope}/challenges`, signal);
    if (!/^[a-f0-9]{64}$/.test(challenge.challenge_id) || typeof challenge.ticket !== "string" || challenge.ticket.length > 2048) throw new Failure("invalid_response");
    let localError;
    try {
      const local = await request("http://127.0.0.1:47831/v1/status", {local: true, signal, timeout: 30000,
        headers: {"X-MySync-Bridge": "1", "X-MySync-Challenge": challenge.ticket}});
      if (!local.response.ok) localError = local.data.error;
    } catch (_) { /* Check the server even when the bridge acknowledgement is lost. */ }
    if (signal.aborted) throw new Failure("cancelled");
    try { await request(`/v1/web/files/${scope}/challenges/${challenge.challenge_id}`, {signal}); }
    catch (error) {
      if (error.code === "pending" && ["files_write_disabled", "files_manage_disabled", "files_read_disabled"].includes(localError)) throw new Failure(localError);
      if (error.code === "pending" && localError === "invalid_challenge") throw new Failure("local_rejected");
      throw error;
    }
  }
  function closeFolderDialog() {
    if (folderAction?.sent) return;
    folderRequest?.abort(); folderAction = undefined; $("folder-dialog").close();
  }
  $("folder-cancel").addEventListener("click", closeFolderDialog);
  $("folder-dialog").addEventListener("cancel", event => { event.preventDefault(); closeFolderDialog(); });
  async function editDirectory(entry, action) {
    if (!session || folderAction || upload || transfer) { toast("Attendez la fin de l’opération en cours."); return; }
    const current = epoch, controller = new AbortController(); folderRequest = controller;
    const operation = {entry, action, snapshot: undefined, sent: false}; folderAction = operation;
    const rename = action === "rename";
    $("folder-title").textContent = rename ? "Renommer le dossier" : "Supprimer le dossier";
    $("folder-description").textContent = `Chargement des propriétés · ${entry.path}`;
    $("folder-name-field").hidden = !rename; $("folder-name").value = basename(entry.path); $("folder-name").disabled = false;
    $("folder-confirm").textContent = rename ? "Renommer" : "Supprimer"; $("folder-confirm").disabled = true;
    $("folder-cancel").disabled = false; $("folder-error").hidden = true; $("folder-help").hidden = true;
    $("folder-dialog").showModal();
    try {
      const info = await directoryInfo(entry, controller.signal);
      if (current !== epoch || folderAction !== operation) return;
      operation.snapshot = info.snapshot;
      $("folder-description").textContent = rename ? `Le nouveau nom s’appliquera au dossier « ${entry.path} » et à ses ${info.file_count} fichiers, sous-dossiers compris.` :
        `Supprimer « ${entry.path} » et ses ${info.file_count} fichiers, sous-dossiers compris ? La suppression sera synchronisée sur les appareils. Les fichiers seront conservés 30 jours dans la corbeille serveur.`;
      if (info.snapshot === null) throw new Failure("directory_too_large");
      $("folder-confirm").disabled = false;
      if (rename) { $("folder-name").focus(); $("folder-name").select(); } else $("folder-cancel").focus();
    } catch (error) {
      if (current !== epoch || folderAction !== operation || controller.signal.aborted) return;
      if (error.code === "session_expired") { lock("expired"); return; }
      $("folder-error").textContent = error.code === "directory_too_large" ? "La gestion web est limitée à 10 000 fichiers par dossier. Utilisez votre dossier synchronisé." : "Propriétés indisponibles. Fermez cette fenêtre, actualisez la liste et réessayez.";
      $("folder-error").hidden = false;
    }
  }
  $("folder-form").addEventListener("submit", async event => {
    event.preventDefault();
    const operation = folderAction;
    if (!operation?.snapshot || $("folder-confirm").disabled || !session) return;
    const name = $("folder-name").value;
    if (operation.action === "rename" && (!name || name === basename(operation.entry.path) || name.includes("/") || name.includes("\\") || new TextEncoder().encode(name).length > 255 || [".", "..", ".mysync-conflicts", ".mysync-staging"].includes(name))) {
      $("folder-error").textContent = "Saisissez un nouveau nom valide, sans séparateur de dossier (255 octets maximum)."; $("folder-error").hidden = false; $("folder-name").focus(); return;
    }
    const current = epoch, controller = new AbortController(); folderRequest = controller;
    $("folder-confirm").disabled = true; $("folder-name").disabled = true; $("folder-error").hidden = true; $("folder-help").hidden = true;
    try {
      await authorizeUpload(controller.signal, "manage");
      if (controller.signal.aborted || current !== epoch || folderAction !== operation) return;
      operation.sent = true; $("folder-cancel").disabled = true;
      const value = await request(`/v1/web/files/directories/${operation.action}`, {method: "POST", signal: controller.signal, limit: 32768,
        headers: {"Content-Type": "application/json"}, body: JSON.stringify({path: operation.entry.path, snapshot: operation.snapshot, ...(operation.action === "rename" ? {name} : {})})});
      if (typeof value.path !== "string" || !Number.isSafeInteger(value.file_count) || value.file_count < 1) throw new Failure("invalid_response");
      if (current !== epoch || folderAction !== operation) return;
      folderAction = undefined; $("folder-dialog").close();
      toast(operation.action === "rename" ? "Dossier renommé." : "Dossier supprimé. Les fichiers sont dans la corbeille serveur.");
      await load();
    } catch (error) {
      if (current !== epoch || folderAction !== operation || controller.signal.aborted) return;
      if (["session_expired", "authentication_refused"].includes(error.code)) { lock("expired"); return; }
      const messages = {
        directory_changed: "Le contenu du dossier a changé. Fermez cette fenêtre et actualisez la liste avant de réessayer.",
        directory_exists: "Ce nom est déjà utilisé par un dossier ou un fichier. Choisissez un autre nom.",
        directory_not_found: "Ce dossier n’existe plus. Fermez cette fenêtre et actualisez la liste.",
        invalid_name: "Le nouveau nom ou les chemins résultants dépassent les limites autorisées.",
        directory_too_large: "La gestion web est limitée à 10 000 fichiers par dossier.",
        files_manage_disabled: "La gestion des dossiers n’est pas autorisée sur cet appareil.",
        files_read_disabled: "La lecture web doit aussi être autorisée sur cet appareil.",
        local_rejected: "Mettez à jour le client local pour autoriser la gestion des dossiers.",
        files_manage_required: "L’autorisation de gestion a expiré. Réessayez."
      };
      $("folder-error").textContent = messages[error.code] || (operation.sent ? "Opération non confirmée. Fermez cette fenêtre et actualisez la liste pour vérifier le résultat." : "Autorisation non confirmée. Vérifiez le client local et réessayez.");
      $("folder-error").hidden = false;
      $("folder-help").hidden = !["files_manage_disabled", "files_read_disabled", "local_rejected"].includes(error.code);
      const retry = !operation.sent || error.code === "directory_exists" || error.code === "invalid_name";
      $("folder-confirm").disabled = !retry;
    } finally {
      if (folderAction === operation) { operation.sent = false; $("folder-cancel").disabled = false; $("folder-name").disabled = false; }
    }
  });
  async function sendFiles(files, destination) {
    if (!canUpload() || !files.length) return;
    if (files.length > 50) { toast("Ajoutez au maximum 50 fichiers à la fois."); return; }
    const current = epoch, controller = new AbortController(); upload = controller; clearDrop(); updateUploadButton();
    const {signal} = controller, limit = session.upload_limit, chunkBytes = session.chunk_bytes;
    let sent = 0, rejected = 0, activeId, committing = false;
    const live = () => current === epoch && Boolean(session);
    const check = () => { if (!live() || signal.aborted) throw new Failure("cancelled"); };
    const result = (name, message, error) => {
      const row = document.createElement("li"); row.textContent = `${name} — ${message}`;
      if (error) row.className = "upload-error";
      $("upload-results").append(row); $("upload-results").hidden = false;
    };
    $("upload-status").hidden = false; $("upload-results").replaceChildren(); $("upload-results").hidden = true;
    $("upload-help").hidden = true; $("upload-close").hidden = true; $("upload-cancel").hidden = false;
    $("upload-progress").hidden = false; $("upload-progress").value = 0;
    $("upload-destination").textContent = `Vers ${destination ? `Fichiers / ${destination}` : "Tous les fichiers"}`;
    $("upload-message").textContent = "Vérification de l’autorisation d’envoi…";
    try {
      await authorizeUpload(signal); check();
      for (let index = 0; index < files.length; index++) {
        check(); const file = files[index];
        const path = `${destination ? destination + "/" : ""}${file.name}`;
        const bytes = new TextEncoder();
        if (!file.name || /[/\\\0]/.test(file.name) || [".", "..", ".mysync-conflicts", ".mysync-staging"].includes(file.name) || bytes.encode(file.name).length > 255 || bytes.encode(path).length > 4096 || file.size > limit) {
          rejected++; result(file.name, file.size > limit ? "Limite de 256 Mio par fichier dépassée." : "Nom de fichier non pris en charge.", true); continue;
        }
        try {
          $("upload-message").textContent = `Préparation · ${index + 1}/${files.length} · ${file.name}`;
          $("upload-progress").value = 0;
          // Only one file is hashed at a time; the bounded buffer is released
          // before transferring 8 MiB slices from the original File.
          const sha256 = [...new Uint8Array(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()))].map(byte => byte.toString(16).padStart(2, "0")).join("");
          check();
          const started = await request("/v1/web/files/uploads", {method: "POST", signal,
            headers: {"Content-Type": "application/json"}, body: JSON.stringify({path, size: file.size, sha256})});
          if (!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(started.id) || started.offset !== 0) throw new Failure("invalid_response");
          activeId = started.id;
          let offset = 0;
          while (offset < file.size) {
            check();
            const end = Math.min(offset + chunkBytes, file.size);
            $("upload-message").textContent = `Envoi · ${index + 1}/${files.length} · ${file.name}`;
            const part = await request(`/v1/web/files/uploads/${activeId}?offset=${offset}`, {method: "PUT", signal, timeout: 30000,
              headers: {"Content-Type": "application/octet-stream"}, body: file.slice(offset, end)});
            if (part.id !== activeId || part.offset !== end) throw new Failure("invalid_response");
            offset = end; $("upload-progress").value = Math.floor(offset / file.size * 100);
          }
          check(); committing = true;
          $("upload-message").textContent = `Confirmation · ${file.name}`;
          const entry = await post(`/v1/web/files/uploads/${activeId}/commit`, signal);
          if (entry.path !== path || entry.sha256 !== sha256 || entry.size !== file.size || entry.deleted || !Number.isSafeInteger(entry.revision) || entry.revision <= 0) throw new Failure("invalid_response");
          activeId = undefined; committing = false; check(); sent++;
          $("upload-progress").value = 100; result(file.name, "Envoyé", false);
        } catch (error) {
          if (signal.aborted || !live() || ["session_expired", "authentication_refused", "files_write_required"].includes(error.code)) throw error;
          rejected++; result(file.name, committing ? "Envoi non confirmé. Actualisez la liste avant de réessayer." : uploadErrors[error.code] || "Envoi interrompu. Vérifiez la connexion et réessayez.", true);
        } finally {
          if (activeId && live()) await request(`/v1/web/files/uploads/${activeId}`, {method: "DELETE", timeout: 5000}).catch(() => {});
          activeId = undefined;
        }
        committing = false;
      }
      check();
      $("upload-message").textContent = `${sent} fichier${sent === 1 ? "" : "s"} envoyé${sent === 1 ? "" : "s"}${rejected ? ` · ${rejected} non envoyé${rejected === 1 ? "" : "s"}` : ""}`;
    } catch (error) {
      if (!live()) return;
      if (["session_expired", "authentication_refused"].includes(error.code)) { lock("expired"); return; }
      $("upload-message").textContent = signal.aborted ? (committing ? "Envoi interrompu pendant la confirmation. Vérifiez la liste." : `Envoi annulé · ${sent} fichier${sent === 1 ? "" : "s"} déjà envoyé${sent === 1 ? "" : "s"}`) : uploadErrors[error.code] || "Envoi interrompu. Vérifiez la connexion et réessayez.";
      $("upload-help").hidden = !["files_write_disabled", "files_read_disabled", "local_rejected"].includes(error.code);
    } finally {
      if (upload === controller) upload = undefined;
      if (live()) {
        $("upload-cancel").hidden = true; $("upload-close").hidden = false; $("upload-progress").hidden = true;
        updateUploadButton();
        // Refresh the view currently open, never redirect back to a stale target.
        if (!listingRequest && !retryView) await load();
      }
    }
  }
  // Never restore private names from the back-forward cache without a fresh
  // server authorization. Only UI/automatic-access preferences use local storage.
  addEventListener("pagehide", () => lock());
  addEventListener("pageshow", event => { if (event.persisted) restore(); });
  addEventListener("storage", event => { if (event.key === "mysync-auto-access" && event.newValue === "off") lock(); });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible" || statusPage || !autoAccess()) return;
    if (session && session.expires_at * 1000 <= Date.now()) lock("expired");
    if (session) renewSession();
    else if ($("access").dataset.state === "expired") verify();
  });
  if (editorPage) codeEditor = window.MySyncEditor({request, post, Failure, icon});
  restore();
})();
