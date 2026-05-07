function toast(msg, type = "success") {
    const container = document.getElementById("toast-container");
    if (!container) {
        return;
    }
    const el = document.createElement("div");
    el.className = `toast align-items-center text-bg-${type} border-0 show mb-2`;
    el.innerHTML = `<div class="d-flex"><div class="toast-body">${msg}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest('.toast').remove()"></button></div>`;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

async function apiFetch(url, opts = {}) {
    const response = await fetch(url, {
        headers: { "Content-Type": "application/json", ...opts.headers },
        ...opts,
    });
    if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(err.detail || response.statusText);
    }
    return response;
}

async function showQR(pubkey, name) {
    const modal = new bootstrap.Modal(document.getElementById("qrModal"));
    const img = document.getElementById("qr-img");
    const spinner = document.getElementById("qr-spinner");
    const errEl = document.getElementById("qr-error");
    const nameEl = document.getElementById("qr-name");
    const dlBtn = document.getElementById("qr-download");

    img.classList.add("d-none");
    errEl.classList.add("d-none");
    spinner.classList.remove("d-none");
    nameEl.textContent = name;
    modal.show();

    img.removeAttribute("src");
    try {
        const artifact = await resolvePeerArtifactOption(pubkey);
        if (!artifact.qr_endpoint) {
            spinner.classList.add("d-none");
            errEl.textContent = `${getXrayProtocolLabel(artifact.protocol, artifact.label)} QR is not available for this artifact. Download the config file instead.`;
            errEl.classList.remove("d-none");
            dlBtn.href = artifact.config_endpoint;
            dlBtn.download = `${name}.conf`;
            return;
        }
        img.src = artifact.qr_endpoint;
        img.onload = () => {
            spinner.classList.add("d-none");
            img.classList.remove("d-none");
        };
        img.onerror = () => {
            spinner.classList.add("d-none");
            errEl.textContent = `${getXrayProtocolLabel(artifact.protocol, artifact.label)} конфиг недоступен: приватный ключ ещё не сохранён.`;
            errEl.classList.remove("d-none");
        };
        dlBtn.href = artifact.config_endpoint;
        dlBtn.download = artifact.protocol === "wg" ? `${name}.conf` : `${name}.${artifact.protocol}.config`;
    } catch (e) {
        spinner.classList.add("d-none");
        errEl.textContent = e.message;
        errEl.classList.remove("d-none");
    }
}

let deletePubkey = null;
let routingOverrides = [];
let xrayClients = [];
let xrayClientArtifactCatalogs = {};
let peerArtifactCatalogs = {};
let telegramBillingSummary = null;
let telegramUsers = [];
let telegramPayments = [];
let telegramInvites = [];
let telegramLeads = [];
let telegramCommandDocs = null;
let telegramBillingFilter = "all";
let telegramSupportSummary = null;
let telegramSupportOpenTickets = [];
let telegramSupportArchivedTickets = [];
let telegramSupportSelectedTicketId = "";

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function formatDateTime(value) {
    if (!value) {
        return "—";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return value;
    }

    return parsed.toLocaleString("ru-RU", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function getMatchTypeLabel(matchType) {
    return matchType === "exact" ? "Exact" : "Suffix";
}

function getRouteLabel(route) {
    return route === "ru" ? "RU / direct" : "non-RU / via NL";
}

function getRouteBadgeClass(route) {
    return route === "ru" ? "badge-route-ru" : "badge-route-non-ru";
}

function getXrayClientStatusLabel(client) {
    return client.enabled ? "Включён" : "Выключен";
}

function getXrayProtocolLabel(protocol, fallbackLabel = "") {
    if (fallbackLabel) {
        return fallbackLabel;
    }
    if (protocol === "amneziawg") {
        return "AmneziaWG";
    }
    if (protocol === "wg") {
        return "WireGuard";
    }
    if (protocol === "vless") {
        return "VLESS/Xray";
    }
    return String(protocol || "unknown").toUpperCase();
}

function renderXrayProtocolBadge(protocol) {
    if (protocol === "vless") {
        return '<span class="badge badge-vless">VLESS</span>';
    }
    if (protocol === "wg") {
        return '<span class="badge badge-wg">WG</span>';
    }
    if (protocol === "amneziawg") {
        return '<span class="badge text-bg-info">AmneziaWG</span>';
    }
    return `<span class="badge text-bg-secondary">${escapeHtml(String(protocol || "unknown").toUpperCase())}</span>`;
}

function buildXrayArtifactEndpoint(clientId, artifactType, protocol = null) {
    const suffix = protocol ? `?protocol=${encodeURIComponent(protocol)}` : "";
    return `/api/xray/clients/${encodeURIComponent(clientId)}/${artifactType}${suffix}`;
}

function buildDefaultXrayArtifactOption(clientId, protocol = "vless") {
    return {
        protocol,
        label: getXrayProtocolLabel(protocol),
        share_endpoint: buildXrayArtifactEndpoint(clientId, "share", protocol),
        config_endpoint: buildXrayArtifactEndpoint(clientId, "config", protocol),
        qr_endpoint: buildXrayArtifactEndpoint(clientId, "qr", protocol),
        bundle_endpoint: buildXrayArtifactEndpoint(clientId, "bundle", protocol),
    };
}

async function fetchXrayClientArtifactCatalog(clientId, force = false) {
    if (!force && xrayClientArtifactCatalogs[clientId]) {
        return xrayClientArtifactCatalogs[clientId];
    }
    const response = await apiFetch(`/api/xray/clients/${encodeURIComponent(clientId)}/artifacts`);
    const catalog = await response.json();
    xrayClientArtifactCatalogs[clientId] = catalog;
    return catalog;
}

function findXrayClientArtifactOption(catalog, protocol = null) {
    if (!catalog) {
        return null;
    }
    const normalizedProtocol = protocol || catalog.default_protocol;
    return (catalog.available_protocols || []).find((option) => option.protocol === normalizedProtocol) || null;
}

async function resolveXrayClientArtifactOption(clientId, protocol = null) {
    const normalizedProtocol = protocol || "vless";
    try {
        const catalog = await fetchXrayClientArtifactCatalog(clientId);
        return (
            findXrayClientArtifactOption(catalog, protocol)
            || buildDefaultXrayArtifactOption(clientId, protocol || catalog.default_protocol || normalizedProtocol)
        );
    } catch (_error) {
        return buildDefaultXrayArtifactOption(clientId, normalizedProtocol);
    }
}

function buildPeerArtifactEndpoint(pubkey, artifactType, protocol = null) {
    const suffix = protocol ? `?protocol=${encodeURIComponent(protocol)}` : "";
    return `/api/peers/${encodeURIComponent(pubkey)}/${artifactType}${suffix}`;
}

function buildDefaultPeerArtifactOption(pubkey, protocol = "wg") {
    return {
        protocol,
        label: getXrayProtocolLabel(protocol),
        config_endpoint: buildPeerArtifactEndpoint(pubkey, "config", protocol),
        qr_endpoint: protocol === "wg" ? buildPeerArtifactEndpoint(pubkey, "qr", protocol) : null,
    };
}

async function fetchPeerArtifactCatalog(pubkey, force = false) {
    if (!force && peerArtifactCatalogs[pubkey]) {
        return peerArtifactCatalogs[pubkey];
    }
    const response = await apiFetch(`/api/peers/${encodeURIComponent(pubkey)}/artifacts`);
    const catalog = await response.json();
    peerArtifactCatalogs[pubkey] = catalog;
    return catalog;
}

function findPeerArtifactOption(catalog, protocol = null) {
    if (!catalog) {
        return null;
    }
    const normalizedProtocol = protocol || catalog.default_protocol;
    return (catalog.available_protocols || []).find((option) => option.protocol === normalizedProtocol) || null;
}

async function resolvePeerArtifactOption(pubkey, protocol = null) {
    const normalizedProtocol = protocol || "wg";
    try {
        const catalog = await fetchPeerArtifactCatalog(pubkey);
        return (
            findPeerArtifactOption(catalog, protocol)
            || buildDefaultPeerArtifactOption(pubkey, protocol || catalog.default_protocol || normalizedProtocol)
        );
    } catch (_error) {
        return buildDefaultPeerArtifactOption(pubkey, normalizedProtocol);
    }
}

function getTelegramUserStatus(user) {
    if (user.subscription_active) {
        return { label: "Paid active", className: "text-bg-success" };
    }
    if (user.subscription_expired) {
        return { label: "Expired", className: "text-bg-warning" };
    }
    return { label: "Free", className: "badge-disabled" };
}

function getTelegramPaymentStatusClass(status) {
    if (status === "completed") {
        return "text-bg-success";
    }
    if (status === "pending") {
        return "text-bg-warning";
    }
    return "badge-disabled";
}

function renderTelegramBillingSummary(summary) {
    telegramBillingSummary = summary;
    const counts = summary.counts || {};
    const settings = summary.settings || {};

    const values = {
        "telegram-billing-total-users": counts.total_users || 0,
        "telegram-billing-active-paid": counts.active_paid || 0,
        "telegram-billing-expired-paid": counts.expired_paid || 0,
        "telegram-billing-free-users": counts.free_users || 0,
        "telegram-billing-price": settings.subscription_price_stars || 0,
        "telegram-billing-completed-payments": counts.completed_payments || 0,
        "telegram-billing-pending-invites": counts.pending_invites || 0,
        "telegram-billing-uninvited-leads": counts.uninvited_leads || 0,
        "telegram-billing-bonus-balance": counts.bonus_balance_stars || 0,
    };

    for (const [id, value] of Object.entries(values)) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
        }
    }

    const priceInput = document.getElementById("telegram-billing-price-input");
    if (priceInput && document.activeElement !== priceInput) {
        priceInput.value = settings.subscription_price_stars || 0;
    }

    const maxDiscountInput = document.getElementById("telegram-billing-max-discount-input");
    if (maxDiscountInput && document.activeElement !== maxDiscountInput) {
        maxDiscountInput.value = settings.subscription_max_12m_discount_percent || 0;
    }

    const trialInput = document.getElementById("telegram-billing-trial-input");
    if (trialInput && document.activeElement !== trialInput) {
        trialInput.value = settings.trial_period_days || 7;
    }
}

function telegramUserMatchesFilter(user) {
    if (telegramBillingFilter === "active") {
        return Boolean(user.subscription_active);
    }
    if (telegramBillingFilter === "expired") {
        return Boolean(user.subscription_expired);
    }
    if (telegramBillingFilter === "free") {
        return user.account_type !== "paid";
    }
    return true;
}

function renderTelegramUsers(users) {
    const body = document.getElementById("telegram-users-body");
    if (!body) {
        return;
    }

    const search = (document.getElementById("telegram-users-search")?.value || "").trim().toLowerCase();
    const filtered = users.filter((user) => {
        if (!telegramUserMatchesFilter(user)) {
            return false;
        }
        if (!search) {
            return true;
        }
        return `${user.display_name || ""} ${user.username || ""} ${user.first_name || ""} ${user.last_name || ""} ${user.telegram_user_id} ${user.client_id || ""}`
            .toLowerCase()
            .includes(search);
    });

    if (!filtered.length) {
        body.innerHTML = `
            <tr>
              <td colspan="7" class="text-center text-muted py-4">
                Telegram users не найдены.
              </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = filtered
        .map((user) => {
            const status = getTelegramUserStatus(user);
            const payment = user.last_completed_payment;
            const paymentText = payment
                ? `${escapeHtml(payment.amount_stars)} ${escapeHtml(payment.currency || "XTR")}<div class="small text-muted">${escapeHtml(formatDateTime(payment.updated_at || payment.created_at))}</div>`
                : "—";
            return `
                <tr>
                  <td>
                    ${user.display_name ? `<div class="fw-semibold">${escapeHtml(user.display_name)}</div>` : ""}
                    <code>${escapeHtml(user.telegram_user_id)}</code>
                    <div class="small text-muted">invited by ${escapeHtml(user.invited_by || "—")}</div>
                    ${user.trial_invite_id ? `<div class="small text-muted">trial invite ${escapeHtml(user.trial_invite_id)}</div>` : ""}
                  </td>
                  <td>
                    ${user.client_id ? `<code>${escapeHtml(user.client_id)}</code>` : "—"}
                    ${user.deactivated_at ? `<div class="small text-muted">deactivated ${escapeHtml(formatDateTime(user.deactivated_at))}</div>` : ""}
                  </td>
                  <td>
                    <span class="badge ${status.className}">${escapeHtml(status.label)}</span>
                    <div class="small text-muted">${escapeHtml(user.account_type || "free")}</div>
                  </td>
                  <td class="small text-muted">${escapeHtml(formatDateTime(user.subscription_expires_at))}</td>
                  <td>
                    ${escapeHtml(user.discount_percent || 0)}%
                    ${
                        user.bonus_balance_stars
                            ? `<div class="small text-success">${escapeHtml(user.bonus_balance_stars)} bonus Stars</div>`
                            : ""
                    }
                  </td>
                  <td class="small">${paymentText}</td>
                  <td>
                    <div class="d-flex gap-1 flex-wrap">
                      <button class="btn btn-outline-success btn-sm" type="button" title="Grant paid access"
                        onclick="showTelegramUserAction(${Number(user.telegram_user_id)}, 'grant')">
                        <i class="bi bi-plus-circle"></i>
                      </button>
                      <button class="btn btn-outline-warning btn-sm" type="button" title="Set expiry"
                        onclick="showTelegramUserAction(${Number(user.telegram_user_id)}, 'expires')">
                        <i class="bi bi-calendar-event"></i>
                      </button>
                      <button class="btn btn-outline-info btn-sm" type="button" title="Set discount"
                        onclick="showTelegramUserAction(${Number(user.telegram_user_id)}, 'discount')">
                        <i class="bi bi-percent"></i>
                      </button>
                      <button class="btn btn-outline-danger btn-sm" type="button" title="Revoke and disable"
                        onclick="revokeTelegramUser(${Number(user.telegram_user_id)})">
                        <i class="bi bi-slash-circle"></i>
                      </button>
                    </div>
                  </td>
                </tr>
            `;
        })
        .join("");
}

function renderTelegramPayments(payments) {
    const body = document.getElementById("telegram-payments-body");
    const count = document.getElementById("telegram-payments-count");
    if (count) {
        count.textContent = payments.length;
    }
    if (!body) {
        return;
    }

    if (!payments.length) {
        body.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">Платежей пока нет.</td></tr>';
        return;
    }

    body.innerHTML = payments
        .slice(0, 20)
        .map(
            (payment) => `
                <tr title="payload: ${escapeHtml(payment.payload)}">
                  <td><code>${escapeHtml(payment.user_id || "—")}</code></td>
                  <td>
                    <span class="badge ${getTelegramPaymentStatusClass(payment.status)}">
                      ${escapeHtml(payment.status || "unknown")}
                    </span>
                    ${
                        payment.telegram_payment_charge_id_short
                            ? `<div class="small text-muted">${escapeHtml(payment.telegram_payment_charge_id_short)}</div>`
                            : ""
                    }
                  </td>
                  <td>
                    ${escapeHtml(payment.amount_stars || 0)}
                    <div class="small text-muted">${escapeHtml(payment.months || 1)}m / ${escapeHtml(payment.period_days || 0)}d</div>
                    ${
                        payment.total_discount_percent
                            ? `<div class="small text-info">${escapeHtml(payment.total_discount_percent)}% discount</div>`
                            : ""
                    }
                    ${
                        payment.bonus_spent_stars
                            ? `<div class="small text-success">-${escapeHtml(payment.bonus_spent_stars)} bonus</div>`
                            : ""
                    }
                    ${
                        payment.referral_bonus_stars
                            ? `<div class="small text-info">+${escapeHtml(payment.referral_bonus_stars)} referral</div>`
                            : ""
                    }
                  </td>
                  <td class="small text-muted">${escapeHtml(formatDateTime(payment.updated_at || payment.created_at))}</td>
                </tr>
            `
        )
        .join("");
}

function getInviteStatusClass(status) {
    if (status === "pending") {
        return "text-bg-warning";
    }
    if (status === "accepted") {
        return "text-bg-success";
    }
    return "badge-disabled";
}

function renderTelegramInvites(invites) {
    const body = document.getElementById("telegram-invites-body");
    const count = document.getElementById("telegram-invites-count");
    if (count) {
        count.textContent = invites.length;
    }
    if (!body) {
        return;
    }

    if (!invites.length) {
        body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Инвайтов пока нет.</td></tr>';
        return;
    }

    body.innerHTML = invites
        .slice(0, 30)
        .map((invite) => {
            const target = invite.target_username_hint || invite.target_phone_hint || invite.target_user_id || "—";
            return `
                <tr>
                  <td>
                    <code>${escapeHtml(invite.id || "—")}</code>
                    <div class="small text-muted">by ${escapeHtml(invite.created_by || "—")}</div>
                  </td>
                  <td>
                    ${escapeHtml(target)}
                    ${invite.target_user_id ? `<div class="small text-muted">user ${escapeHtml(invite.target_user_id)}</div>` : ""}
                  </td>
                  <td>
                    <span class="badge ${getInviteStatusClass(invite.status)}">${escapeHtml(invite.status || "unknown")}</span>
                    ${invite.accepted_at ? `<div class="small text-muted">accepted ${escapeHtml(formatDateTime(invite.accepted_at))}</div>` : ""}
                  </td>
                  <td>${escapeHtml(invite.trial_days || 0)}d</td>
                  <td class="small text-muted">${escapeHtml(formatDateTime(invite.updated_at || invite.created_at))}</td>
                </tr>
            `;
        })
        .join("");
}

function renderTelegramLeads(leads) {
    const body = document.getElementById("telegram-leads-body");
    const count = document.getElementById("telegram-leads-count");
    if (count) {
        count.textContent = leads.length;
    }
    if (!body) {
        return;
    }

    if (!leads.length) {
        body.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-4">Новых заявок пока нет.</td></tr>';
        return;
    }

    body.innerHTML = leads
        .slice(0, 30)
        .map((lead) => {
            const name = [lead.first_name, lead.last_name].filter(Boolean).join(" ") || "—";
            return `
                <tr>
                  <td>
                    <code>${escapeHtml(lead.telegram_user_id || "—")}</code>
                    <div class="small text-muted">chat ${escapeHtml(lead.chat_id || "—")}</div>
                  </td>
                  <td>
                    ${escapeHtml(name)}
                    <div class="small text-muted">${lead.username ? `@${escapeHtml(lead.username)}` : "no username"}</div>
                    ${lead.phone_number ? `<div class="small text-muted">phone ${escapeHtml(lead.phone_number)}</div>` : ""}
                  </td>
                  <td class="small text-muted">
                    ${escapeHtml(formatDateTime(lead.last_seen_at || lead.updated_at))}
                    <div>${escapeHtml(lead.message_count || 0)} msg</div>
                  </td>
                </tr>
            `;
        })
        .join("");
}

function formatTelegramSupportUser(ticket) {
    if (ticket.display_name) {
        return ticket.display_name;
    }
    if (ticket.username) {
        return `@${String(ticket.username).replace(/^@+/, "")}`;
    }
    const fullName = [ticket.first_name, ticket.last_name].filter(Boolean).join(" ").trim();
    return fullName || String(ticket.user_id || "—");
}

function renderTelegramSupportSummary(summary) {
    telegramSupportSummary = summary;
    const counts = summary.counts || {};
    const values = {
        "telegram-support-new-tickets": counts.new_tickets || 0,
        "telegram-support-new-messages": counts.unread_user_messages || 0,
        "telegram-support-open-tickets": counts.open_tickets || 0,
        "telegram-support-archived-tickets": counts.archived_tickets || 0,
    };
    Object.entries(values).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
        }
    });
}

function renderTelegramSupportTable(tickets, bodyId, countId, isArchived = false) {
    const body = document.getElementById(bodyId);
    const count = document.getElementById(countId);
    if (count) {
        count.textContent = tickets.length;
    }
    if (!body) {
        return;
    }

    if (!tickets.length) {
        body.innerHTML = `
            <tr>
              <td colspan="${isArchived ? 3 : 4}" class="text-center text-muted py-4">
                ${isArchived ? "Архивных заявок пока нет." : "Открытых заявок пока нет."}
              </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = tickets
        .map((ticket) => {
            const selectedClass = telegramSupportSelectedTicketId === ticket.ticket_id ? "table-active" : "";
            return `
                <tr class="${selectedClass}" role="button" onclick="openTelegramSupportTicket('${escapeHtml(ticket.ticket_id)}', ${isArchived ? "false" : "true"})">
                  <td>
                    <code>${escapeHtml(ticket.ticket_id || "—")}</code>
                    <div class="small text-muted text-truncate" style="max-width: 220px;">${escapeHtml(ticket.last_message_excerpt || "—")}</div>
                  </td>
                  <td>
                    ${escapeHtml(formatTelegramSupportUser(ticket))}
                    ${!isArchived ? `<div class="small text-muted">${escapeHtml(ticket.user_id || "—")}</div>` : ""}
                  </td>
                  ${isArchived
                        ? `<td class="small text-muted">${escapeHtml(formatDateTime(ticket.updated_at))}</td>`
                        : `<td><span class="badge ${Number(ticket.unread_user_messages || 0) > 0 ? "text-bg-warning" : "badge-disabled"}">${escapeHtml(ticket.unread_user_messages || 0)}</span></td>
                           <td class="small text-muted">${escapeHtml(formatDateTime(ticket.updated_at))}</td>`}
                </tr>
            `;
        })
        .join("");
}

function renderTelegramSupportThread(ticket) {
    const thread = document.getElementById("telegram-support-thread");
    const meta = document.getElementById("telegram-support-detail-meta");
    const markReadBtn = document.getElementById("telegram-support-mark-read");
    const archiveBtn = document.getElementById("telegram-support-archive");
    const replyBtn = document.getElementById("telegram-support-reply-send");
    if (!thread || !meta || !markReadBtn || !archiveBtn || !replyBtn) {
        return;
    }

    if (!ticket) {
        meta.textContent = "Выберите заявку слева, чтобы посмотреть переписку и ответить.";
        thread.innerHTML = '<div class="text-muted small">Здесь появится история выбранной заявки.</div>';
        markReadBtn.disabled = true;
        archiveBtn.disabled = true;
        replyBtn.disabled = true;
        return;
    }

    telegramSupportSelectedTicketId = ticket.ticket_id || "";
    meta.innerHTML = `
        <div><code>${escapeHtml(ticket.ticket_id || "—")}</code> · ${escapeHtml(formatTelegramSupportUser(ticket))} · status ${escapeHtml(ticket.status || "unknown")}</div>
        <div class="small text-muted">Created ${escapeHtml(formatDateTime(ticket.created_at))} · Updated ${escapeHtml(formatDateTime(ticket.updated_at))} · Messages ${escapeHtml(ticket.message_count || 0)}</div>
    `;
    const messages = Array.isArray(ticket.messages) ? ticket.messages : [];
    thread.innerHTML = messages.length
        ? messages
            .map((message) => `
                <div class="border rounded p-2 ${message.author === "admin" ? "border-info" : "border-secondary"}">
                  <div class="d-flex justify-content-between align-items-center gap-2 mb-1">
                    <span class="badge ${message.author === "admin" ? "text-bg-info" : "text-bg-secondary"}">${escapeHtml(message.author || "user")}</span>
                    <span class="small text-muted">${escapeHtml(formatDateTime(message.created_at))}</span>
                  </div>
                  <div class="small" style="white-space: pre-wrap;">${escapeHtml(message.text || "")}</div>
                </div>
            `)
            .join("")
        : '<div class="text-muted small">Сообщений пока нет.</div>';

    const isOpen = ticket.status === "open";
    markReadBtn.disabled = !isOpen;
    archiveBtn.disabled = !isOpen;
    replyBtn.disabled = !isOpen;
}

async function loadTelegramSupportSnapshot() {
    const [summaryResponse, openResponse, archivedResponse] = await Promise.all([
        apiFetch("/api/telegram/support/summary"),
        apiFetch("/api/telegram/support/tickets?status=open"),
        apiFetch("/api/telegram/support/tickets?status=archived"),
    ]);
    const [summary, openTickets, archivedTickets] = await Promise.all([
        summaryResponse.json(),
        openResponse.json(),
        archivedResponse.json(),
    ]);
    telegramSupportOpenTickets = openTickets;
    telegramSupportArchivedTickets = archivedTickets;
    renderTelegramSupportSummary(summary);
    renderTelegramSupportTable(openTickets, "telegram-support-open-body", "telegram-support-open-count", false);
    renderTelegramSupportTable(archivedTickets, "telegram-support-archived-body", "telegram-support-archived-count", true);
}

async function refreshTelegramSupport() {
    const openBody = document.getElementById("telegram-support-open-body");
    const archivedBody = document.getElementById("telegram-support-archived-body");
    try {
        await loadTelegramSupportSnapshot();
        if (!telegramSupportSelectedTicketId) {
            return;
        }
        const detailResponse = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(telegramSupportSelectedTicketId)}`);
        renderTelegramSupportThread(await detailResponse.json());
    } catch (e) {
        if (openBody) {
            openBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        if (archivedBody) {
            archivedBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        renderTelegramSupportThread(null);
        toast(e.message, "danger");
    }
}

async function openTelegramSupportTicket(ticketId, markRead = true) {
    try {
        let detailResponse = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(ticketId)}`);
        let detail = await detailResponse.json();
        if (markRead && detail.status === "open" && Number(detail.unread_user_messages || 0) > 0) {
            detailResponse = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(ticketId)}/mark-read`, {
                method: "POST",
            });
            detail = await detailResponse.json();
        }
        renderTelegramSupportThread(detail);
        await loadTelegramSupportSnapshot();
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function markTelegramSupportTicketRead() {
    if (!telegramSupportSelectedTicketId) {
        return;
    }
    try {
        const response = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(telegramSupportSelectedTicketId)}/mark-read`, {
            method: "POST",
        });
        renderTelegramSupportThread(await response.json());
        await loadTelegramSupportSnapshot();
        toast("Support ticket marked as read");
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function archiveTelegramSupportTicket() {
    if (!telegramSupportSelectedTicketId) {
        return;
    }
    if (!window.confirm(`Archive support ticket ${telegramSupportSelectedTicketId}?`)) {
        return;
    }
    try {
        const response = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(telegramSupportSelectedTicketId)}/archive`, {
            method: "POST",
        });
        renderTelegramSupportThread(await response.json());
        await loadTelegramSupportSnapshot();
        toast("Support ticket archived");
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function replyTelegramSupportTicket() {
    const textarea = document.getElementById("telegram-support-reply-message");
    const button = document.getElementById("telegram-support-reply-send");
    if (!telegramSupportSelectedTicketId || !textarea || !button) {
        return;
    }
    const message = textarea.value.trim();
    if (!message) {
        toast("Напишите ответ пользователю", "warning");
        return;
    }
    button.disabled = true;
    try {
        const response = await apiFetch(`/api/telegram/support/tickets/${encodeURIComponent(telegramSupportSelectedTicketId)}/reply`, {
            method: "POST",
            body: JSON.stringify({ message }),
        });
        textarea.value = "";
        renderTelegramSupportThread(await response.json());
        await loadTelegramSupportSnapshot();
        toast("Support reply sent");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        button.disabled = false;
    }
}

async function refreshTelegramBilling() {
    const usersBody = document.getElementById("telegram-users-body");
    const paymentsBody = document.getElementById("telegram-payments-body");
    const invitesBody = document.getElementById("telegram-invites-body");
    const leadsBody = document.getElementById("telegram-leads-body");
    try {
        const [summaryResponse, usersResponse, paymentsResponse, invitesResponse, leadsResponse] = await Promise.all([
            apiFetch("/api/telegram/billing/summary"),
            apiFetch("/api/telegram/users"),
            apiFetch("/api/telegram/payments"),
            apiFetch("/api/telegram/invites"),
            apiFetch("/api/telegram/leads"),
        ]);
        const [summary, users, payments, invites, leads] = await Promise.all([
            summaryResponse.json(),
            usersResponse.json(),
            paymentsResponse.json(),
            invitesResponse.json(),
            leadsResponse.json(),
        ]);
        telegramUsers = users;
        telegramPayments = payments;
        telegramInvites = invites;
        telegramLeads = leads;
        renderTelegramBillingSummary(summary);
        renderTelegramUsers(telegramUsers);
        renderTelegramPayments(telegramPayments);
        renderTelegramInvites(telegramInvites);
        renderTelegramLeads(telegramLeads);
    } catch (e) {
        if (usersBody) {
            usersBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        if (paymentsBody) {
            paymentsBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        if (invitesBody) {
            invitesBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        if (leadsBody) {
            leadsBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-4">${escapeHtml(e.message)}</td></tr>`;
        }
        toast(e.message, "danger");
    }
}

async function saveTelegramBillingPrice() {
    const input = document.getElementById("telegram-billing-price-input");
    const button = document.getElementById("telegram-billing-price-save");
    if (!input || !button) {
        return;
    }
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 0) {
        toast("Цена должна быть целым числом Stars", "warning");
        return;
    }

    button.disabled = true;
    try {
        const response = await apiFetch("/api/telegram/billing/settings", {
            method: "PUT",
            body: JSON.stringify({ subscription_price_stars: value }),
        });
        renderTelegramBillingSummary(await response.json());
        toast("Цена подписки обновлена");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        button.disabled = false;
    }
}

async function saveTelegramBillingMaxDiscount() {
    const input = document.getElementById("telegram-billing-max-discount-input");
    const button = document.getElementById("telegram-billing-max-discount-save");
    if (!input || !button) {
        return;
    }
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 0 || value > 100) {
        toast("Пакетная скидка должна быть целым числом 0..100", "warning");
        return;
    }

    button.disabled = true;
    try {
        const response = await apiFetch("/api/telegram/billing/settings", {
            method: "PUT",
            body: JSON.stringify({ subscription_max_12m_discount_percent: value }),
        });
        renderTelegramBillingSummary(await response.json());
        toast("Максимальная скидка для 12 месяцев обновлена");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        button.disabled = false;
    }
}

async function saveTelegramBillingTrial() {
    const input = document.getElementById("telegram-billing-trial-input");
    const button = document.getElementById("telegram-billing-trial-save");
    if (!input || !button) {
        return;
    }
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 1) {
        toast("Trial должен быть целым числом дней", "warning");
        return;
    }

    button.disabled = true;
    try {
        const response = await apiFetch("/api/telegram/billing/settings", {
            method: "PUT",
            body: JSON.stringify({ trial_period_days: value }),
        });
        renderTelegramBillingSummary(await response.json());
        toast("Trial период обновлён");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        button.disabled = false;
    }
}

function renderTelegramCommandDocs(payload) {
    telegramCommandDocs = payload;
    const editor = document.getElementById("telegram-command-docs-editor");
    const statusEl = document.getElementById("telegram-command-docs-status");
    const pathEl = document.getElementById("telegram-command-docs-path");
    const syntaxEl = document.getElementById("telegram-command-docs-syntax");
    const previewTargets = {
        help_admin: "telegram-command-docs-preview-admin",
        help_user_en: "telegram-command-docs-preview-user-en",
        help_user_ru: "telegram-command-docs-preview-user-ru",
        apps_en: "telegram-command-docs-preview-apps-en",
        apps_ru: "telegram-command-docs-preview-apps-ru",
        install_en: "telegram-command-docs-preview-install-en",
        install_ru: "telegram-command-docs-preview-install-ru",
        instruction_en: "telegram-command-docs-preview-instruction-en",
        instruction_ru: "telegram-command-docs-preview-instruction-ru",
        menu_user_root_en: "telegram-command-docs-preview-menu-user-root-en",
        menu_user_root_ru: "telegram-command-docs-preview-menu-user-root-ru",
        menu_user_subscription_en: "telegram-command-docs-preview-menu-user-subscription-en",
        menu_user_subscription_ru: "telegram-command-docs-preview-menu-user-subscription-ru",
        menu_user_config_en: "telegram-command-docs-preview-menu-user-config-en",
        menu_user_config_ru: "telegram-command-docs-preview-menu-user-config-ru",
        menu_user_setup_en: "telegram-command-docs-preview-menu-user-setup-en",
        menu_user_setup_ru: "telegram-command-docs-preview-menu-user-setup-ru",
        menu_admin_root: "telegram-command-docs-preview-menu-admin-root",
        menu_admin_clients: "telegram-command-docs-preview-menu-admin-clients",
        menu_admin_users: "telegram-command-docs-preview-menu-admin-users",
        menu_admin_invites: "telegram-command-docs-preview-menu-admin-invites",
        menu_admin_billing: "telegram-command-docs-preview-menu-admin-billing",
        menu_admin_broadcast: "telegram-command-docs-preview-menu-admin-broadcast",
        menu_admin_system: "telegram-command-docs-preview-menu-admin-system",
    };

    if (editor) {
        editor.value = payload.raw_config || "";
    }
    if (pathEl) {
        pathEl.textContent = payload.path || "—";
    }
    if (syntaxEl) {
        syntaxEl.textContent = payload.syntax_help || "";
    }
    Object.entries(previewTargets).forEach(([previewKey, elementId]) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = payload.preview?.[previewKey] || "";
        }
    });
    if (statusEl) {
        if (payload.valid) {
            statusEl.innerHTML = `<span class="badge text-bg-success">Valid</span> Текущий конфиг синтаксически корректен.`;
        } else {
            statusEl.innerHTML = `<span class="badge text-bg-warning">Fallback to defaults</span> ${escapeHtml(payload.error || "Invalid config.")}`;
        }
    }
}

async function refreshTelegramCommandDocs() {
    try {
        const response = await apiFetch("/api/telegram/command-docs");
        renderTelegramCommandDocs(await response.json());
    } catch (e) {
        const statusEl = document.getElementById("telegram-command-docs-status");
        if (statusEl) {
            statusEl.innerHTML = `<span class="text-danger">${escapeHtml(e.message)}</span>`;
        }
        toast(e.message, "danger");
    }
}

async function saveTelegramCommandDocs() {
    const editor = document.getElementById("telegram-command-docs-editor");
    const saveBtn = document.getElementById("telegram-command-docs-save");
    if (!editor || !saveBtn) {
        return;
    }

    saveBtn.disabled = true;
    try {
        const response = await apiFetch("/api/telegram/command-docs", {
            method: "PUT",
            body: JSON.stringify({ raw_config: editor.value }),
        });
        renderTelegramCommandDocs(await response.json());
        toast("Telegram bot command docs updated");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        saveBtn.disabled = false;
    }
}

async function resetTelegramCommandDocs() {
    const resetBtn = document.getElementById("telegram-command-docs-reset");
    if (!resetBtn) {
        return;
    }

    if (!window.confirm("Reset Telegram command docs to bundled defaults? This will overwrite the current custom file.")) {
        return;
    }

    resetBtn.disabled = true;
    try {
        const response = await apiFetch("/api/telegram/command-docs/reset", {
            method: "POST",
        });
        renderTelegramCommandDocs(await response.json());
        toast("Telegram bot command docs reset to defaults");
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        resetBtn.disabled = false;
    }
}

function setTelegramBillingFilter(filterValue) {
    telegramBillingFilter = filterValue;
    document.querySelectorAll("[data-telegram-filter]").forEach((button) => {
        button.classList.toggle("active", button.dataset.telegramFilter === filterValue);
    });
    renderTelegramUsers(telegramUsers);
}

function showTelegramUserAction(userId, action) {
    const modalEl = document.getElementById("telegramUserActionModal");
    if (!modalEl) {
        return;
    }
    const user = telegramUsers.find((item) => Number(item.telegram_user_id) === Number(userId)) || {};
    document.getElementById("telegram-user-action-user-id").value = String(userId);
    document.getElementById("telegram-user-action-kind").value = action;
    document.getElementById("telegram-user-action-user-label").value = String(userId);
    document.getElementById("telegram-user-action-title").textContent = {
        grant: "Grant paid access",
        discount: "Set user discount",
        expires: "Set subscription expiry",
    }[action] || "Telegram user action";

    document.getElementById("telegram-user-action-days-group").classList.toggle("d-none", action !== "grant");
    document.getElementById("telegram-user-action-discount-group").classList.toggle("d-none", action !== "discount");
    document.getElementById("telegram-user-action-expiry-group").classList.toggle("d-none", action !== "expires");

    document.getElementById("telegram-user-action-days").value = telegramBillingSummary?.settings?.subscription_period_days || 30;
    document.getElementById("telegram-user-action-discount").value = user.discount_percent || 0;
    document.getElementById("telegram-user-action-expiry").value = user.subscription_expires_at
        ? String(user.subscription_expires_at).slice(0, 10)
        : "";

    new bootstrap.Modal(modalEl).show();
}

async function saveTelegramUserAction() {
    const userId = document.getElementById("telegram-user-action-user-id").value;
    const action = document.getElementById("telegram-user-action-kind").value;
    const saveBtn = document.getElementById("telegram-user-action-save");
    if (!userId || !action || !saveBtn) {
        return;
    }
    saveBtn.disabled = true;
    try {
        if (action === "grant") {
            const days = Number(document.getElementById("telegram-user-action-days").value);
            if (!Number.isInteger(days) || days < 1) {
                throw new Error("Days must be a positive integer");
            }
            await apiFetch(`/api/telegram/users/${encodeURIComponent(userId)}/grant`, {
                method: "POST",
                body: JSON.stringify({ days }),
            });
        } else if (action === "discount") {
            const discount = Number(document.getElementById("telegram-user-action-discount").value);
            if (!Number.isInteger(discount) || discount < 0 || discount > 100) {
                throw new Error("Discount must be 0..100");
            }
            await apiFetch(`/api/telegram/users/${encodeURIComponent(userId)}/discount`, {
                method: "PUT",
                body: JSON.stringify(discount === 0 ? { clear: true } : { discount_percent: discount }),
            });
        } else if (action === "expires") {
            const expiresAt = document.getElementById("telegram-user-action-expiry").value;
            if (!expiresAt) {
                throw new Error("Choose expiry date");
            }
            await apiFetch(`/api/telegram/users/${encodeURIComponent(userId)}/expires`, {
                method: "PUT",
                body: JSON.stringify({ expires_at: expiresAt }),
            });
        }
        bootstrap.Modal.getInstance(document.getElementById("telegramUserActionModal")).hide();
        toast("Telegram user updated");
        await Promise.all([refreshTelegramBilling(), refreshXrayClients()]);
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        saveBtn.disabled = false;
    }
}

async function revokeTelegramUser(userId) {
    if (!window.confirm(`Revoke paid access and disable bound VLESS client for Telegram user ${userId}?`)) {
        return;
    }
    try {
        await apiFetch(`/api/telegram/users/${encodeURIComponent(userId)}/revoke`, {
            method: "POST",
        });
        toast("Telegram user revoked");
        await Promise.all([refreshTelegramBilling(), refreshXrayClients()]);
    } catch (e) {
        toast(e.message, "danger");
    }
}

function renderXraySettingsStatus(settings) {
    const statusEl = document.getElementById("xray-settings-status");
    if (!statusEl) {
        return;
    }

    const errors = settings.errors && settings.errors.length
        ? `<div class="mt-2 text-warning">${settings.errors.map((item) => escapeHtml(item)).join("<br>")}</div>`
        : "";
    const warnings = settings.warnings && settings.warnings.length
        ? `<div class="mt-2 text-muted">${settings.warnings.map((item) => escapeHtml(item)).join("<br>")}</div>`
        : "";

    statusEl.innerHTML = `
        <div class="d-flex flex-wrap align-items-center gap-2">
          <span class="badge ${settings.ready ? "text-bg-success" : "text-bg-warning"}">
            ${settings.ready ? "VLESS share settings ready" : "VLESS share settings incomplete"}
          </span>
          <span>Inbound: <code>${escapeHtml(settings.inbound_tag)}</code></span>
          <span>Endpoint: <code>${escapeHtml(settings.server)}:${escapeHtml(settings.port)}</code></span>
          <span>Transport: <code>${escapeHtml(settings.network)} / ${escapeHtml(settings.security)}</code></span>
          <span>Local: <code>socks ${escapeHtml(settings.local_socks_port)} / http ${escapeHtml(settings.local_http_port)}</code></span>
          <span>REALITY pbk: <code>${settings.reality_public_key_configured ? "configured" : "missing"}</code></span>
          <span>shortId: <code>${settings.reality_short_id_configured ? "configured" : "missing"}</code></span>
        </div>
        ${errors}
        ${warnings}
    `;
}

function renderXrayDoctorStatus(doctor) {
    const doctorEl = document.getElementById("xray-doctor-status");
    if (!doctorEl) {
        return;
    }

    const badgeClass = {
        ok: "text-bg-success",
        warn: "text-bg-warning",
        error: "text-bg-danger",
    };

    const checks = (doctor.checks || [])
        .map(
            (check) => `
                <div class="d-flex flex-wrap align-items-center gap-2 py-1 border-top border-secondary">
                  <span class="badge ${badgeClass[check.status] || "badge-disabled"}">${escapeHtml(check.status)}</span>
                  <strong>${escapeHtml(check.label)}</strong>
                  <span class="text-muted">${escapeHtml(check.detail)}</span>
                </div>
            `
        )
        .join("");

    doctorEl.innerHTML = `
        <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
          <span class="badge ${doctor.ready ? "text-bg-success" : "text-bg-danger"}">
            ${doctor.ready ? "Xray doctor ready" : "Xray doctor needs attention"}
          </span>
          <span class="text-muted">Read-only checklist перед Export / Validate / Apply и ручным smoke.</span>
        </div>
        ${checks}
    `;
}

function renderRoutingRuntimeStatus(runtime) {
    const runtimeEl = document.getElementById("routing-runtime-status");
    if (!runtimeEl) {
        return;
    }

    const lastAction = runtime.last_action
        ? `
            <div class="border-top border-secondary pt-2 mt-2">
              <div><strong>Last action:</strong> ${escapeHtml(runtime.last_action.action)} / ${escapeHtml(runtime.last_action.status)}</div>
              <div><strong>Updated:</strong> ${escapeHtml(formatDateTime(runtime.last_action.updated_at))}</div>
              <div class="mt-1">${escapeHtml(runtime.last_action.detail || "—")}</div>
              ${
                  runtime.last_action.live_config_path
                      ? `<div class="mt-1"><strong>Live:</strong> <code>${escapeHtml(runtime.last_action.live_config_path)}</code></div>`
                      : ""
              }
              ${
                  runtime.last_action.backup_path
                      ? `<div class="mt-1"><strong>Backup:</strong> <code>${escapeHtml(runtime.last_action.backup_path)}</code></div>`
                      : ""
              }
              ${
                  runtime.last_action.command && runtime.last_action.command.length
                      ? `<div class="mt-1"><code>${escapeHtml(runtime.last_action.command.join(" "))}</code></div>`
                      : ""
              }
            </div>
        `
        : '<div class="border-top border-secondary pt-2 mt-2 text-muted">Last action state пока не сохранён.</div>';

    const routingSyncBadge = runtime.routing_export_in_sync
        ? '<span class="badge text-bg-success">routing synced</span>'
        : '<span class="badge badge-disabled">routing stale</span>';

    let mergedSyncBadge = '<span class="badge badge-disabled">merged unavailable</span>';
    if (runtime.merged_config_export_in_sync === true) {
        mergedSyncBadge = '<span class="badge text-bg-success">merged synced</span>';
    } else if (runtime.merged_config_export_in_sync === false) {
        mergedSyncBadge = '<span class="badge badge-disabled">merged stale</span>';
    }

    const warnings = [
        runtime.base_config_error
            ? `<div class="text-warning mt-2">${escapeHtml(runtime.base_config_error)}</div>`
            : "",
        runtime.action_state_error
            ? `<div class="text-warning mt-1">${escapeHtml(runtime.action_state_error)}</div>`
            : "",
    ]
        .filter(Boolean)
        .join("");

    runtimeEl.innerHTML = `
        <div><strong>Export:</strong> <code>${escapeHtml(runtime.export_path)}</code></div>
        <div><strong>Merged export:</strong> <code>${escapeHtml(runtime.merged_config_path)}</code></div>
        <div><strong>Base config:</strong> <code>${escapeHtml(runtime.base_config_path)}</code></div>
        <div><strong>State file:</strong> <code>${escapeHtml(runtime.action_state_path)}</code></div>
        <div><strong>Apply backups:</strong> <code>${escapeHtml(runtime.apply_backup_dir)}</code></div>
        <div class="mt-1">
          <span class="badge ${runtime.export_exists ? "text-bg-success" : "badge-disabled"}">
            ${runtime.export_exists ? "export exists" : "export missing"}
          </span>
          <span class="badge ${runtime.merged_config_exists ? "text-bg-success" : "badge-disabled"}">
            ${runtime.merged_config_exists ? "merged exists" : "merged missing"}
          </span>
          <span class="badge ${runtime.base_config_exists ? "text-bg-success" : "badge-disabled"}">
            ${runtime.base_config_exists ? "base config exists" : "base config missing"}
          </span>
          <span class="badge ${runtime.action_state_exists ? "text-bg-success" : "badge-disabled"}">
            ${runtime.action_state_exists ? "state exists" : "state missing"}
          </span>
          <span class="badge ${runtime.validate_command_configured ? "text-bg-success" : "badge-disabled"}">
            ${runtime.validate_command_configured ? "validate configured" : "validate disabled"}
          </span>
          <span class="badge ${runtime.reload_command_configured ? "text-bg-success" : "badge-disabled"}">
            ${runtime.reload_command_configured ? "reload configured" : "reload disabled"}
          </span>
          ${routingSyncBadge}
          ${mergedSyncBadge}
        </div>
        <div class="mt-2 small">
          <div><strong>Current routing SHA:</strong> <code>${escapeHtml(runtime.current_routing_sha256)}</code></div>
          <div><strong>Exported routing SHA:</strong> <code>${escapeHtml(runtime.exported_routing_sha256 || "—")}</code></div>
          <div><strong>Current merged SHA:</strong> <code>${escapeHtml(runtime.current_merged_config_sha256 || "—")}</code></div>
          <div><strong>Exported merged SHA:</strong> <code>${escapeHtml(runtime.exported_merged_config_sha256 || "—")}</code></div>
        </div>
        ${lastAction}
        ${warnings}
    `;
}

function showXrayClientModal(client = null) {
    const modalEl = document.getElementById("xrayClientModal");
    if (!modalEl) {
        return;
    }

    const modal = new bootstrap.Modal(modalEl);
    const title = document.getElementById("xray-client-title");
    const saveBtn = document.getElementById("xray-client-save-btn");
    const nameInput = document.getElementById("xray-client-name");
    const emailInput = document.getElementById("xray-client-email");

    if (!title || !saveBtn || !nameInput || !emailInput) {
        return;
    }

    if (client) {
        title.innerHTML = '<i class="bi bi-pencil-square"></i> Изменить VLESS клиента';
        saveBtn.dataset.clientId = client.id;
        nameInput.value = client.name;
        emailInput.value = client.email;
    } else {
        title.innerHTML = '<i class="bi bi-person-plus"></i> Новый VLESS клиент';
        saveBtn.dataset.clientId = "";
        nameInput.value = "";
        emailInput.value = "";
    }

    modal.show();
}

function showXrayClientEdit(clientId) {
    const client = xrayClients.find((item) => item.id === clientId);
    if (!client) {
        toast("Xray клиент не найден", "danger");
        return;
    }
    showXrayClientModal(client);
}

function renderXrayClients(clients) {
    const body = document.getElementById("xray-clients-body");
    if (!body) {
        return;
    }

    if (!clients.length) {
        body.innerHTML = `
            <tr>
              <td colspan="7" class="text-center text-muted py-4">
                VLESS клиентов пока нет. Создайте первого клиента и затем примените generated Xray config.
              </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = clients
        .map(
            (client) => `
                <tr>
                  <td>${escapeHtml(client.name)}</td>
                  <td>
                    ${renderXrayProtocolBadge("vless")}
                    <div class="small text-muted">default delivery</div>
                  </td>
                  <td>
                    <code>${escapeHtml(client.id)}</code>
                  </td>
                  <td class="small text-muted">${escapeHtml(client.email)}</td>
                  <td>
                    <span class="badge ${client.enabled ? "text-bg-success" : "badge-disabled"}">
                      ${escapeHtml(getXrayClientStatusLabel(client))}
                    </span>
                  </td>
                  <td class="small text-muted">${escapeHtml(formatDateTime(client.created_at))}</td>
                  <td>
                    <div class="d-flex gap-1 flex-wrap">
                      <button class="btn btn-outline-info btn-sm" type="button" title="Скопировать vless:// link"
                        onclick="copyXrayClientLink('${escapeHtml(client.id)}')">
                        <i class="bi bi-link-45deg"></i>
                      </button>
                      <button class="btn btn-outline-info btn-sm" type="button" title="QR"
                        onclick="showXrayClientQR('${escapeHtml(client.id)}', decodeURIComponent('${encodeURIComponent(client.name)}'))">
                        <i class="bi bi-qr-code"></i>
                      </button>
                      <a class="btn btn-outline-secondary btn-sm" title="Full Xray client JSON"
                        href="/api/xray/clients/${encodeURIComponent(client.id)}/config">
                        <i class="bi bi-download"></i>
                      </a>
                      <a class="btn btn-outline-secondary btn-sm" title="Smoke bundle: link, JSON, doctor, checklist"
                        href="/api/xray/clients/${encodeURIComponent(client.id)}/bundle">
                        <i class="bi bi-file-zip"></i>
                      </a>
                      <button class="btn btn-outline-primary btn-sm" type="button" title="Artifacts / protocols"
                        onclick="showXrayClientArtifacts('${escapeHtml(client.id)}', decodeURIComponent('${encodeURIComponent(client.name)}'))">
                        <i class="bi bi-collection"></i>
                      </button>
                      <button class="btn btn-outline-secondary btn-sm" type="button" title="Изменить"
                        onclick="showXrayClientEdit('${escapeHtml(client.id)}')">
                        <i class="bi bi-pencil"></i>
                      </button>
                      <button class="btn btn-outline-${client.enabled ? "warning" : "success"} btn-sm" type="button"
                        title="${client.enabled ? "Выключить" : "Включить"}"
                        onclick="toggleXrayClient('${escapeHtml(client.id)}')">
                        <i class="bi ${client.enabled ? "bi-pause-circle" : "bi-play-circle"}"></i>
                      </button>
                      <button class="btn btn-outline-danger btn-sm" type="button" title="Удалить"
                        onclick="deleteXrayClient('${escapeHtml(client.id)}', decodeURIComponent('${encodeURIComponent(client.name)}'))">
                        <i class="bi bi-trash3"></i>
                      </button>
                    </div>
                  </td>
                </tr>
            `
        )
        .join("");
}

async function refreshXrayClients() {
    const body = document.getElementById("xray-clients-body");
    if (!body) {
        return;
    }

    try {
        const [clientsResponse, settingsResponse, doctorResponse] = await Promise.all([
            apiFetch("/api/xray/clients"),
            apiFetch("/api/xray/settings"),
            apiFetch("/api/xray/doctor"),
        ]);
        const [clients, settings, doctor] = await Promise.all([
            clientsResponse.json(),
            settingsResponse.json(),
            doctorResponse.json(),
        ]);
        xrayClients = clients;
        xrayClientArtifactCatalogs = {};
        renderXraySettingsStatus(settings);
        renderXrayDoctorStatus(doctor);
        renderXrayClients(xrayClients);
    } catch (e) {
        body.innerHTML = `
            <tr>
              <td colspan="7" class="text-center text-danger py-4">
                Не удалось загрузить Xray клиентов: ${escapeHtml(e.message)}
              </td>
            </tr>
        `;
        toast(e.message, "danger");
    }
}

async function refreshXrayState() {
    await Promise.all([refreshXrayClients(), refreshRoutingOverrides()]);
}

async function showXrayClientArtifacts(clientId, name) {
    const modalEl = document.getElementById("xrayClientArtifactsModal");
    const titleEl = document.getElementById("xray-client-artifacts-title");
    const subtitleEl = document.getElementById("xray-client-artifacts-subtitle");
    const loadingEl = document.getElementById("xray-client-artifacts-loading");
    const errorEl = document.getElementById("xray-client-artifacts-error");
    const listEl = document.getElementById("xray-client-artifacts-list");
    if (!modalEl || !titleEl || !subtitleEl || !loadingEl || !errorEl || !listEl) {
        return;
    }

    const modal = new bootstrap.Modal(modalEl);
    titleEl.textContent = name;
    subtitleEl.innerHTML = `Client <code>${escapeHtml(clientId)}</code>`;
    loadingEl.classList.remove("d-none");
    errorEl.classList.add("d-none");
    errorEl.textContent = "";
    listEl.innerHTML = "";
    modal.show();

    try {
        const catalog = await fetchXrayClientArtifactCatalog(clientId);
        const availableProtocols = catalog.available_protocols || [];
        subtitleEl.innerHTML = `
            Default protocol: <strong>${escapeHtml(getXrayProtocolLabel(catalog.default_protocol))}</strong>
            <span class="text-muted">· client <code>${escapeHtml(catalog.client_id)}</code></span>
        `;
        if (!availableProtocols.length) {
            listEl.innerHTML = `
                <div class="text-center text-muted py-4">
                  Для этого клиента пока нет доступных protocol artifacts.
                </div>
            `;
            return;
        }

        listEl.innerHTML = availableProtocols
            .map((option) => {
                const encodedName = encodeURIComponent(catalog.client_name || name || clientId);
                const isDefault = option.protocol === catalog.default_protocol;
                return `
                    <div class="card border-secondary bg-body-tertiary">
                      <div class="card-body py-3">
                        <div class="d-flex flex-wrap justify-content-between align-items-start gap-2">
                          <div>
                            <div class="fw-semibold">${escapeHtml(option.label || getXrayProtocolLabel(option.protocol))}</div>
                            <div class="small text-muted">
                              <code>${escapeHtml(option.protocol)}</code>
                              ${isDefault ? '<span class="ms-1">default delivery path</span>' : ""}
                            </div>
                          </div>
                          ${renderXrayProtocolBadge(option.protocol)}
                        </div>
                        <div class="d-flex gap-2 flex-wrap mt-3">
                          <button class="btn btn-outline-info btn-sm" type="button"
                            onclick="copyXrayClientLink('${escapeHtml(catalog.client_id)}', '${escapeHtml(option.protocol)}')">
                            <i class="bi bi-link-45deg"></i> Link
                          </button>
                          <button class="btn btn-outline-info btn-sm" type="button"
                            onclick="showXrayClientQR('${escapeHtml(catalog.client_id)}', decodeURIComponent('${encodedName}'), '${escapeHtml(option.protocol)}')">
                            <i class="bi bi-qr-code"></i> QR
                          </button>
                          <a class="btn btn-outline-secondary btn-sm" href="${escapeHtml(option.config_endpoint)}">
                            <i class="bi bi-download"></i> Config
                          </a>
                          <a class="btn btn-outline-secondary btn-sm" href="${escapeHtml(option.bundle_endpoint)}">
                            <i class="bi bi-file-zip"></i> Bundle
                          </a>
                        </div>
                      </div>
                    </div>
                `;
            })
            .join("");
    } catch (e) {
        errorEl.textContent = e.message;
        errorEl.classList.remove("d-none");
    } finally {
        loadingEl.classList.add("d-none");
    }
}

async function copyXrayClientLink(clientId, protocol = null) {
    try {
        const artifact = await resolveXrayClientArtifactOption(clientId, protocol);
        const response = await apiFetch(artifact.share_endpoint);
        const payload = await response.json();
        if (!payload.settings_ready) {
            toast(
                `${getXrayProtocolLabel(artifact.protocol, artifact.label)} settings incomplete: ${payload.settings_errors.join("; ")}`,
                "warning"
            );
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(payload.share_link);
            toast(`${getXrayProtocolLabel(artifact.protocol, artifact.label)} link скопирован`);
        } else {
            window.prompt(`${getXrayProtocolLabel(artifact.protocol, artifact.label)} link`, payload.share_link);
        }
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function showXrayClientQR(clientId, name, protocol = null) {
    const modal = new bootstrap.Modal(document.getElementById("qrModal"));
    const img = document.getElementById("qr-img");
    const spinner = document.getElementById("qr-spinner");
    const errEl = document.getElementById("qr-error");
    const nameEl = document.getElementById("qr-name");
    const dlBtn = document.getElementById("qr-download");

    img.classList.add("d-none");
    errEl.classList.add("d-none");
    spinner.classList.remove("d-none");
    nameEl.textContent = name;
    img.removeAttribute("src");
    modal.show();

    try {
        const artifact = await resolveXrayClientArtifactOption(clientId, protocol);
        img.onload = () => {
            spinner.classList.add("d-none");
            img.classList.remove("d-none");
        };
        img.onerror = () => {
            spinner.classList.add("d-none");
            errEl.textContent = `${getXrayProtocolLabel(artifact.protocol, artifact.label)} QR недоступен.`;
            errEl.classList.remove("d-none");
        };
        img.src = artifact.qr_endpoint;
        dlBtn.href = artifact.config_endpoint;
        dlBtn.download = artifact.protocol === "vless"
            ? `${name}.xray-client.json`
            : `${name}.${artifact.protocol}.config`;
    } catch (e) {
        spinner.classList.add("d-none");
        errEl.textContent = e.message;
        errEl.classList.remove("d-none");
    }
}

function setRoutingActionResult(payload) {
    const resultEl = document.getElementById("routing-action-result");
    if (!resultEl) {
        return;
    }
    resultEl.textContent = JSON.stringify(payload, null, 2);
}

function showRoutingOverrideModal(override = null) {
    const modalEl = document.getElementById("routingOverrideModal");
    if (!modalEl) {
        return;
    }

    const modal = new bootstrap.Modal(modalEl);
    const title = document.getElementById("routing-override-title");
    const saveBtn = document.getElementById("routing-override-save-btn");
    const valueInput = document.getElementById("routing-override-value");
    const matchTypeInput = document.getElementById("routing-override-match-type");
    const routeInput = document.getElementById("routing-override-route");
    const commentInput = document.getElementById("routing-override-comment");

    if (!title || !saveBtn || !valueInput || !matchTypeInput || !routeInput || !commentInput) {
        return;
    }

    if (override) {
        title.innerHTML = '<i class="bi bi-pencil-square"></i> Изменить правило';
        saveBtn.dataset.overrideId = override.id;
        valueInput.value = override.value;
        matchTypeInput.value = override.match_type;
        routeInput.value = override.route;
        commentInput.value = override.comment || "";
    } else {
        title.innerHTML = '<i class="bi bi-signpost-split"></i> Новое правило';
        saveBtn.dataset.overrideId = "";
        valueInput.value = "";
        matchTypeInput.value = "exact";
        routeInput.value = "ru";
        commentInput.value = "";
    }

    modal.show();
}

function showRoutingOverrideEdit(overrideId) {
    const override = routingOverrides.find((item) => item.id === overrideId);
    if (!override) {
        toast("Правило не найдено", "danger");
        return;
    }
    showRoutingOverrideModal(override);
}

function renderRoutingPreview(preview) {
    const countEl = document.getElementById("routing-manual-count");
    const orderEl = document.getElementById("routing-preview-order");
    const manualEl = document.getElementById("routing-preview-manual");
    const jsonEl = document.getElementById("routing-preview-json");

    if (!countEl || !orderEl || !manualEl || !jsonEl) {
        return;
    }

    countEl.textContent = `${preview.manual_overrides_enabled} active`;
    orderEl.innerHTML = preview.routing_order
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("");
    jsonEl.textContent = JSON.stringify(preview.rendered_routing, null, 2);

    if (!preview.manual_rules.length) {
        manualEl.innerHTML = '<div class="text-muted small">Активных ручных правил пока нет.</div>';
        return;
    }

    manualEl.innerHTML = preview.manual_rules
        .map(
            (rule) => `
                <div class="preview-rule-card">
                  <div class="d-flex justify-content-between align-items-center gap-2 mb-2">
                    <span class="badge ${getRouteBadgeClass(rule.route)}">${escapeHtml(getRouteLabel(rule.route))}</span>
                    <span class="badge text-bg-dark">#${rule.priority}</span>
                  </div>
                  <div class="small fw-semibold">${escapeHtml(rule.rendered_rule)}</div>
                  <div class="small text-muted mt-1">${escapeHtml(getMatchTypeLabel(rule.match_type))}: ${escapeHtml(rule.value)}</div>
                </div>
            `
        )
        .join("");
}

function renderRoutingCheckResult(payload) {
    const resultEl = document.getElementById("routing-check-result");
    if (!resultEl) {
        return;
    }

    if (payload.matched) {
        const sourceLabel = payload.source === "manual_override" ? "manual match" : "built-in .ru/.рф";
        const sourceClass = payload.source === "manual_override" ? "text-bg-success" : "text-bg-info";
        resultEl.innerHTML = `
            <div class="preview-rule-card">
              <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                <span class="badge ${sourceClass}">${escapeHtml(sourceLabel)}</span>
                <span class="badge ${getRouteBadgeClass(payload.route)}">${escapeHtml(getRouteLabel(payload.route))}</span>
                <span class="badge text-bg-dark">${escapeHtml(getMatchTypeLabel(payload.match_type))}</span>
              </div>
              <div><strong>${escapeHtml(payload.normalized_value)}</strong> -> <code>${escapeHtml(payload.outbound)}</code></div>
              <div class="text-muted mt-1">${escapeHtml(payload.rendered_rule)}</div>
              <div class="text-muted mt-1">${escapeHtml(payload.detail)}</div>
            </div>
        `;
        return;
    }

    resultEl.innerHTML = `
        <div class="preview-rule-card">
          <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
            <span class="badge text-bg-warning">no manual match</span>
            <span class="badge text-bg-dark">fallback</span>
          </div>
          <div><strong>${escapeHtml(payload.normalized_value)}</strong></div>
          <div class="text-muted mt-1">${escapeHtml(payload.outbound)}</div>
        </div>
    `;
}

async function checkRoutingDomain() {
    const input = document.getElementById("routing-check-host");
    const button = document.getElementById("routing-check-btn");
    if (!input || !button) {
        return;
    }

    const host = input.value.trim();
    if (!host) {
        toast("Введите домен для проверки", "warning");
        return;
    }

    button.disabled = true;
    button.textContent = "Проверка...";
    try {
        const response = await apiFetch(`/api/routing/check?host=${encodeURIComponent(host)}`);
        const payload = await response.json();
        renderRoutingCheckResult(payload);
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        button.disabled = false;
        button.textContent = "Проверить";
    }
}

function renderRoutingOverrides(overrides) {
    const body = document.getElementById("routing-overrides-body");
    if (!body) {
        return;
    }

    if (!overrides.length) {
        body.innerHTML = `
            <tr>
              <td colspan="7" class="text-center text-muted py-4">
                Ручных routing rules пока нет. Добавьте первое правило для RU/direct или non-RU/via NL.
              </td>
            </tr>
        `;
        return;
    }

    body.innerHTML = overrides
        .map(
            (override) => `
                <tr>
                  <td>
                    <code>${escapeHtml(override.value)}</code>
                    <div class="small text-muted">${escapeHtml(override.normalized_value)}</div>
                  </td>
                  <td><span class="badge text-bg-dark">${escapeHtml(getMatchTypeLabel(override.match_type))}</span></td>
                  <td><span class="badge ${getRouteBadgeClass(override.route)}">${escapeHtml(getRouteLabel(override.route))}</span></td>
                  <td>
                    <span class="badge ${override.enabled ? "text-bg-success" : "badge-disabled"}">
                      ${override.enabled ? "Включено" : "Выключено"}
                    </span>
                  </td>
                  <td class="small text-muted">${escapeHtml(override.comment || "—")}</td>
                  <td class="small text-muted">${escapeHtml(formatDateTime(override.updated_at))}</td>
                  <td>
                    <div class="d-flex gap-1">
                      <button class="btn btn-outline-secondary btn-sm" type="button" title="Изменить"
                        onclick="showRoutingOverrideEdit('${escapeHtml(override.id)}')">
                        <i class="bi bi-pencil"></i>
                      </button>
                      <button class="btn btn-outline-${override.enabled ? "warning" : "success"} btn-sm" type="button"
                        title="${override.enabled ? "Выключить" : "Включить"}"
                        onclick="toggleRoutingOverride('${escapeHtml(override.id)}')">
                        <i class="bi ${override.enabled ? "bi-pause-circle" : "bi-play-circle"}"></i>
                      </button>
                      <button class="btn btn-outline-danger btn-sm" type="button" title="Удалить"
                        onclick="deleteRoutingOverride('${escapeHtml(override.id)}', decodeURIComponent('${encodeURIComponent(override.value)}'))">
                        <i class="bi bi-trash3"></i>
                      </button>
                    </div>
                  </td>
                </tr>
            `
        )
        .join("");
}

async function refreshRoutingOverrides() {
    const body = document.getElementById("routing-overrides-body");
    if (!body) {
        return;
    }

    try {
        const [overridesResponse, previewResponse, runtimeResponse] = await Promise.all([
            apiFetch("/api/routing/overrides"),
            apiFetch("/api/routing/preview"),
            apiFetch("/api/routing/runtime"),
        ]);
        const [overrides, preview, runtime] = await Promise.all([
            overridesResponse.json(),
            previewResponse.json(),
            runtimeResponse.json(),
        ]);

        routingOverrides = overrides;
        renderRoutingOverrides(overrides);
        renderRoutingPreview(preview);
        renderRoutingRuntimeStatus(runtime);
    } catch (e) {
        body.innerHTML = `
            <tr>
              <td colspan="7" class="text-center text-danger py-4">
                Не удалось загрузить routing rules: ${escapeHtml(e.message)}
              </td>
            </tr>
        `;
        toast(e.message, "danger");
    }
}

async function runRoutingAction(action) {
    const validActions = new Set(["export", "validate", "reload", "apply"]);
    if (!validActions.has(action)) {
        return;
    }

    if (action === "apply" && !window.confirm("Apply will replace the live Xray config with config.generated.json, create a backup, and reload Xray. Continue?")) {
        return;
    }

    const actionLabels = {
        export: "Export",
        validate: "Validate",
        reload: "Reload Xray",
        apply: "Apply + Reload",
    };

    try {
        const response = await apiFetch(`/api/routing/${action}`, { method: "POST" });
        const payload = await response.json();
        setRoutingActionResult(payload);
        toast(`${actionLabels[action]} completed`);
        await refreshRoutingOverrides();
    } catch (e) {
        setRoutingActionResult({ status: "error", action, detail: e.message });
        toast(e.message, "danger");
        await refreshRoutingOverrides();
    }
}

function showDelete(pubkey, name) {
    deletePubkey = pubkey;
    document.getElementById("delete-name").textContent = name;
    new bootstrap.Modal(document.getElementById("deleteModal")).show();
}

function showRename(pubkey, name) {
    document.getElementById("rename-input").value = name;
    document.getElementById("rename-confirm-btn").dataset.pubkey = pubkey;
    new bootstrap.Modal(document.getElementById("renameModal")).show();
}

async function togglePeer(pubkey, action) {
    try {
        await apiFetch(`/api/peers/${encodeURIComponent(pubkey)}/${action}`, { method: "POST" });
        toast(action === "activate" ? "Пир активирован" : "Пир деактивирован");
        setTimeout(() => location.reload(), 800);
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function createPeer() {
    const name = document.getElementById("create-name").value.trim();
    if (!name) {
        toast("Введите имя", "warning");
        return;
    }

    const btn = document.getElementById("create-btn");
    btn.disabled = true;
    btn.textContent = "Создание...";

    try {
        const response = await apiFetch("/api/peers", {
            method: "POST",
            body: JSON.stringify({ name }),
        });
        const data = await response.json();

        const blob = new Blob([data.client_conf], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        document.getElementById("create-download").href = url;
        document.getElementById("create-download").download = `${name}.conf`;
        document.getElementById("create-qr").src = buildPeerArtifactEndpoint(data.public_key, "qr", "wg");
        document.getElementById("create-result").classList.remove("d-none");
        btn.classList.add("d-none");
    } catch (e) {
        toast(e.message, "danger");
        btn.disabled = false;
        btn.textContent = "Создать";
    }
}

async function saveRoutingOverride() {
    const saveBtn = document.getElementById("routing-override-save-btn");
    const valueInput = document.getElementById("routing-override-value");
    const matchTypeInput = document.getElementById("routing-override-match-type");
    const routeInput = document.getElementById("routing-override-route");
    const commentInput = document.getElementById("routing-override-comment");

    if (!saveBtn || !valueInput || !matchTypeInput || !routeInput || !commentInput) {
        return;
    }

    const value = valueInput.value.trim();
    if (!value) {
        toast("Введите домен", "warning");
        return;
    }

    const overrideId = saveBtn.dataset.overrideId;
    const isEdit = Boolean(overrideId);
    saveBtn.disabled = true;
    saveBtn.textContent = isEdit ? "Сохранение..." : "Создание...";

    try {
        await apiFetch(
            isEdit ? `/api/routing/overrides/${encodeURIComponent(overrideId)}` : "/api/routing/overrides",
            {
                method: isEdit ? "PUT" : "POST",
                body: JSON.stringify({
                    match_type: matchTypeInput.value,
                    value,
                    route: routeInput.value,
                    comment: commentInput.value.trim(),
                }),
            }
        );

        bootstrap.Modal.getInstance(document.getElementById("routingOverrideModal")).hide();
        toast(isEdit ? "Правило обновлено" : "Правило создано");
        await refreshRoutingOverrides();
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Сохранить";
    }
}

async function toggleRoutingOverride(overrideId) {
    try {
        await apiFetch(`/api/routing/overrides/${encodeURIComponent(overrideId)}/toggle`, {
            method: "POST",
        });
        toast("Статус правила обновлён");
        await refreshRoutingOverrides();
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function deleteRoutingOverride(overrideId, value) {
    if (!window.confirm(`Удалить routing rule для ${value}?`)) {
        return;
    }

    try {
        await apiFetch(`/api/routing/overrides/${encodeURIComponent(overrideId)}`, {
            method: "DELETE",
        });
        toast("Правило удалено");
        await refreshRoutingOverrides();
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function saveXrayClient() {
    const saveBtn = document.getElementById("xray-client-save-btn");
    const nameInput = document.getElementById("xray-client-name");
    const emailInput = document.getElementById("xray-client-email");

    if (!saveBtn || !nameInput || !emailInput) {
        return;
    }

    const name = nameInput.value.trim();
    if (!name) {
        toast("Введите имя VLESS клиента", "warning");
        return;
    }

    const clientId = saveBtn.dataset.clientId;
    const isEdit = Boolean(clientId);
    saveBtn.disabled = true;
    saveBtn.textContent = isEdit ? "Сохранение..." : "Создание...";

    try {
        await apiFetch(
            isEdit ? `/api/xray/clients/${encodeURIComponent(clientId)}` : "/api/xray/clients",
            {
                method: isEdit ? "PUT" : "POST",
                body: JSON.stringify({
                    name,
                    email: emailInput.value.trim() || null,
                }),
            }
        );

        bootstrap.Modal.getInstance(document.getElementById("xrayClientModal")).hide();
        toast(isEdit ? "VLESS клиент обновлён" : "VLESS клиент создан");
        await refreshXrayState();
    } catch (e) {
        toast(e.message, "danger");
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Сохранить";
    }
}

async function toggleXrayClient(clientId) {
    try {
        await apiFetch(`/api/xray/clients/${encodeURIComponent(clientId)}/toggle`, {
            method: "POST",
        });
        toast("Статус VLESS клиента обновлён");
        await refreshXrayState();
    } catch (e) {
        toast(e.message, "danger");
    }
}

async function deleteXrayClient(clientId, name) {
    if (!window.confirm(`Удалить VLESS клиента ${name}?`)) {
        return;
    }

    try {
        await apiFetch(`/api/xray/clients/${encodeURIComponent(clientId)}`, {
            method: "DELETE",
        });
        toast("VLESS клиент удалён");
        await refreshXrayState();
    } catch (e) {
        toast(e.message, "danger");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const deleteConfirmBtn = document.getElementById("delete-confirm-btn");
    if (deleteConfirmBtn) {
        deleteConfirmBtn.addEventListener("click", async () => {
            if (!deletePubkey) {
                return;
            }
            try {
                await apiFetch(`/api/peers/${encodeURIComponent(deletePubkey)}`, { method: "DELETE" });
                toast("Пир удалён");
                bootstrap.Modal.getInstance(document.getElementById("deleteModal")).hide();
                setTimeout(() => location.reload(), 800);
            } catch (e) {
                toast(e.message, "danger");
            }
        });
    }

    const renameConfirmBtn = document.getElementById("rename-confirm-btn");
    if (renameConfirmBtn) {
        renameConfirmBtn.addEventListener("click", async () => {
            const pubkey = renameConfirmBtn.dataset.pubkey;
            const name = document.getElementById("rename-input").value.trim();
            if (!name) {
                return;
            }
            try {
                await apiFetch(`/api/peers/${encodeURIComponent(pubkey)}`, {
                    method: "PUT",
                    body: JSON.stringify({ name }),
                });
                toast("Имя обновлено");
                bootstrap.Modal.getInstance(document.getElementById("renameModal")).hide();
                setTimeout(() => location.reload(), 800);
            } catch (e) {
                toast(e.message, "danger");
            }
        });
    }

    const routingSaveBtn = document.getElementById("routing-override-save-btn");
    if (routingSaveBtn) {
        routingSaveBtn.addEventListener("click", saveRoutingOverride);
        refreshRoutingOverrides();
    }

    const routingCheckBtn = document.getElementById("routing-check-btn");
    const routingCheckInput = document.getElementById("routing-check-host");
    if (routingCheckBtn) {
        routingCheckBtn.addEventListener("click", checkRoutingDomain);
    }
    if (routingCheckInput) {
        routingCheckInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                checkRoutingDomain();
            }
        });
    }

    const xrayClientSaveBtn = document.getElementById("xray-client-save-btn");
    if (xrayClientSaveBtn) {
        xrayClientSaveBtn.addEventListener("click", saveXrayClient);
        refreshXrayClients();
    }

    const telegramPriceSaveBtn = document.getElementById("telegram-billing-price-save");
    if (telegramPriceSaveBtn) {
        telegramPriceSaveBtn.addEventListener("click", saveTelegramBillingPrice);
        refreshTelegramBilling();
        refreshTelegramSupport();
    }

    const telegramTrialSaveBtn = document.getElementById("telegram-billing-trial-save");
    if (telegramTrialSaveBtn) {
        telegramTrialSaveBtn.addEventListener("click", saveTelegramBillingTrial);
    }

    const telegramMaxDiscountSaveBtn = document.getElementById("telegram-billing-max-discount-save");
    if (telegramMaxDiscountSaveBtn) {
        telegramMaxDiscountSaveBtn.addEventListener("click", saveTelegramBillingMaxDiscount);
    }

    document.querySelectorAll("[data-telegram-filter]").forEach((button) => {
        button.addEventListener("click", () => setTelegramBillingFilter(button.dataset.telegramFilter || "all"));
    });

    const telegramUsersSearch = document.getElementById("telegram-users-search");
    if (telegramUsersSearch) {
        telegramUsersSearch.addEventListener("input", () => renderTelegramUsers(telegramUsers));
    }

    const telegramUserActionSave = document.getElementById("telegram-user-action-save");
    if (telegramUserActionSave) {
        telegramUserActionSave.addEventListener("click", saveTelegramUserAction);
    }

    const telegramCommandDocsSaveBtn = document.getElementById("telegram-command-docs-save");
    if (telegramCommandDocsSaveBtn) {
        telegramCommandDocsSaveBtn.addEventListener("click", saveTelegramCommandDocs);
        refreshTelegramCommandDocs();
    }

    const telegramCommandDocsResetBtn = document.getElementById("telegram-command-docs-reset");
    if (telegramCommandDocsResetBtn) {
        telegramCommandDocsResetBtn.addEventListener("click", resetTelegramCommandDocs);
    }

    const telegramSupportMarkReadBtn = document.getElementById("telegram-support-mark-read");
    if (telegramSupportMarkReadBtn) {
        telegramSupportMarkReadBtn.addEventListener("click", markTelegramSupportTicketRead);
    }

    const telegramSupportArchiveBtn = document.getElementById("telegram-support-archive");
    if (telegramSupportArchiveBtn) {
        telegramSupportArchiveBtn.addEventListener("click", archiveTelegramSupportTicket);
    }

    const telegramSupportReplyBtn = document.getElementById("telegram-support-reply-send");
    if (telegramSupportReplyBtn) {
        telegramSupportReplyBtn.addEventListener("click", replyTelegramSupportTicket);
    }
});
