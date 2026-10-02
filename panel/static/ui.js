"use strict";
(async () => {
    const language = document.documentElement.lang;
    const dictionary = await fetch(`/static/i18n/${language}.json`).then(r => r.json());
    const t = key => dictionary[key] || key;
    const body = document.body, admin = body.dataset.role === "admin", portal = body.dataset.page === "portal";
    const view = document.getElementById("view"), actions = document.getElementById("page-actions");
    const modal = document.getElementById("modal"), modalContent = document.getElementById("modal-content");
    const notice = document.getElementById("notice");
    let tab = portal ? "My devices" : "Dashboard", rows = [], columns = [], rowActions = () => [];
    const el = (tag, text = "", cls = "") => {
        const node = document.createElement(tag); node.textContent = text; if (cls) node.className = cls; return node;
    };
    const message = (value, error = false) => { notice.textContent = value; notice.className = error ? "error" : ""; };
    async function request(url, method = "GET", payload, blob = false) {
        const headers = {"X-CSRF-Token": body.dataset.csrf || ""};
        if (payload !== undefined) headers["Content-Type"] = "application/json";
        const response = await fetch(url, {method, headers, credentials: "same-origin", body: payload === undefined ? undefined : JSON.stringify(payload)});
        if (!response.ok) {
            if (response.status === 401) location.assign("/login");
            let error; try { error = (await response.json()).detail; } catch (_) { error = response.statusText; }
            throw new Error(typeof error === "string" ? error : JSON.stringify(error));
        }
        return blob ? response.blob() : response.json();
    }
    function button(label, handler) {
        const node = el("button", t(label)); node.type = "button";
        node.addEventListener("click", async () => {
            node.disabled = true;
            try { await handler(); } catch (error) { message(error.message, true); }
            finally { node.disabled = false; }
        }); return node;
    }
    function show(title, content) {
        modalContent.replaceChildren(el("h2", t(title)), content, button("Cancel", () => modal.close())); modal.showModal();
    }
    function showText(title, content) { show(title, el("pre", typeof content === "string" ? content : JSON.stringify(content, null, 2))); }
    async function download(url, filename) {
        const blob = await request(url, "GET", undefined, true);
        const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = filename;
        document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    }
    async function mutate(url, method = "POST", payload, confirm = false) {
        if (confirm && !window.confirm(t("Confirm this action?"))) return;
        await request(url, method, payload); message(t("Operation complete")); await load();
    }
    function form(title, fields, initial, save) {
        const node = el("form"), controls = {};
        for (const field of fields) {
            const [key, label, type = "text", options = [], fallback = ""] = field;
            const wrapper = el("label", t(label));
            const input = el(type === "select" ? "select" : type === "textarea" ? "textarea" : "input");
            if (type === "select") for (const option of options) {
                const item = el("option", Array.isArray(option) ? option[1] : option); item.value = Array.isArray(option) ? option[0] : option; input.append(item);
            }
            if (input.tagName === "INPUT") input.type = type === "number" ? "number" : "text";
            const value = initial[key] ?? fallback; input.value = Array.isArray(value) ? value.join(", ") : value;
            input.name = key; controls[key] = {input, type}; wrapper.append(input); node.append(wrapper);
        }
        const submit = el("button", t("Save")); submit.type = "submit"; node.append(submit);
        node.addEventListener("submit", async event => {
            event.preventDefault(); submit.disabled = true;
            const values = {};
            for (const [key, {input, type}] of Object.entries(controls)) values[key] = type === "number" ? Number(input.value) : type === "csv" ? input.value.split(",").map(x => x.trim()).filter(Boolean) : input.value;
            try { const result=await save(values); if(result!==false)modal.close(); message(t("Operation complete")); await load(); }
            catch (error) { message(error.message, true); }
            finally { submit.disabled = false; }
        }); show(title, node);
    }
    async function choices(url, label = "name") { return (await request(url)).map(x => [x.id, x[label] || x.username || x.id]); }
    function table() {
        const filter = (document.getElementById("search")?.value || "").toLowerCase();
        const wrapper = el("div", "", "table-wrap"), table = el("table"), head = el("thead"), line = el("tr");
        columns.forEach(([key, label]) => line.append(el("th", t(label)))); line.append(el("th", t("Actions"))); head.append(line); table.append(head);
        const tbody = el("tbody");
        for (const row of rows) {
            if (filter && !JSON.stringify(row).toLowerCase().includes(filter)) continue;
            const tr = el("tr");
            columns.forEach(([key]) => { const value = row[key]; tr.append(el("td", typeof value === "object" ? JSON.stringify(value) : String(value ?? ""))); });
            const cell = el("td"), tools = el("div", "", "toolbar"); for (const [label, handler] of rowActions(row)) tools.append(button(label, handler)); cell.append(tools); tr.append(cell); tbody.append(tr);
        }
        if (!tbody.children.length) { const tr = el("tr"), td = el("td", t("No entries")); td.colSpan = columns.length + 1; tr.append(td); tbody.append(tr); }
        table.append(tbody); wrapper.append(table); view.replaceChildren(wrapper);
    }
    const profileFields = [ ["name", "Name"], ["description", "Description"], ["tunnel_mode", "Tunnel mode", "select", ["full", "split"], "full"], ["allowed_cidrs", "Allowed networks", "csv"], ["dns_servers", "DNS servers", "csv"], ["search_domains", "Search domains", "csv"], ["protocols", "Protocols", "csv", [], "wg,awg,vless"], ["max_devices", "Device limit", "number", [], 3], ["device_ttl_days", "Device TTL (days)", "number", [], 0] ];
    async function userForm(row) {
        const profiles = [["", t("Set default")], ...await choices("/api/profiles")];
        const fields = row ? [] : [["username", "Username"]];
        fields.push(["display_name", "Display name"], ["role", "Role", "select", ["user", "operator", "admin"], "user"], ["access_profile_id", "Profile", "select", profiles]);
        form(row ? "Edit" : "Create", fields, row || {}, values => request("/api/auth/local-users" + (row ? "/" + row.id : ""), row ? "PUT" : "POST", values));
    }
    async function deviceForm() {
        const users = portal ? [] : await choices("/api/users/brief", "display_name");
        const fields = [["name", "Name"], ["protocol", "Protocol", "select", portal ? (await request("/api/me/devices")).profile.protocols : ["wg", "awg", "vless"], "wg"]];
        if (!portal) fields.push(["user_id", "User", "select", users]);
        form("Add device", fields, {}, values => request(portal ? "/api/me/devices" : "/api/devices", "POST", values));
    }
    async function factorSetup() {
        const factor = await request("/api/me/totp/start", "POST");
        const content = el("div"); content.append(el("p", t("Authenticator secret")), el("code", factor.secret));
        const link = el("a", t("Open authenticator")); link.href = factor.uri; content.append(link);
        const input = el("input"); input.autocomplete = "one-time-code"; content.append(input);
        content.append(button("Save", async () => { const result = await request("/api/me/totp/confirm", "POST", {code: input.value}); showText("Save recovery codes", result.recovery_codes.join("\n")); })); show("TOTP setup", content);
    }
    async function qr(url) {
        const blob = await request(url, "GET", undefined, true), reader = new FileReader(), image = el("img", "", "qr");
        const source=await new Promise((resolve,reject)=>{reader.onload=()=>resolve(reader.result);reader.onerror=reject;reader.readAsDataURL(blob);});image.src=source;image.alt=t("QR code");show("QR code", image);
    }
    async function load() {
        if (!view) return;
        const title = document.getElementById("page-title"); if (title) title.textContent = t(tab);
        actions.replaceChildren(button("Refresh", load));
        if (tab === "Dashboard") {
            const result = await request("/api/vpn/status");
            const extra = admin ? await request("/api/health") : await request("/api/xray/doctor");
            const cards = el("div", "", "cards"); for (const [name,value] of [["WireGuard",result],["Status",extra]]) { const card=el("section", "", "card"); card.append(el("h2",t(name)),el("pre",JSON.stringify(value,null,2)));cards.append(card); }
            view.replaceChildren(cards); return;
        }
        if (tab === "Devices" || tab === "My devices") {
            const result = await request(portal ? "/api/me/devices" : "/api/devices?include_revoked=true"); rows = portal ? result.devices : result;
            columns = [["name","Name"],["owner","User"],["protocol","Protocol"],["status","Status"]];
            actions.append(button(portal ? "Add device" : "Issue device",deviceForm));
            if (portal && body.dataset.localAccount === "true") actions.append(button("TOTP setup",factorSetup));
            rowActions = row => {
                const path = (portal ? "/api/me/devices/" : "/api/devices/") + row.id, options = [];
                if (portal && row.status === "active") options.push(["Download",()=>download(path+"/config",row.name+(row.protocol === "vless" ? ".json" : ".conf"))],["QR code",()=>qr(path+"/qr")]);
                if (!portal && row.status !== "revoked") options.push([row.status === "active" ? "Suspend" : "Resume",()=>mutate(path+(row.status === "active" ? "/suspend" : "/resume"))],["Assign", async()=>form("Assign",[["user_id","User","select",await choices("/api/users/brief","display_name")]],{},values=>request(path+"/assign","POST",values))]);
                if (row.status !== "revoked") options.push(["Revoke",()=>mutate(path,"DELETE",undefined,true)]);
                return options;
            };
        } else if (tab === "Diagnostics") {
            const results = await Promise.all([request("/api/health"),request("/api/xray/doctor"),request("/api/xray/settings"),request("/api/routing/runtime")]);
            const cards=el("div","","cards");
            for(const [index,label] of ["Gateway","Xray","Client settings","Routing"].entries()) {const card=el("section","","card");card.append(el("h2",t(label)),el("pre",JSON.stringify(results[index],null,2)));cards.append(card);}
            actions.append(button("Validate",()=>mutate("/api/routing/validate")));view.replaceChildren(cards);return;
        } else if (tab === "Configuration links") {
            rows=await request("/api/config-links");columns=[["label","Name"],["state","Status"],["expires_at","Expires (days)"]];
            rowActions=row=>row.state==="active"?[["Revoke",()=>mutate("/api/config-links/"+row.code,"DELETE",undefined,true)]]:[];
        } else if (tab === "Address pools") {
            rows=[await request("/api/network/pools")];columns=[["network","WireGuard"],["awg_network","AmneziaWG"],["size","Size"],["used","Used"],["free","Free"]];rowActions=()=>[];
        } else if (tab === "Access profiles") {
            rows = await request("/api/profiles"); columns = [["name","Name"],["tunnel_mode","Tunnel mode"],["allowed_cidrs","Allowed networks"],["max_devices","Device limit"]];
            actions.append(button("Create",()=>form("Create",profileFields,{},values=>request("/api/profiles","POST",values))),button("Apply policy",()=>mutate("/api/network/policy/apply")),button("View policy",async()=>showText("View policy",await request("/api/network/policy"))));
            rowActions = row => [["Edit",()=>form("Edit",profileFields,row,values=>request("/api/profiles/"+row.id,"PUT",values))],["Set default",()=>mutate("/api/profiles/"+row.id+"/default")],["Delete",()=>mutate("/api/profiles/"+row.id,"DELETE",undefined,true)]];
        } else if (tab === "Local users" || tab === "Directory users") {
            rows = await request(tab === "Local users" ? "/api/auth/local-users" : "/api/auth/users");columns=[["username","Username"],["provider","Provider"],["role","Role"],["status","Status"],["attestation_due_at","Expires (days)"]];
            if (tab === "Local users") actions.append(button("Create",()=>userForm(null)));
            else actions.append(button("Test providers",async()=>showText("Test providers",await request("/api/auth/providers/test","POST"))),button("Sync directory",async()=>{showText("Sync directory",await request("/api/auth/sync","POST"));}));
            rowActions = row => {
                const options = [[row.status === "active" ? "Disable" : "Enable",()=>mutate("/api/auth/users/"+row.id+(row.status === "active" ? "/disable" : "/enable"),"POST",undefined,true)]];
                if (tab === "Local users") options.unshift(["Edit",()=>userForm(row)],["Invite / reset",async()=>{if(window.confirm(t("Confirm this action?")))showText("Invite / reset",(await request("/api/auth/local-users/"+row.id+"/invite","POST")).invite_url);}]);return options;
            };
        } else if (tab === "Group policies") {
            rows=await request("/api/auth/policies");columns=[["provider","Provider"],["group_name","Group"],["role","Role"],["priority","Priority"]];
            const edit=async row=>form(row ? "Edit":"Create",[["provider","Provider","select",["any","oidc","ldap"],"any"],["group_name","Group"],["role","Role","select",["user","operator","admin"],"user"],["priority","Priority","number",[],100],["access_profile_id","Profile","select",[["",t("Set default")],...await choices("/api/profiles")]]],row||{},values=>request("/api/auth/policies"+(row?"/"+row.id:""),row?"PUT":"POST",values));
            actions.append(button("Create",()=>edit(null)));rowActions=row=>[["Edit",()=>edit(row)],["Delete",()=>mutate("/api/auth/policies/"+row.id,"DELETE",undefined,true)]];
        } else if (tab === "API tokens") {
            rows=await request("/api/auth/tokens");columns=[["name","Name"],["role","Role"],["expires_at","Expires (days)"],["revoked","Status"]];
            actions.append(button("Create",()=>form("Create",[["name","Name"],["role","Role","select",["metrics","auditor","user","operator","admin"],"metrics"],["ttl_days","Expires (days)","number",[],30]],{},async values=>{const result=await request("/api/auth/tokens","POST",values);window.prompt(t("API tokens"),result.token);})));rowActions=row=>row.revoked?[]:[["Revoke",()=>mutate("/api/auth/tokens/"+row.id,"DELETE",undefined,true)]];
        } else if (tab === "Audit") {
            rows=await request("/api/auth/audit?limit=1000");columns=[["ts","Status"],["actor","User"],["action","Actions"],["target","Value"]];rowActions=row=>[["View policy",()=>showText("Audit",row)]];
            actions.append(button("Export audit",async()=>{
                let cursor="",parts=[];
                do { const response=await fetch("/api/auth/audit/export?limit=1000&cursor="+encodeURIComponent(cursor),{credentials:"same-origin"});if(!response.ok)throw new Error(response.statusText);parts.push(await response.text());cursor=response.headers.get("X-Next-Cursor")||"";}while(cursor);
                const link=el("a");link.href=URL.createObjectURL(new Blob(parts,{type:"application/x-ndjson"}));link.download="corpvpn-audit.jsonl";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(link.href),1000);
            }));
        } else if (tab === "Routing") {
            const result=await request("/api/routing/overrides");rows=Array.isArray(result)?result:result.overrides||result.rules||[];columns=[["match_type","Match type"],["value","Value"],["route","Route"],["enabled","Status"]];
            const edit=row=>form(row?"Edit":"Create",[["match_type","Match type","select",["exact","suffix"],"exact"],["value","Value"],["route","Route","select",["direct","egress","block"],"direct"],["comment","Comment"]],row||{},values=>request("/api/routing/overrides"+(row?"/"+row.id:""),row?"PUT":"POST",values));
            actions.append(button("Create",()=>edit(null)),button("Preview",async()=>showText("Preview",await request("/api/routing/preview"))),button("Validate",()=>mutate("/api/routing/validate")),button("Apply",()=>mutate("/api/routing/apply","POST",undefined,true)),button("Check domain",()=>form("Check domain",[["host","Value"]],{},async values=>{showText("Check domain",await request("/api/routing/check?host="+encodeURIComponent(values.host)));return false;})));
            rowActions=row=>[["Edit",()=>edit(row)],["Enable",()=>mutate("/api/routing/overrides/"+row.id+"/toggle")],["Delete",()=>mutate("/api/routing/overrides/"+row.id,"DELETE",undefined,true)]];
        } else if (tab === "WireGuard" || tab === "AmneziaWG") {
            rows=await request("/api/peers");columns=[["name","Name"],[tab === "AmneziaWG" ? "awg_ip" : "vpn_ip","Value"],["status","Status"],["deactivated","Suspend"]];
            if(admin) actions.append(button("Create",()=>form("Create",[["name","Name"]],{},values=>request("/api/peers","POST",values))));
            rowActions=row=>{
                const path="/api/peers/"+encodeURIComponent(row.public_key), options=[[row.deactivated?"Enable":"Disable",()=>mutate(path+(row.deactivated?"/activate":"/deactivate"))],["Delete",()=>mutate(path,"DELETE",undefined,true)]];
                if(admin)options.push(["Download",()=>download(path+"/config?protocol="+(tab==="AmneziaWG"?"amneziawg":"wg"),row.name+".conf")],["Invite / reset",()=>form("One-time configuration",[["label","Name"]],{label:row.name},async values=>{const result=await request("/api/config-links","POST",{peer_public_key:row.public_key,label:values.label});window.prompt(t("One-time configuration"),result.url||result.link_url||JSON.stringify(result));})]);return options;
            };
        } else if (tab === "VLESS") {
            const result=await request("/api/xray/clients");rows=Array.isArray(result)?result:result.clients||[];columns=[["name","Name"],["email","User"],["enabled","Status"]];
            if(admin)actions.append(button("Create",()=>form("Create",[["name","Name"]],{},values=>request("/api/xray/clients","POST",values))));
            rowActions=row=>{
                if(!admin)return [];
                const path="/api/xray/clients/"+encodeURIComponent(row.id), options=[["Edit",()=>form("Edit",[["name","Name"],["email","User"]],row,values=>request(path,"PUT",values))],[row.enabled?"Disable":"Enable",()=>mutate(path+"/toggle")],["Delete",()=>mutate(path,"DELETE",undefined,true)]];
                if(admin)options.push(["Download",()=>download(path+"/config",row.name+".json")],["Bundle",()=>download(path+"/bundle",row.name+".zip")],["QR code",()=>qr(path+"/qr")]);return options;
            };
        }
        table();
    }
    if (view) {
        if(!portal){
            const nav=document.getElementById("navigation");for(const node of nav.querySelectorAll("button[data-tab]"))node.addEventListener("click",async()=>{tab=node.dataset.tab;nav.querySelectorAll("button").forEach(b=>b.classList.toggle("active",b===node));try{await load();}catch(error){message(error.message,true);}});
            document.getElementById("search").addEventListener("input",()=>{if(tab!=="Dashboard")table();});
        }
        try{await load();}catch(error){message(error.message,true);}
    }
    document.getElementById("copy-config")?.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(document.getElementById("configuration").textContent);message(t("Operation complete"));}catch(error){message(error.message,true);}});
})();
