package main

const templates = `
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gateway control plane</title>
<style>
:root{--navy:#0F172A;--navy2:#1E293B;--ink:#E2E8F0;--ink3:#94A3B8;--cyan:#60A5FA;--lime:#3B82F6;--edge:rgba(255,255,255,.10);--alert:#F87171}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--navy);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;display:flex;flex-direction:column;align-items:center}
.brand{margin:40px 0 8px;font-weight:800;font-size:20px;letter-spacing:.02em}
.brand small{display:block;text-align:center;color:var(--cyan);font-size:11px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;margin-top:2px}
.card{width:min(440px,92vw);background:var(--navy2);border:1px solid var(--edge);border-radius:16px;padding:28px;margin-top:16px}
.wide{width:min(720px,92vw)}
h1{font-size:22px;margin:0 0 4px}
p.sub{color:var(--ink3);margin:0 0 20px;font-size:14px}
label{display:block;font-size:13px;color:var(--ink3);margin:14px 0 6px}
input[type=email],input[type=text],input[type=password]{width:100%;height:42px;padding:0 12px;border-radius:10px;border:1px solid var(--edge);background:var(--navy);color:var(--ink);font-size:15px}
input:focus{outline:none;border-color:var(--cyan)}
button{margin-top:22px;width:100%;height:44px;border:0;border-radius:999px;background:var(--lime);color:#fff;font-weight:800;font-size:15px;cursor:pointer}
button.link{background:none;color:var(--cyan);width:auto;height:auto;margin:0;font-weight:600}
.err{margin-top:16px;background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:var(--alert);padding:10px 12px;border-radius:10px;font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--edge)}
th{color:var(--ink3);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;background:rgba(55,179,210,.14);color:var(--cyan)}
.soon{margin-top:22px;padding-top:16px;border-top:1px solid var(--edge);color:var(--ink3);font-size:13px}
.soon span{display:inline-block;margin:4px 8px 0 0;padding:3px 10px;border:1px solid var(--edge);border-radius:999px}
.ok{margin-top:16px;background:rgba(157,223,75,.12);border:1px solid rgba(157,223,75,.35);color:#dff0c8;padding:10px 12px;border-radius:10px;font-size:13px;word-break:break-all}
.ok code{color:var(--ink)}
button.mini{width:auto;height:34px;margin:12px 0 0;padding:0 16px;font-size:13px}
button.danger{background:var(--alert);color:#fff}
.muted{color:var(--ink3)}
a.cyan,.cyan{color:var(--cyan);text-decoration:none}
h2{font-weight:700}
select{width:100%;height:42px;padding:0 10px;border-radius:10px;border:1px solid var(--edge);background:var(--navy);color:var(--ink);font-size:15px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}
.inline{display:flex;gap:10px;align-items:flex-end;margin-top:12px}
.inline input{margin:0}
code{font-family:ui-monospace,Menlo,monospace}
table td form,table td form button{margin:0}
input[type=radio]{width:auto;transform:scale(1.2)}
.ordiv{margin:18px 0 6px;text-align:center;color:var(--ink3);font-size:12px;text-transform:uppercase;letter-spacing:.1em}
.ssorow{display:flex;flex-direction:column;gap:10px}
.ssobtn{display:block;text-align:center;padding:11px;border-radius:999px;border:1px solid var(--edge);color:var(--ink);text-decoration:none;font-weight:600}
.ssobtn:hover{border-color:var(--cyan);color:var(--cyan)}
</style></head><body>
<div class="brand">Control plane<small>gateway</small></div>{{end}}

{{define "foot"}}</body></html>{{end}}

{{define "setup"}}{{template "head" .}}
<div class="card">
<h1>Create the super admin</h1>
<p class="sub">This is the first account. It owns the gateway: users, permissions, SSO, and the audit trail.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/setup">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name</label><input type="text" name="name" autocomplete="name" required>
<label>Email</label><input type="email" name="email" autocomplete="username" required>
<label>Password (min 12 characters)</label><input type="password" name="password" autocomplete="new-password" required>
<label>Confirm password</label><input type="password" name="confirm" autocomplete="new-password" required>
<button type="submit">Create super admin</button>
</form>
</div>{{template "foot" .}}{{end}}

{{define "login"}}{{template "head" .}}
<div class="card">
<h1>Sign in</h1>
<p class="sub">Sign in to the gateway control plane.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Email</label><input type="email" name="email" autocomplete="username" required>
<label>Password</label><input type="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
{{if .SSO}}{{if or (index .SSO "microsoft") (index .SSO "google")}}
<div class="ordiv">or</div>
<div class="ssorow">
{{if index .SSO "microsoft"}}<a class="ssobtn" href="/auth/microsoft/start">Sign in with Microsoft</a>{{end}}
{{if index .SSO "google"}}<a class="ssobtn" href="/auth/google/start">Sign in with Google</a>{{end}}
</div>
{{end}}{{end}}
</div>{{template "foot" .}}{{end}}

{{define "admin"}}{{template "head" .}}
<div class="card wide">
<div class="row"><h1>Admin</h1>
<form method="post" action="/logout"><button class="link" type="submit">Sign out</button></form></div>
<p class="sub">Signed in as {{.User.Name}} ({{.User.Email}}) <span class="badge">{{.User.Role}}</span></p>

{{if .NewToken}}<div class="ok">New token <b>{{.NewTokenLabel}}</b> (shown once, copy it now):<br><code>{{.NewToken}}</code></div>{{end}}

<div class="row"><h2 style="font-size:16px;margin:18px 0 0">Users</h2>
{{if .IsAdmin}}<a href="/admin/user/new"><button class="mini" type="button">Add user</button></a>{{end}}</div>
<table>
<tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th>{{if .IsAdmin}}<th></th>{{end}}</tr>
{{range .Users}}<tr>
<td>{{.Email}}</td><td>{{.Name}}</td><td>{{.Role}}</td>
<td>{{if .Disabled}}<span class="muted">disabled</span>{{else}}active{{end}}</td>
{{if $.IsAdmin}}<td><a class="cyan" href="/admin/user?email={{.Email}}">Manage</a></td>{{end}}
</tr>{{end}}
</table>

<h2 style="font-size:16px;margin:22px 0 0">Your access tokens</h2>
<p class="sub" style="margin-top:4px">For Claude Desktop, scripts, or any non-Callisto client. Scoped to your permissions.</p>
<table>
<tr><th>Label</th><th>Created</th><th></th></tr>
{{range .User.Tokens}}<tr><td>{{.Label}}</td><td>{{.CreatedAt}}</td>
<td><form method="post" action="/admin/token"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke"><input type="hidden" name="hash" value="{{.Hash}}"><button class="link" type="submit">Revoke</button></form></td></tr>{{end}}
</table>
<form method="post" action="/admin/token" class="inline">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="mint">
<input type="text" name="label" placeholder="Token label (e.g. laptop)" style="max-width:260px">
<button class="mini" type="submit">Generate token</button>
</form>

<div class="row" style="margin-top:22px">
<a class="cyan" href="/admin/audit">View audit trail &rarr;</a>
{{if .IsSuperAdmin}}<a class="cyan" href="/admin/sso">Single sign-on &rarr;</a>{{end}}
</div>
</div>{{template "foot" .}}{{end}}

{{define "newuser"}}{{template "head" .}}
<div class="card">
<div class="row"><h1>Add user</h1><a class="cyan" href="/admin">Back</a></div>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/admin/user/new">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name</label><input type="text" name="name" required>
<label>Email</label><input type="email" name="email" required>
<label>Role</label><select name="role">{{range .Roles}}<option value="{{.}}">{{.}}</option>{{end}}</select>
<label>Temporary password (min 12 characters)</label><input type="password" name="password" required>
<button type="submit">Create user</button>
</form>
</div>{{template "foot" .}}{{end}}

{{define "manageuser"}}{{template "head" .}}
<div class="card wide">
<div class="row"><h1>{{.T.Name}}</h1><a class="cyan" href="/admin">Back</a></div>
<p class="sub">{{.T.Email}} <span class="badge">{{.T.Role}}</span>{{if .T.Disabled}} <span class="muted">disabled</span>{{end}}</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

<h2 style="font-size:16px;margin:16px 0 6px">Connector permissions</h2>
<form method="post" action="/admin/user?email={{.T.Email}}">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="permissions">
<table>
<tr><th>Connector</th><th>None</th><th>Read</th><th>Read + write</th></tr>
{{range .Rows}}<tr><td>{{.Name}}</td>
<td><input type="radio" name="grant_{{.Slug}}" value="none" {{if eq .Access "none"}}checked{{end}}></td>
<td><input type="radio" name="grant_{{.Slug}}" value="read" {{if eq .Access "read"}}checked{{end}}></td>
<td><input type="radio" name="grant_{{.Slug}}" value="write" {{if eq .Access "write"}}checked{{end}}></td>
</tr>{{end}}
</table>
<button class="mini" type="submit">Save permissions</button>
</form>

<div class="grid2">
<form method="post" action="/admin/user?email={{.T.Email}}">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="role">
<label>Role</label><select name="role">{{range .Roles}}<option value="{{.}}" {{if eq . $.T.Role}}selected{{end}}>{{.}}</option>{{end}}</select>
<button class="mini" type="submit">Update role</button>
</form>
<form method="post" action="/admin/user?email={{.T.Email}}">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="reset">
<label>Reset password (min 12)</label><input type="password" name="password">
<button class="mini" type="submit">Reset</button>
</form>
</div>

<div class="row" style="margin-top:18px">
{{if .T.Disabled}}
<form method="post" action="/admin/user?email={{.T.Email}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="enable"><button class="mini" type="submit">Enable</button></form>
{{else}}
<form method="post" action="/admin/user?email={{.T.Email}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="disable"><button class="mini" type="submit">Disable</button></form>
{{end}}
<form method="post" action="/admin/user?email={{.T.Email}}" onsubmit="return confirm('Delete {{.T.Email}}?')"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><button class="mini danger" type="submit">Delete</button></form>
</div>
</div>{{template "foot" .}}{{end}}

{{define "audit"}}{{template "head" .}}
<div class="card wide">
<div class="row"><h1>Audit trail</h1><a class="cyan" href="/admin">Back</a></div>
{{if not .Rep.Configured}}<p class="sub">No audit log configured. Set CONTROL_PLANE_AUDIT_LOG to the gateway's hash-chained log file.</p>
{{else}}
<p class="sub">{{.Rep.Total}} events.
{{if .Rep.ChainOK}}<span class="badge" style="background:rgba(75,183,72,.16);color:#7cc397">chain verified</span>
{{else}}<span class="badge" style="background:rgba(248,113,113,.16);color:#e08a7c">chain broken: {{.Rep.ChainErr}}</span>{{end}}</p>
{{if .Rep.Events}}
<table>
<tr><th>Time</th><th>Actor</th><th>Connector</th><th>Action</th><th>Decision</th></tr>
{{range .Rep.Events}}<tr>
<td class="muted">{{.TS}}</td>
<td>{{if .Actor.Email}}{{.Actor.Email}}{{else}}{{.Actor.Name}}{{end}}</td>
<td>{{.Connector}}</td>
<td>{{.MCP.Method}}{{if .MCP.Tool}} &middot; {{.MCP.Tool}}{{end}}</td>
<td>{{if eq .Policy.Decision "deny"}}<span style="color:#e08a7c">deny</span>{{else}}allow{{end}}{{if .Policy.Class}} <span class="muted">({{.Policy.Class}})</span>{{end}}</td>
</tr>{{end}}
</table>
{{else}}<p class="sub">No events recorded yet.</p>{{end}}
{{end}}
</div>{{template "foot" .}}{{end}}

{{define "sso"}}{{template "head" .}}
<div class="card wide">
<div class="row"><h1>Single sign-on</h1><a class="cyan" href="/admin">Back</a></div>
<p class="sub">Configure Microsoft and/or Google sign-in. Anyone from an allowed domain is auto-provisioned as a low-privilege member on first login; you grant connectors afterward.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Saved}}<div class="ok">{{.Saved}}</div>{{end}}
{{if not .External}}<div class="err">CONTROL_PLANE_EXTERNAL_URL is not set, so the redirect URIs below are blank. Set it to your Caddy hostname (e.g. https://controlplane.local.bearium.net).</div>{{end}}
<form method="post" action="/admin/sso">
<input type="hidden" name="csrf" value="{{.CSRF}}">

<h2 style="font-size:16px;margin:18px 0 4px">Microsoft (Entra)</h2>
<p class="sub" style="margin:0 0 8px">Redirect URI to register: <code>{{.MSRedirect}}</code></p>
<label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="ms_enabled" {{if .MSEnabled}}checked{{end}} style="width:auto">Enabled</label>
<label>Directory (tenant) ID</label><input type="text" name="ms_tenant" value="{{.MSTenant}}">
<label>Application (client) ID</label><input type="text" name="ms_client_id" value="{{.MSClientID}}">
<label>Client secret {{if .MSHasSecret}}<span class="muted">(set &mdash; leave blank to keep)</span>{{end}}</label><input type="password" name="ms_client_secret" autocomplete="off">
<label>Allowed email domains (comma-separated)</label><input type="text" name="ms_domains" value="{{.MSDomains}}" placeholder="bearium.net">

<h2 style="font-size:16px;margin:26px 0 4px">Google Workspace</h2>
<p class="sub" style="margin:0 0 8px">Redirect URI to register: <code>{{.GRedirect}}</code></p>
<label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="g_enabled" {{if .GEnabled}}checked{{end}} style="width:auto">Enabled</label>
<label>Client ID</label><input type="text" name="g_client_id" value="{{.GClientID}}">
<label>Client secret {{if .GHasSecret}}<span class="muted">(set &mdash; leave blank to keep)</span>{{end}}</label><input type="password" name="g_client_secret" autocomplete="off">
<label>Allowed email domains (comma-separated)</label><input type="text" name="g_domains" value="{{.GDomains}}" placeholder="bearium.net">

<button type="submit">Save SSO settings</button>
</form>
</div>{{template "foot" .}}{{end}}
`
