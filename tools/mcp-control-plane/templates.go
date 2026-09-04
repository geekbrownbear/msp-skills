package main

const templates = `
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bearium Control Plane</title>
<style>
:root{--navy:#0B2545;--navy2:#11315C;--ink:#E6EDED;--ink3:#94A3B8;--cyan:#37B3D2;--lime:#9DDF4B;--edge:rgba(255,255,255,.12);--alert:#F87171}
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
button{margin-top:22px;width:100%;height:44px;border:0;border-radius:999px;background:var(--lime);color:#0F172A;font-weight:800;font-size:15px;cursor:pointer}
button.link{background:none;color:var(--cyan);width:auto;height:auto;margin:0;font-weight:600}
.err{margin-top:16px;background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:var(--alert);padding:10px 12px;border-radius:10px;font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--edge)}
th{color:var(--ink3);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;background:rgba(55,179,210,.14);color:var(--cyan)}
.soon{margin-top:22px;padding-top:16px;border-top:1px solid var(--edge);color:var(--ink3);font-size:13px}
.soon span{display:inline-block;margin:4px 8px 0 0;padding:3px 10px;border:1px solid var(--edge);border-radius:999px}
</style></head><body>
<div class="brand">Bearium Control Plane<small>msp-skills gateway</small></div>{{end}}

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
<p class="sub">Sign in to the Bearium gateway control plane.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Email</label><input type="email" name="email" autocomplete="username" required>
<label>Password</label><input type="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</div>{{template "foot" .}}{{end}}

{{define "admin"}}{{template "head" .}}
<div class="card wide">
<div class="row"><h1>Admin</h1>
<form method="post" action="/logout"><button class="link" type="submit">Sign out</button></form></div>
<p class="sub">Signed in as {{.User.Name}} ({{.User.Email}}) <span class="badge">{{.User.Role}}</span></p>
<table>
<tr><th>Email</th><th>Name</th><th>Role</th></tr>
{{range .Users}}<tr><td>{{.Email}}</td><td>{{.Name}}</td><td>{{.Role}}</td></tr>{{end}}
</table>
<div class="soon">Coming next:
<span>Add users</span><span>Per-connector permissions</span><span>Read/write grants</span><span>SSO (M365 / Google)</span><span>Personal access tokens</span><span>Audit trail</span>
</div>
</div>{{template "foot" .}}{{end}}
`
