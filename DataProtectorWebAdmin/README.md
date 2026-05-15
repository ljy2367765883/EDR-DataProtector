# DataProtector Web Admin

DataProtector Web Admin is the browser-based management console for
DataProtector. It is based on SoybeanAdmin and focuses on policy coordination,
driver bridge health, and operator audit visibility.

## Architecture

```text
Browser UI
  |
  | HTTP /api
  v
DataProtectorWebBridge.exe
  |
  | P/Invoke
  v
DataProtectorPolicyApi.dll
  |
  | Filter Manager communication port
  v
DataProtector.sys
```

The browser never talks to the driver or native DLL directly. All native calls
go through the local bridge process. This keeps the UI portable and leaves a
clear place for authentication, audit, request validation, and future service
hardening.

## Pages

- Operations: bridge health, rule counts, protected extensions, recent audit.
- Policy: add, remove, query, and clear extension-bound rules.
- Audit: read recent JSONL audit records emitted by the bridge.

## Local Development

Start the bridge first:

```cmd
DataProtectorWebBridge.exe
```

Then start the web UI:

```powershell
pnpm install
pnpm dev
```

Default development endpoints:

```text
Web UI:      http://localhost:9527
Bridge API:  http://127.0.0.1:17643/api
Audit file:  C:\ProgramData\DataProtector\WebAudit.jsonl
```

Default deployment endpoint:

```text
http://<server-ip>:17643/
```

In deployment, `DataProtectorWebBridge.exe` listens on all interfaces by
default and serves both the static web UI and the `/api` backend. The listener
uses the HTTP.sys wildcard prefix, which is the Windows equivalent of binding a
socket server to `0.0.0.0`.

If `HttpListener` cannot bind without elevation, reserve the URL:

```cmd
netsh http add urlacl url=http://+:17643/ user=%USERNAME%
```

For remote management, allow inbound TCP port `17643` on the server firewall.

## Bridge API

The bridge returns SoybeanAdmin-compatible responses:

```json
{
  "code": "0000",
  "msg": "Success.",
  "data": {}
}
```

Implemented endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | Driver and bridge status |
| GET | `/api/policy/rules` | Query all driver rules |
| POST | `/api/policy/rules` | Add one policy rule |
| DELETE | `/api/policy/rules` | Remove one policy rule |
| POST | `/api/policy/clear` | Clear all driver rules |
| GET | `/api/audit/events?limit=200` | Read recent audit events |

## Production Notes

This first web implementation is local-operator mode. Before enterprise
deployment, the bridge should become a hardened Windows service with identity
checks, CSRF protection for browser-origin calls, signed policy authorization,
TLS or named-pipe transport where appropriate, and protected audit retention.
