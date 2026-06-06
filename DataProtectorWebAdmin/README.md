# DataProtector Central Web Admin

DataProtector Web Admin is the browser-based central management console for
DataProtector endpoints. It is based on SoybeanAdmin and manages policy,
registered agents, and aggregated audit records.

## Architecture

```text
Browser UI
  |
  | HTTP /api
  v
Central Server: DataProtectorWebBridge.exe server
  |
  | policy version, device registry, audit state
  v
C:\ProgramData\DataProtector\CentralState.json

Endpoint Agent: DataProtectorWebBridge.exe agent http://<server-ip>:17643/
  |
  | active polling /api/agent/sync
  v
Central Server
  |
  | local policy apply
  v
DataProtectorPolicyApi.dll -> DataProtector.sys
```

Agents always initiate communication to the server. The server does not need to
open inbound ports on client machines.

## Runtime Modes

```cmd
DataProtectorWebBridge.exe server [http://+:17643/] [webRoot]
DataProtectorWebBridge.exe agent http://<server-ip>:17643/ [pollSeconds]
DataProtectorWebBridge.exe standalone [http://+:17643/] [webRoot]
```

- `server`: central management server and static Web UI.
- `agent`: endpoint process that pulls central policy and applies it locally.
- `standalone`: legacy local bridge mode for single-machine debugging.

## Pages

- Operations: central server health, policy version, device counts, recent audit.
- Devices: registered agents, online status, driver status, last apply result.
- Policy: add, remove, query, and clear central extension-bound rules.
- Remote: queue audited endpoint tasks such as app inventory, startup item
  review, file listing, screenshots, lock screen, command execution, and local
  password changes.
- Audit: read central audit records from policy and agent synchronization.

## Local Development

Start the central server:

```cmd
DataProtectorWebBridge.exe server
```

Then start the web UI:

```powershell
pnpm install
pnpm dev
```

Default development endpoints:

```text
Web UI:       http://localhost:9527
Server API:   http://127.0.0.1:17643/api
Central file: C:\ProgramData\DataProtector\CentralState.json
```

Default deployment endpoint:

```text
http://<server-ip>:17643/
```

The server listens on all interfaces by default using the HTTP.sys wildcard
prefix, which is the Windows equivalent of binding a socket server to
`0.0.0.0`.

If `HttpListener` cannot bind without elevation, reserve the URL on the server:

```cmd
netsh http add urlacl url=http://+:17643/ user=%USERNAME%
```

Allow inbound TCP port `17643` on the server firewall. Client machines only need
outbound access to the server.

## API

The server returns SoybeanAdmin-compatible responses:

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
| GET | `/api/status` | Central server status |
| GET | `/api/devices` | Query registered agents |
| GET | `/api/tasks?limit=100` | Query remote task history |
| POST | `/api/tasks` | Queue a remote endpoint task |
| GET | `/api/policy/rules` | Query central policy rules |
| POST | `/api/policy/rules` | Add one central policy rule |
| DELETE | `/api/policy/rules` | Remove one central policy rule |
| POST | `/api/policy/clear` | Clear all central policy rules |
| GET | `/api/audit/events?limit=200` | Read central audit events |
| POST | `/api/agent/sync` | Agent registration, heartbeat, and policy pull |

## Production Notes

This is the first runnable central-control implementation. Before enterprise
deployment, add authenticated agents, TLS, signed policy updates, Windows
Service hosting, installer/upgrade logic, replay protection, state backup, and
tamper-resistant audit storage.
