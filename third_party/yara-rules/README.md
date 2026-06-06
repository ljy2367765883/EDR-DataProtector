# Bundled YARA rule sets

These directories contain third-party YARA detection rules pulled from public
open-source repositories. They are consumed by the user-mode static scan engine
(`DataProtectorWebBridge` -> `YaraScanEngine`), which loads every `*.yar` /
`*.yara` file found under the agent's `yara-rules` folder (and the
runtime-updatable `C:\ProgramData\DataProtector\StaticScan\rules` directory).

Each rule file is compiled into its own isolated rules object, so a single
malformed or module-dependent file only loses that file rather than the whole
set. Standard external variables (`filename`, `filepath`, `extension`,
`filetype`, `owner`) are defined at compile time and bound per scan.

## Sources

| Directory        | Upstream                                                | License            |
| ---------------- | ------------------------------------------------------- | ------------------ |
| `signature-base` | https://github.com/Neo23x0/signature-base               | Detection Rule License (DRL) 1.1 |
| `yara-rules`     | https://github.com/Yara-Rules/rules                     | GPL-2.0            |
| `reversinglabs`  | https://github.com/reversinglabs/reversinglabs-yara-rules | MIT              |
| `elastic`        | https://github.com/elastic/protections-artifacts        | Elastic License 2.0 |

The original upstream `LICENSE` file is preserved inside each source directory.

## LICENSING NOTICE (read before any commercial release)

These rule sets carry licenses with real obligations and restrictions. They are
bundled here for INTERNAL TESTING ONLY. Before shipping in a commercial product:

- `signature-base` (DRL 1.1): review the Detection Rule License terms.
- `yara-rules` (GPL-2.0): copyleft / viral; redistribution implications.
- `elastic` (Elastic License 2.0): usage restrictions apply.
- `reversinglabs` (MIT): permissive, generally safe to redistribute.

A production build should narrow this down to rule sets whose licenses permit
commercial redistribution, or replace them with first-party / properly-licensed
content. Detection content is intentionally decoupled from the signed kernel
driver so rule sets can be swapped without any driver change.

## Updating

Rules are runtime-updatable. Drop new `*.yar` files into the agent's
`yara-rules` folder or the ProgramData rules directory; the engine recompiles on
the next scan when it detects a newer timestamp. The central server can also
sync rules to endpoints over the existing policy/sync channel.
