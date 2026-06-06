# Static Analyzer Tools

Place optional unpacking tools here for the published server package.

- `upx.exe`: used by the smart static analysis preflight to unpack UPX-packed PE samples before running Ghidra.

The server also checks `DATAPROTECTOR_UPX_PATH` and the system `PATH`. If UPX is detected in a sample but no tool is available, the analysis falls back to the original sample and records the missing-tool status in the report.
