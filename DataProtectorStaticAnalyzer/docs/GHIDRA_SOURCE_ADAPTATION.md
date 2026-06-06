# DataProtector Ghidra Source Adaptation

DataProtector's "Smart Static Analysis Master" uses a Ghidra source-derived analyzer layer instead of treating Ghidra as a black-box launcher.

Source baseline:

- Upstream: https://github.com/NationalSecurityAgency/ghidra
- Local checkout used during extraction: `external/ghidra`
- Commit inspected: `94164bd6e90eef1ae6b771a5692c0ca53ea92b81`
- License: Apache License 2.0

Extracted architecture paths:

- Headless launch model:
  `Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/AnalyzeHeadless.java`
- Windows runtime launcher:
  `Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat`
- Decompiler script API:
  `Ghidra/Features/Decompiler/ghidra_scripts/ShowCCallsScript.java`
- Function call graph script API:
  `Ghidra/Features/Base/ghidra_scripts/PrintFunctionCallTreesScript.java`
- Program model APIs:
  `ghidra.program.model.listing.Function`,
  `FunctionManager`, `ReferenceManager`, `SymbolTable`, and
  `DefinedStringIterator`.

DataProtector adaptation:

- `ghidra_scripts/DataProtectorGhidraAnalyzer.java` is the maintained forked analyzer script.
- It runs after Ghidra import/auto-analysis and exports bounded JSON:
  program metadata, imports, defined strings, functions, pseudocode, instruction summaries, call graph edges, and malware-oriented feature hits.
- The server wraps this analyzer with DataProtector sample storage, rule scoring, AI prompt construction, configurable OpenAI-compatible endpoint parameters, and web reporting.

Deployment note:

The published server package includes the DataProtector analyzer assets. Operators may point the module at either a built Ghidra distribution or a compiled local source checkout. The server verifies the configured root by locating `support/analyzeHeadless.bat`.
