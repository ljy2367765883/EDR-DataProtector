# libyara.dll (bundled native YARA engine)

This is libyara built from the official VirusTotal/YARA source, tag v4.5.5,
compiled in-house (not downloaded as a prebuilt third-party binary) for supply-
chain integrity.

- Source: https://github.com/VirusTotal/yara (tag v4.5.5)
- Build: MSVC v142 (VS2019), x64 Release, via a minimal CMake SHARED target.
- Modules: core + pe, elf, math, time, console, string, macho, dex.
- Excluded: hash / dotnet / cuckoo / magic modules (they pull in OpenSSL /
  jansson / libmagic). The DataProtector scan engine does not require them.
- No OpenSSL dependency, so the DLL is self-contained (only ws2_32 / crypt32 /
  advapi32 from the OS).

The user-mode static scan engine (DataProtectorWebBridge -> YaraScanEngine)
late-binds this DLL via LoadLibrary/GetProcAddress. If it is absent the YARA
engine reports 'unavailable' and the pipeline degrades to the heuristic + hash
engines.

x64\libyara.dll is deployed into the agent and server packages by
Publish-WebAdmin.ps1.
