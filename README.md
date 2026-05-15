# DataProtector

Windows minifilter based transparent encryption prototype with a WPF policy administration tool.

## Projects

- `DataProtector`: kernel minifilter driver.
- `DataProtectorPolicyApi`: native user-mode policy API DLL.
- `DataProtectorAdmin`: WPF administration UI.

## Build

Use Visual Studio 2019 with the Windows Driver Kit installed, then build `DataProtector.sln` for `x64`.

Admin publish package:

```powershell
.\Publish-Admin.ps1
```
