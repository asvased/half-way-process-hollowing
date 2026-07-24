# Half-Way Process Hollowing

Shellcode loader that overwrites the `.text` section of a suspended legitimate process. No `VirtualAllocEx`, no `NtUnmapViewOfSection`, no `QueueUserAPC`.

## Why Half-Way?

Classic process hollowing creates a loud footprint: it unmaps the entire original PE (`NtUnmapViewOfSection`), allocates a fresh region (`VirtualAllocEx`), writes the payload there, and patches PEB to point at the new base. Every step is a well-signatured event.

Half-way hollowing takes a different approach: the original image stays mapped. Shellcode is written directly into the existing `.text` section at `AddressOfEntryPoint`. No new allocation, no unmapping, no PEB patching, no thread context modification. The memory region remains backed by the legitimate module on disk.

This doesn't make it invisible — but it avoids the most common detection heuristics that flag unbacked RWX regions and unmapped images.

## Process Flow

### Classic Process Hollowing

```
CreateProcess(target, SUSPENDED)
        │
        ▼
NtUnmapViewOfSection       ← unmaps original PE (loud)
        │
        ▼
VirtualAllocEx(new RWX)    ← allocates unbacked region (loud)
        │
        ▼
WriteProcessMemory(payload) ← written to unbacked region
        │
        ▼
Fix PEB ImageBaseAddress   ← patches PEB
        │
        ▼
SetThreadContext(RIP)      ← redirects thread
        │
        ▼
ResumeThread
```

### Half-Way Process Hollowing

```
CreateProcess(target, SUSPENDED | NO_WINDOW)
        │
        ▼
NtQueryInformationProcess → PEB → ImageBaseAddress
        │
        ▼
ReadProcessMemory: DOS → e_lfanew → NT Headers → AddressOfEntryPoint
        │
        ▼
VirtualProtectEx(.text, RW)
        │
        ▼
WriteProcessMemory(shellcode at entry point)
        │
        ▼
VirtualProtectEx(.text, RX)
        │
        ▼
ResumeThread               ← thread starts at original entry point
                             which is now shellcode
```

No unmapping. No new allocation. No PEB patching. No `SetThreadContext`. The primary thread resumes at its original `AddressOfEntryPoint` — which now contains shellcode.

## Comparison

| | Classic Hollowing | Doppelgänging | Ghosting | Herpaderping | **Half-way** |
|---|---|---|---|---|---|
| Unmaps original PE | Yes | No | No | No | **No** |
| Modifies file on disk | No | No | Yes | Yes | **No** |
| Uses temp file | No | No | No | Yes | **No** |
| New memory allocation | Yes (VirtualAllocEx) | Yes (NtCreateSection) | Yes | No | **No** |
| Shellcode in backed region | No | No | No | Partial | **Yes** |
| APC injection | Sometimes | No | No | No | **No** |
| EDR file trigger | No | No | On delete | On rename | **No** |
| Patches PEB | Yes | No | No | No | **No** |
| Modifies thread context | Yes | No | No | No | **No** |
| Complexity | Low | High | High | Medium | **Low** |

## OPSEC Features

| Feature | Why it matters |
|---|---|
| No `VirtualAllocEx` | EDR hooks `VirtualAllocEx` for RWX regions — never called here |
| No `NtUnmapViewOfSection` | Classic hollowing unmapping is a loud signal |
| No `QueueUserAPC` | APC injection pattern is heavily signatured |
| No PEB patching | No `WriteProcessMemory` to PEB ImageBaseAddress |
| No `SetThreadContext` | Thread context modification is a well-known indicator |
| Shellcode in existing `.text` | Region is backed by module on disk, not unbacked |
| `CREATE_NO_WINDOW` | No visible window for the sacrificial process |
| Embedded resource payload | Shellcode not stored as byte array in source |
| `[DefaultDllImportSearchPaths(System32)]` | DLL planting protection on all P/Invoke calls |
| `IntPtr.Size == 8` guard | Fails clearly on WOW64 instead of silent corruption |

## Detection

This technique can still be detected. Understanding detection is part of understanding the attack:

| Detection method | What it catches |
|---|---|
| **Memory scanners** | Compare in-memory `.text` section hash with on-disk copy — modified `.text` is a mismatch |
| **Thread start address** | Thread starts at `AddressOfEntryPoint` of a signed binary but executes non-legitimate code |
| **ETW** | `WriteProcessMemory` across process boundary is a telltale event |
| **Kernel callbacks** | `PsCreateProcessNotify` + `PsCreateThreadNotify` fire on `CreateProcess(SUSPENDED)` — pattern matches hollowing |
| **PE inconsistencies** | `.text` section content doesn't match the import table, section characteristics, or debug directory |
| **Behavioral** | Sacrificial process (e.g. `msedge.exe`) with no network activity, no child processes, no UI |

Against modern EDR (CrowdStrike, SentinelOne, Defender for Endpoint) this will get caught. To harden: indirect syscalls, shellcode encryption, sleep mask, ETW patching — none of which are in scope here.

## Build

**csc.exe (command line):**

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe `
    /target:exe /unsafe /platform:x64 `
    /out:ProcessHollow.exe `
    /resource:shellcode_x64.bin,ProcessHollow.shellcode_x64.bin `
    ProcessHollow.cs
```

**Visual Studio:** Console App (.NET Framework) → add `ProcessHollow.cs` → add shellcode as Embedded Resource → Platform target: x64 → Build.

## Configuration

Target process is configured in the `CONFIG` block in `ProcessHollow.cs`:

```csharp
private const string TargetPath    = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
private const string TargetArgs    = @"""C:\...\msedge.exe"" --no-startup-window";
private const string TargetWorkDir = @"C:\Program Files (x86)\Microsoft\Edge\Application\";
```

Requirements for the target process: 64-bit, signed, no GUI required, `.text` section large enough for shellcode (~200–300 KB).

## License

MIT