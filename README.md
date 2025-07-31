# Remote Memory Injection into explorer.exe – Static and Dynamic Analysis

This repository documents a small C-based proof-of-concept that performs remote memory injection into the `explorer.exe` process on Windows. The injected payload is a benign string written into memory, simulating a common staging technique used in both red team tooling and real-world malware. Note - I have uploaded the compiled version to [Virus Total](https://www.virustotal.com/gui/file/4ea4913b3e44eb5dbb449de93bf8b064c78b3f0a34386cc883c08e0eba17ae97) for vendor analysis and the betterment of the security community. 

## File Contents
- `injector.c`: C source code demonstrating remote memory injection (stager only; no execution)
- `README.md`: Static/dynamic analysis, behavioral signature breakdown, and detection strategy

---

## Analysis Overview

### Objective

Statically and dynamically analyze a C sample that:
1. Enumerates processes to identify `explorer.exe`
2. Obtains a handle to the process with `OpenProcess(PROCESS_ALL_ACCESS)`
3. Allocates remote memory using `VirtualAllocEx`
4. Writes a payload string using `WriteProcessMemory`
5. Exits without executing the injected code

This reflects real-world usage patterns of memory stagers and early-stage payload loaders.

---

### Static Analysis

- Enumerates running processes using `CreateToolhelp32Snapshot` and `PROCESSENTRY32`
- Performs string matching to locate `explorer.exe`
- Allocates 1024 bytes of memory in the target process with `PAGE_READWRITE`
- Writes the string `"Hello from injected code!"` into the target memory
- Provides console output on success

### Dynamic Analysis Environment

- OS: Windows 11 24H2 (Build 26100.4652)
- Compiler: `x86_64-w64-mingw32-gcc` (MinGW-w64)
- Defender: Disabled for initial testing, then re-enabled
- SHA256: `4ea4913b3e44eb5dbb449de93bf8b064c78b3f0a34386cc883c08e0eba17ae97`

### Runtime Behavior

- Successfully wrote 26 bytes into `explorer.exe` memory
- Observed injected string at `0x61f0000` via Process Hacker
- No detection or blocking behavior from Microsoft Defender post-write

---

## Threat Modeling Perspective

### MITRE ATT&CK Mapping

- **T1055.002 – Portable Executable Injection**
- Behavior suggests a staging mechanism prior to execution (e.g., via remote thread, APC, or shellcode trampoline)

### Malicious Behavior Patterns

- `CreateToolhelp32Snapshot` → `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` chain
- Targeting of trusted process (`explorer.exe`) for evasion and elevated context

---

## Detection Strategy

### Static Indicators

- Hardcoded string: `"Hello from injected code!"`
- Known hash (easily evaded via trivial modification)

### Behavioral Correlation

A robust detection approach would involve:

- Monitoring memory allocation and writing into remote processes
- Flagging suspicious use of RW/RWX permissions in trusted processes
- Correlating parent/child process lineage and token privilege shifts
- Leveraging telemetry from `VirtualAllocEx`, `WriteProcessMemory`, and suspicious handle access in known-good binaries

### Pyramid of Pain Alignment

| Indicator Type        | Resilience       |
|-----------------------|------------------|
| SHA256                | Low              |
| Hardcoded String      | Low              |
| API Behavior Pattern  | High             |
| Process Injection TTP | Highest Priority |

---

## Purpose and Intent

This project was developed solely for **educational and defensive research purposes**. It serves as a simple example of how remote memory injection operates at the system level and how defenders can identify it through behavioral analysis.

---

## License

MIT License. Use at your own risk.
