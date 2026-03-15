# `detect` Module Documentation

The `detect` module serves as the analytical core of the Event Horizon observer. Its primary responsibility is to ingest high-frequency Event Tracing for Windows (ETW) telemetry (for now at least), normalize it, and asynchronously fan it out to specialized heuristic engines to identify malicious behavior.

## Architecture & Data Flow

To maintain the extreme performance required for ETW fast-path consumption, this module strictly separates **event ingestion** from **event analysis**.

We employ a Multi-Producer, Single-Consumer (MPSC) architectural pattern per detector. The main ETW thread acts as the producer, doing only the absolute minimum required work:

* Filtering obvious noise (kernel memory boundaries, empty stacks).
* Wrapping the stack frame in an Atomic Reference Counted slice (`Arc<[u64]>`).
* Dispatching the reference-counted context via bounded synchronization channels (`sync_channel`) to background worker threads.

This design guarantees **Zero-Cost Abstraction** during the fan-out phase. The actual memory of the stack trace is never copied, preventing heap-allocation bottlenecks and avoiding Out-Of-Memory (OOM) crashes under heavy load.


## Detectors

### `DirectSyscallDetector` (`direct.rs`)

Identifies processes bypassing standard Windows API hooks by issuing `syscall` instructions directly from unauthorized memory regions.

* **Mechanism:** Queries the memory mapping of the top-of-stack caller (`frame[0]`) using `OpenProcess` and `VirtualQueryEx`.
* **Detection Logic:** Alerts if the calling memory region is unbacked (anonymous memory) or backed by a module outside of the highly restricted `ALLOWED_MODULES` list (e.g., `ntdll.dll`, `win32u.dll`).

### `IndirectSyscallDetector` (`indirect.rs`)

Identifies processes attempting to evade direct syscall detection by preparing the registers and jumping into a legitimate `ntdll.dll` syscall trampoline.

* **Mechanism:** Resolves the top two frames of the call stack using the Windows `DbgHelp` API.
* **Detection Logic:** Alerts if the execution transitioned from an anomalous region (raw memory) directly into a known NT API syscall stub, bypassing the expected Windows subsystem layers.


## Utilities & Infrastructure

### `DetectionEngine` (`engine.rs`)

The centralized orchestrator. It holds a registry of active `Detector` implementations and manages their lifecycle. The engine exposes the `process_etw_event` method, which is the singular entry point for raw ETW events transitioning into normalized `SyscallEventContext` payloads.

### `symbols.rs`

Provides a safe wrapper around the Windows `DbgHelp` API.
*Note on usage:* `DbgHelp` is inherently single-threaded and requires the memory context of the target process. This module exposes `init_remote_symbols` and `resolve_remote_symbol` to safely query symbols for foreign process architectures. Heavy usage in hot paths should be avoided.
