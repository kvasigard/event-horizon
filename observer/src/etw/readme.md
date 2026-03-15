# `etw` Module Documentation

The `etw` module serves as the foundational telemetry ingestion layer of the application. Its primary responsibility is to safely and efficiently interface with the Windows Event Tracing for Windows (ETW) subsystem, abstracting complex C APIs into idiomatic, memory-safe Rust structures.

This module is designed to capture high-throughput system events—such as syscall invocations, process creations, and thread context modifications—and route them to the detection engine with minimal overhead.

## Architecture & Data Flow

ETW relies on a strict Provider -> Session -> Consumer architecture. To model this safely in Rust, we separate the configuration of a trace session from its blocking consumption loop.

We employ a Builder pattern for session configuration and rely on Rust's lifetime system (specifically `PhantomData`) to guarantee memory safety during the high-speed FFI callbacks from the operating system.

* **Configuration:** Sessions are built and configured on the main thread, setting up provider GUIDs, enable flags, and routing callbacks.
* **Consumption:** The OS-level `ProcessTrace` function is inherently blocking. Therefore, consumption is spun out into dedicated background threads (`consumer.rs`).
* **Safety at the Boundary:** When the Windows kernel fires an event, it passes a raw `EVENT_RECORD` pointer to our static C-ABI callbacks. We wrap this pointer in a safe `Event` struct bound by a lifetime marker, ensuring the raw memory cannot be accessed after the callback returns, preventing use-after-free vulnerabilities.

## Trace Sessions

Both trace session types implement the `TraceSession` trait, which defines the standard lifecycle: start, consume, and graceful shutdown to prevent orphaned ETW sessions from lingering in the OS.

### `UserTrace` (`user.rs`)

Manages standard user-mode ETW sessions.

* **Mechanism:** Leverages `StartTraceW` and `EnableTraceEx2` to dynamically subscribe to specific providers.
* **Filtering:** Implements an internal filtering mechanism (`EventFilter`) to drop irrelevant events early in the pipeline based on Event IDs, drastically reducing the load on the global callback dispatchers.
* **Thread Safety:** Encapsulates the `CONTROLTRACE_HANDLE` within a `Mutex`, allowing safe cross-thread manipulation for stopping the session while the consumer thread is blocked.

### `KernelTrace` (`kernel.rs`)

A specialized session strictly for interacting with the `NT Kernel Logger`.

* **Mechanism:** Because the kernel logger is globally unique, it ignores standard provider enabling and instead relies on `EnableFlags` (e.g., `EVENT_TRACE_FLAG_SYSTEMCALL`) within the `EVENT_TRACE_PROPERTIES` block.
* **Stack Walking:** Interfaces with `TraceSetInformation` to instruct the Windows kernel to automatically append call stack data to specific event types, which is crucial for identifying the origin of indirect syscalls.

## Parsing & Telemetry Extraction

To avoid performance bottlenecks during the high-frequency consumption loop, property resolution is handled carefully using the Trace Data Helper (TDH) API.

### `EventParser` (`event_parser.rs`)

Responsible for extracting raw data from the `EVENT_RECORD` memory block.

* **Stack Traces:** Safely iterates over the extended data items of the event header to extract 32-bit or 64-bit stack frames (`EVENT_HEADER_EXT_TYPE_STACK_TRACE64`), converting them into pure Rust `Vec<u64>` structures for the `detect` module.
* **Property Formatting:** Uses `TdhGetProperty` and `TdhFormatProperty` to convert raw C-struct memory into human-readable Rust `String` types, handling complex Windows type mappings automatically.

### `ManifestParser` (`manifest_parser.rs`)

An optimization layer for user-mode provider schemas.

* **Mechanism:** Connects to registered providers on the system and pre-parses their XML manifests using `TdhEnumerateManifestProviderEvents`.
* **Purpose:** By caching event names, parameter names, and expected data types (e.g., `UnicodeString`, `UInt32`) in a `HashMap`, we can theoretically bypass expensive TDH API lookups in the hot path, providing $O(1)$ schema lookups by Event ID.

## Types & Utilities

### `types.rs`

Defines the core `Event<'a>` wrapper. By storing the raw pointer alongside `std::marker::PhantomData`, we instruct the borrow checker to enforce the temporal validity of the OS-provided memory, ensuring our detection engine cannot accidentally stash an `Event` for asynchronous processing without explicitly copying the underlying data first.

### `errors.rs`

Standardizes OS-level failures. Maps raw `u32` Windows error codes (e.g., `ERROR_ALREADY_EXISTS`, `ERROR_INSUFFICIENT_BUFFER`) into a clean, unified `EtwError` enum utilizing the `thiserror` crate, facilitating idiomatic `Result<T>` bubbling.
