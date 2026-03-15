use env_logger::{Builder, Env};
use log;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_FLAG_SYSTEMCALL, EVENT_TRACE_FLAG_THREAD,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

mod etw;
use etw::{KernelTrace, TraceSession};

mod detect;
use detect::{DetectionEngine, DirectSyscallDetector, IndirectSyscallDetector};

/// Signals background threads to gracefully terminate when false.
static RUNNING: AtomicBool = AtomicBool::new(true);

/// Centralized engine for analyzing and broadcasting ETW events.
static ENGINE: OnceLock<DetectionEngine> = OnceLock::new();

/// Cached Process ID to avoid FFI overhead inside high-frequency ETW callbacks.
static CURRENT_PID: OnceLock<u32> = OnceLock::new();

const MICROSOFT_WINDOWS_KERNEL_AUDIT_API_CALLS: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";
const EVENTID_OPENTHREAD: u16 = 4;
const EVENTID_SETTHREADCONTEXT: u16 = 6;
const EVENT_ENABLE_PROPERTY_STACK_TRACE: u32 = 4;
const EVENT_TRACE_TYPE_SYSCALL_ENTER: u32 = 51;

/// Intercepts ETW events from the OS and routes them to the detection engine.
/// Drops events originating from the monitor itself to prevent recursive feedback loops.
fn syscall_detection_callback(event: &etw::Event) {
    let current_pid = *CURRENT_PID.get().unwrap_or(&0);
    
    if event.pid() == current_pid || event.pid() == u32::MAX {
        return;
    }

    if let Some(engine) = ENGINE.get() {
        engine.process_etw_event(event);
    }
}

/// Handles control signals from the OS to initiate graceful shutdown.
unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    log::info!("Termination signal received. Shutting down...");
    RUNNING.store(false, Ordering::SeqCst);
    1
}

fn main() {
    // Configure the default log level without mutating process environment variables
    Builder::from_env(Env::default().default_filter_or("info")).init();

    let pid = unsafe { GetCurrentProcessId() };
    CURRENT_PID.set(pid).expect("Failed to cache current process ID");

    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }

    log::info!("Initializing Detection Engine...");
    
    let mut engine = DetectionEngine::new()
        .add_detector(Box::new(DirectSyscallDetector::new()))
        .add_detector(Box::new(IndirectSyscallDetector::new()));

    if let Err(e) = engine.start() {
        log::error!("Failed to start detection engine asynchronously: {}", e);
        return;
    }

    ENGINE.set(engine).unwrap_or_else(|_| {
        panic!("Global engine instance was already initialized.");
    });

    let user_session = etw::UserTrace::new("Syscalls-Detector")
        .provider_guid(MICROSOFT_WINDOWS_KERNEL_AUDIT_API_CALLS)
        .enable_flags(EVENT_ENABLE_PROPERTY_STACK_TRACE)
        .add_filters([
            etw::EventFilter::new(etw::filter::DoesMatch(EVENTID_OPENTHREAD)),
            etw::EventFilter::new(etw::filter::DoesMatch(EVENTID_SETTHREADCONTEXT)),
        ])
        .add_callback(syscall_detection_callback);

    let kernel_session = KernelTrace::new()
        .enable_flags(EVENT_TRACE_FLAG_SYSTEMCALL | EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD)
        .enable_stack_walk(EVENT_TRACE_TYPE_SYSCALL_ENTER)
        .add_callback(syscall_detection_callback);

    let user_session = Arc::new(user_session);
    let user_session_clone = Arc::clone(&user_session);
    
    let kernel_session = Arc::new(kernel_session);
    let kernel_session_clone = Arc::clone(&kernel_session);

    log::info!("Starting ETW tracing sessions...");

    let user_thread = thread::spawn(move || {
        if let Err(e) = user_session_clone.start_session() {
            log::error!("Failed to initialize UserTrace: {}", e);
            return;
        }
        user_session_clone.consume();
    });

    let kernel_thread = thread::spawn(move || {
        if let Err(e) = kernel_session_clone.start_session() {
            log::error!("Failed to initialize NT Kernel Logger: {}", e);
            return;
        }
        kernel_session_clone.consume();
    });

    // Park the main thread while the background workers collect telemetry
    while RUNNING.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(500));
    }

    log::info!("Cleaning up ETW sessions...");

    user_session.stop_session();
    kernel_session.stop_session();

    let _ = user_thread.join();
    let _ = kernel_thread.join();
}