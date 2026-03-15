use super::{Detector, SyscallEventContext};

use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

pub struct IndirectSyscallDetector {
    sender: Option<SyncSender<SyscallEventContext>>,
}

impl IndirectSyscallDetector {
    pub fn new() -> Self {
        Self { sender: None }
    }
}

impl Detector for IndirectSyscallDetector {
    fn name(&self) -> &'static str {
        "Indirect Syscall Detector"
    }

    fn initialize(&mut self) -> Result<(), String> {
        let (tx, rx) = mpsc::sync_channel::<SyscallEventContext>(10_000);
        self.sender = Some(tx);

        thread::spawn(move || {
            log::info!("Indirect Syscall background worker online.");

            while let Ok(context) = rx.recv() {
                let handle = unsafe {
                    OpenProcess(
                        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        0,
                        context.process_id,
                    )
                };

                if handle.is_null() {
                    continue;
                }

                if crate::detect::symbols::init_remote_symbols(handle).is_err() {
                    unsafe { CloseHandle(handle) };
                    continue;
                }

                let mut resolved_frames = Vec::new();
                let mut is_noise = false;

                for &frame in context.user_frames.iter() {
                    let sym = crate::detect::symbols::resolve_remote_symbol(handle, frame);
                    let sym_lower = sym.to_lowercase();

                    if sym_lower.contains("ldrinitializethunk")
                        || sym_lower.contains("ldrshutdownprocess")
                        || sym_lower.contains("rtlexituserprocess")
                    {
                        is_noise = true;
                        break;
                    }
                    resolved_frames.push(sym);
                }

                crate::detect::symbols::cleanup_remote_symbols(handle);

                if is_noise || resolved_frames.len() < 2 {
                    unsafe { CloseHandle(handle) };
                    continue;
                }

                let f0 = resolved_frames[0].to_lowercase();
                let is_syscall_trampoline = f0.starts_with("nt") || f0.starts_with("zw");

                if is_syscall_trampoline {
                    let call_origin_addr = context.user_frames[1];
                    let mut is_malicious = false;
                    let mut backing_module_name = String::new();

                    // Query the Virtual Memory Manager to identify what actually lives at the Call Origin
                    match crate::detect::utils::get_module_name_from_address(handle, call_origin_addr) {
                        Ok(module_name) => {
                            let module_lower = module_name.to_lowercase();
                            backing_module_name = module_name.clone();

                            // Rule 1: .exe files should NEVER be making direct jumps into ntdll.dll syscall stubs.
                            // This instantly catches your PoC.
                            if module_lower.ends_with(".exe") {
                                is_malicious = true;
                            } else {
                                // Rule 2: Allowlist the standard Windows Subsystem APIs.
                                let allowed_system_dlls = [
                                    "ntdll.dll", "kernelbase.dll", "kernel32.dll", "rpcrt4.dll",
                                    "combase.dll", "mswsock.dll", "sechost.dll", "advapi32.dll",
                                    "win32u.dll", "wow64.dll", "wow64win.dll", "wow64cpu.dll",
                                    "ucrtbase.dll", "ws2_32.dll", "user32.dll", "crypt32.dll",
                                    "bcrypt.dll", "appcore.dll", "windows.storage.dll", "themeservice.dll"
                                ];

                                if !allowed_system_dlls.iter().any(|&m| module_lower.contains(m)) {
                                    is_malicious = true; // Unknown/3rd-party DLL making direct NT API calls
                                }
                            }
                        }
                        Err(_) => {
                            // Rule 3: VirtualQueryEx failed. The origin is Unbacked / Anonymous memory (Shellcode).
                            backing_module_name = "UNBACKED / ANONYMOUS MEMORY".to_string();
                            is_malicious = true;
                        }
                    }

                    if is_malicious {
                        crate::detect::alert::SyscallAlert {
                            detector_name: "Indirect Syscall",
                            process_id: context.process_id,
                            primary_action: "Execution transitioned from an unauthorized memory region into an NT API trampoline".to_string(),
                            context: vec![
                                ("Trampoline used in ntdll", resolved_frames[0].clone()),
                                ("Call Origin Address", format!("{:#X}", call_origin_addr)),
                                ("Origin Backing Module", backing_module_name),
                            ],
                        }.fire();
                    }
                }

                unsafe { CloseHandle(handle) };
            }
        });

        Ok(())
    }

    fn analyze(&self, context: &SyscallEventContext) {
        if let Some(sender) = &self.sender {
            // Apply backpressure via load shedding if the worker falls behind
            if let Err(TrySendError::Full(_)) = sender.try_send(context.clone()) {
                log::trace!("IndirectSyscall queue full, dropping event for PID {}", context.process_id);
            }
        }
    }
}