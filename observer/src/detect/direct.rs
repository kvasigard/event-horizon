use super::{Detector, SyscallEventContext};
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const ALLOWED_MODULES: [&str; 6] = [
    "ntdll.dll",
    "win32u.dll",
    "wow64win.dll",
    "wow64.dll",
    "wow64cpu.dll",
    "kernelbase.dll",
];


pub struct DirectSyscallDetector {
    sender: Option<SyncSender<SyscallEventContext>>,
}

impl DirectSyscallDetector {
    pub fn new() -> Self {
        Self { sender: None }
    }
}

impl Detector for DirectSyscallDetector {
    fn name(&self) -> &'static str {
        "Direct Syscall Detector"
    }

    fn initialize(&mut self) -> Result<(), String> {
        // Enforce backpressure by limiting the queue depth
        let (tx, rx) = mpsc::sync_channel::<SyscallEventContext>(10_000);
        self.sender = Some(tx);

        log::info!("Starting background worker for Direct Syscall Detector...");

        thread::spawn(move || {
            while let Ok(context) = rx.recv() {
                if context.user_frames.is_empty() {
                    continue;
                }

                let top_address = context.user_frames[0];
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

                match crate::detect::utils::get_module_name_from_address(handle, top_address) {
                    Ok(module_name) => {
                        let module_lower = module_name.to_lowercase();
                        if !ALLOWED_MODULES.contains(&module_lower.as_str()) {
                            crate::detect::alert::SyscallAlert {
                                detector_name: "Direct Syscall",
                                process_id: context.process_id,
                                primary_action: "Syscall executed from an unauthorized module bounds".to_string(),
                                context: vec![
                                    ("Module", module_name),
                                    ("Address", format!("{:#X}", top_address)),
                                ],
                            }.fire();
                        }
                    }
                    Err(_) => {
                        // If the VirtualQueryEx fails to find a backing module, it is typically anonymous memory
                        crate::detect::alert::SyscallAlert {
                            detector_name: "Direct Syscall",
                            process_id: context.process_id,
                            primary_action: "Syscall executed from unbacked or anonymous memory".to_string(),
                            context: vec![
                                ("Address", format!("{:#X}", top_address)),
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
            // Non-blocking send. Sheds load if the background thread is overwhelmed.
            if let Err(mpsc::TrySendError::Full(_)) = sender.try_send(context.clone()) {
                log::trace!("DirectSyscall queue full, dropping event for PID {}", context.process_id);
            }
        }
    }
}