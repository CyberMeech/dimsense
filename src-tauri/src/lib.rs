use std::net::TcpStream;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use tauri::{Manager, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

const BACKEND_PORT: &str = "8000";
const BACKEND_HEALTH_ADDR: &str = "127.0.0.1:8000";
const BACKEND_READY_TIMEOUT: Duration = Duration::from_secs(30);

struct BackendProcess(Mutex<Option<CommandChild>>);

/// Polls the backend's port instead of a fixed sleep: a flat delay is either
/// too short (slow first-run PyInstaller extraction, antivirus scanning the
/// freshly unpacked exe) or wastes time when the backend is already up.
/// Returns false if it never came up within the timeout.
fn wait_for_backend() -> bool {
    let addr = BACKEND_HEALTH_ADDR.parse().expect("valid socket address");
    let deadline = Instant::now() + BACKEND_READY_TIMEOUT;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Assigns the sidecar to a Windows Job Object with `KILL_ON_JOB_CLOSE`, so
/// Windows kills it the instant our own process ends — for *any* reason
/// (normal exit, panic, or a force kill from Task Manager). Relying only on
/// our `ExitRequested` handler below left an orphaned dimsense-backend.exe
/// running (observed empirically: it survived a genuine WM_CLOSE to the
/// main window), so this is the actual cleanup guarantee, not that handler.
#[cfg(windows)]
fn assign_to_job_object(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            log::error!("[dimsense-backend] failed to create job object for sidecar cleanup");
            return;
        }

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let configured = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if configured == 0 {
            log::error!("[dimsense-backend] failed to configure job object kill-on-close limit");
            CloseHandle(job);
            return;
        }

        let process_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
        if process_handle.is_null() {
            log::error!("[dimsense-backend] failed to open sidecar process handle for job assignment");
            CloseHandle(job);
            return;
        }

        if AssignProcessToJobObject(job, process_handle) == 0 {
            log::error!("[dimsense-backend] failed to assign sidecar process to job object");
        } else {
            log::info!("[dimsense-backend] sidecar assigned to job object (kill-on-close enabled)");
        }

        CloseHandle(process_handle);
        // job is deliberately never closed: it must stay open for our
        // process's entire lifetime so Windows only closes it (and kills
        // the sidecar) when our own process finally terminates.
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(BackendProcess(Mutex::new(None)))
        .setup(|app| {
            // Registered unconditionally (not just in debug builds) so
            // sidecar output/errors are still captured in the shipped
            // release build — default targets write to both stdout and
            // the OS-standard app log directory (path().app_log_dir()).
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .build(),
            )?;

            // dimsense-backend is a self-contained PyInstaller-frozen
            // executable (see backend/dimsense_backend.spec) — it embeds
            // frontend/dist and all Python dependencies, so no system
            // Python install is required on the end user's machine. It
            // self-hosts uvicorn on 127.0.0.1:8000 via its own
            // `if __name__ == "__main__"` entry point.
            let (mut rx, child) = app
                .shell()
                .sidecar("dimsense-backend")
                .expect("failed to resolve dimsense-backend sidecar")
                .spawn()
                .expect("failed to spawn dimsense-backend sidecar");

            #[cfg(windows)]
            assign_to_job_object(child.pid());

            *app.state::<BackendProcess>().0.lock().unwrap() = Some(child);

            // Surface the sidecar's own output/exit — PyInstaller startup
            // failures are otherwise completely silent.
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            log::info!("[dimsense-backend] {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Stderr(line) => {
                            log::error!("[dimsense-backend] {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Error(err) => {
                            log::error!("[dimsense-backend] sidecar error: {err}");
                        }
                        CommandEvent::Terminated(payload) => {
                            log::error!("[dimsense-backend] process exited: {payload:?}");
                        }
                        _ => {}
                    }
                }
            });

            // The window is configured with "create": false in
            // tauri.conf.json so it isn't created until we do it here —
            // Tauri otherwise creates configured windows (and starts
            // loading the webview) *before* this setup hook ever runs,
            // which would defeat waiting for the backend below.
            if !wait_for_backend() {
                log::error!(
                    "dimsense-backend did not open port {BACKEND_PORT} within {}s; opening window anyway",
                    BACKEND_READY_TIMEOUT.as_secs()
                );
            }

            WebviewWindowBuilder::from_config(app.handle(), &app.config().app.windows[0])?.build()?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            if let Some(child) = app_handle.state::<BackendProcess>().0.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
    });
}
