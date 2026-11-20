#![cfg_attr(windows, windows_subsystem = "windows")]

mod audit;
mod dashboard;

use std::{env, path::PathBuf, process::ExitCode};

const HELP: &str = "security-dashboard [--db PATH] [--summary]\n\
    Open a read-only desktop dashboard for the AI Security Middleware audit database.\n\
    --db PATH   Open this SQLite audit database.\n\
    --summary   Print aggregate counts as JSON and exit without opening a window.";

#[derive(Default)]
struct Options {
    db: Option<PathBuf>,
    summary: bool,
    help: bool,
}

fn options() -> Result<Options, String> {
    let mut parsed = Options::default();
    let mut args = env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--db") if parsed.db.is_none() => {
                let path = args.next().ok_or("--db requires a file path.")?;
                if path.is_empty() || path.to_string_lossy().starts_with("--") {
                    return Err("--db requires a file path.".into());
                }
                parsed.db = Some(path.into());
            }
            Some("--summary") => parsed.summary = true,
            Some("--help" | "-h") => parsed.help = true,
            _ => {
                return Err(format!(
                    "Unexpected argument: {}",
                    argument.to_string_lossy()
                ))
            }
        }
    }
    Ok(parsed)
}

fn default_database() -> PathBuf {
    if let Some(path) =
        env::var_os("AI_SECURITY_MIDDLEWARE_AUDIT_DB").filter(|path| !path.is_empty())
    {
        return path.into();
    }
    let relative = PathBuf::from("runtime_data").join("security_events.db");
    let cwd = env::current_dir().ok();
    let exe = env::current_exe().ok();
    for directory in cwd
        .as_deref()
        .into_iter()
        .chain(exe.as_deref().and_then(|path| path.parent()))
    {
        let candidate = directory.join(&relative);
        if candidate.is_file() {
            return candidate;
        }
    }
    let home = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env::var_os(home)
        .filter(|path| !path.is_empty())
        .map(|path| {
            PathBuf::from(path)
                .join(".ai-security-middleware")
                .join("security_events.db")
        })
        .unwrap_or(relative)
}

#[cfg(windows)]
fn attach_console_if_needed() {
    use windows_sys::Win32::System::Console::{
        AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE,
    };
    // Interoperate with redirected pipes. Attach only if the GUI launch supplied no stdout.
    unsafe {
        let output = GetStdHandle(STD_OUTPUT_HANDLE);
        if output.is_null() || output as isize == -1 {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

#[cfg(not(windows))]
fn attach_console_if_needed() {}

fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err(error) => {
            attach_console_if_needed();
            eprintln!("{error}\n{HELP}");
            return ExitCode::FAILURE;
        }
    };
    if options.help {
        attach_console_if_needed();
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let path = options.db.unwrap_or_else(default_database);
    if options.summary {
        attach_console_if_needed();
        return match audit::read(&path, &audit::Filter::default()) {
            Ok(snapshot) => {
                println!("{}", serde_json::to_string(&snapshot.summary).unwrap());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Could not read {}: {error}", path.display());
                ExitCode::FAILURE
            }
        };
    }

    let native = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([760.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    match eframe::run_native(
        "Security Middleware Dashboard",
        native,
        Box::new(|creation| Ok(Box::new(dashboard::Dashboard::new(creation, path)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            attach_console_if_needed();
            eprintln!("Could not open the dashboard: {error}");
            ExitCode::FAILURE
        }
    }
}
