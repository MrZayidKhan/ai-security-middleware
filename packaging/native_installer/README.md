# Protected Send Windows installer

**Protected-Send-Setup-Windows-x64.exe** installs Protected Send and Security
Dashboard for the current Windows 10/11 x64 user. It bundles CPython, the
local detector, and the dashboard. Setup uses the .NET Framework included
with Windows. The model and runtime are already inside the installer, so
installation has no Python, Ollama, pip, or network setup steps.

1. Run the installer and click **Install**.
2. Select **Open Protected Send** when setup finishes, or open **Protected Send**
   from the **Prompt Security Middleware** folder in the Start menu. Open an
   existing conversation in Antigravity and write your prompt in the overlay.
3. Open **Security Dashboard** from the same Start menu folder to review decisions.

The install folder is
`%LOCALAPPDATA%\PromptSecurityMiddleware\ProtectedSend`. An update replaces only
that install folder if it has the Protected Send setup marker. The separate
`runtime_data` folder, including `security_events.db`, is kept.

The installer is unsigned. Windows may use its unsigned-app protection prompt.
Agent applications handle their own installation, login, and connectivity.

## Build on Windows

Use an x64 CPython 3.14 build environment with pip. The packager requires:

- A newly built project wheel containing `security_middleware.overlay_worker`.
  Build the wheel from a clean source distribution to keep old build output
  out of the release.
- The reviewed Windows x64 CPython 3.14 offline wheelhouse.
- [Python's official 3.14.10 x64 embeddable ZIP](https://www.python.org/downloads/release/python-31410/).
  The packager verifies its published SHA-256 before unpacking.
- An official, redistributable x64 MSVC runtime directory at least as recent
  as the toolset used for the ONNX Runtime wheel. See Microsoft's
  [deployment and redistribution terms](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files).
  Supply an approved runtime distribution directory. Do not assemble a
  release by copying DLLs from Windows System32.
- The verified Horizon model directory, `ProtectedSend.exe` build output,
  and the x64 Rust `security-dashboard.exe` build.

From the repository root:

    .\.venv\Scripts\python.exe packaging/native_installer/build_installer.py stage-runtime --python-archive PATH_TO_PYTHON_ZIP --wheelhouse PATH_TO_WHEELS --project-wheel PATH_TO_PROJECT_WHEEL --vc-runtime-dir PATH_TO_X64_CRT --output dist/installer-build-inputs/runtime

    .\native-overlay\build.ps1 -OutputDirectory dist/installer-build-inputs/launcher
    .\.venv\Scripts\python.exe packaging/native_installer/build_installer.py build --launcher-dir dist/installer-build-inputs/launcher --runtime-dir dist/installer-build-inputs/runtime --model-dir models/pretrained/horizon-small --dashboard PATH_TO_DASHBOARD_EXE --output dist/protected-send-current/Protected-Send-Setup-Windows-x64.exe

Use a new runtime and installer output path for each rebuild. After verifying
the replacement, keep the current installer, the offline rebuild inputs, and
the all-in-one ZIP if needed. Generated files in `dist` stay local.

The build runs offline model inference with the bundled interpreter, checks
that the sanitizer returns the exact cleaned support-ticket text, and verifies
each embedded file against its SHA-256 using the built installer. Use the
[demo prompts](../../docs/PROMPT_SECURITY_DEMO.txt) for live acceptance. The
installer's `--verify-payload` mode runs that check without opening the wizard,
writing to the install location, or changing shortcuts.
