using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

internal static class Setup
{
    internal const string Product = "Protected Send";
    private const string MarkerFile = ".protectedsend-install";
    private const string Marker = "Prompt Security Middleware - Protected Send v1";
    private const string PayloadName = "ProtectedSend.payload.zip";
    private const string ManifestName = "manifest.sha256";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--verify-payload")
        {
            try { ReadPayload(null, null); return 0; }
            catch { return 1; }
        }
        if (args.Length != 0) return 2;
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new InstallerForm());
        return 0;
    }

    internal static string AppRoot
    {
        get
        {
            var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (String.IsNullOrEmpty(localData))
                throw new InvalidOperationException("Windows did not provide a local application data folder.");
            return Path.GetFullPath(Path.Combine(localData, "PromptSecurityMiddleware"));
        }
    }

    internal static string InstallPath { get { return Path.Combine(AppRoot, "ProtectedSend"); } }

    internal static void Install(IProgress<int> progress)
    {
        var parent = AppRoot;
        Directory.CreateDirectory(parent);
        VerifyFolder(parent);
        var install = InstallPath;
        var updating = Directory.Exists(install);
        if (updating && !IsOwnedInstallation(install))
            throw new IOException("This location already contains a folder that Protected Send setup did not create.");

        var stage = Path.Combine(parent, ".protectedsend-stage-" + Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(parent, ".protectedsend-backup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stage);
        bool backedUp = false;
        try
        {
            ReadPayload(stage, progress);
            File.WriteAllText(Path.Combine(stage, MarkerFile), Marker, Encoding.UTF8);
            if (updating)
            {
                Directory.Move(install, backup);
                backedUp = true;
            }
            Directory.Move(stage, install);
        }
        catch
        {
            if (backedUp && !Directory.Exists(install)) Directory.Move(backup, install);
            throw;
        }
        finally
        {
            TryCleanOwnedFolder(parent, stage, ".protectedsend-stage-");
        }
        if (backedUp && IsOwnedInstallation(backup))
            TryCleanOwnedFolder(parent, backup, ".protectedsend-backup-");
    }

    private static void VerifyFolder(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Setup will not replace a folder redirected by a filesystem link.");
    }

    private static bool IsOwnedInstallation(string path)
    {
        VerifyFolder(path);
        var marker = Path.Combine(path, MarkerFile);
        if (!File.Exists(marker)) return false;
        var info = new FileInfo(marker);
        return info.Length <= 100 && (info.Attributes & FileAttributes.ReparsePoint) == 0
            && File.ReadAllText(marker) == Marker;
    }

    private static void TryCleanOwnedFolder(string parent, string path, string prefix)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath) ||
            !String.Equals(Path.GetDirectoryName(fullPath), Path.GetFullPath(parent), StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(fullPath).StartsWith(prefix, StringComparison.Ordinal)) return;
        try
        {
            VerifyFolder(fullPath);
            Directory.Delete(fullPath, true);
        }
        catch (IOException) { /* Leave temporary output available for review or recovery. */ }
        catch (UnauthorizedAccessException) { }
    }

    private static string SafeRelativePath(string fileName)
    {
        foreach (string part in fileName.Split('/'))
        {
            if (part.Length == 0 || part == "." || part == ".."
                || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal)
                || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new InvalidDataException("The installer contains a path that Windows cannot safely extract.");
        }
        return fileName.Replace('/', Path.DirectorySeparatorChar);
    }

    private static Dictionary<string, string> ReadManifest(ZipArchive archive)
    {
        var manifest = archive.GetEntry(ManifestName);
        if (manifest == null || manifest.Length > 4 * 1024 * 1024)
            throw new InvalidDataException("The installer manifest is missing or invalid.");
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var reader = new StreamReader(manifest.Open(), Encoding.UTF8))
        {
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                var separator = line.IndexOf('\t');
                if (separator != 64) throw new InvalidDataException("Invalid installer file checksum.");
                var name = line.Substring(separator + 1);
                SafeRelativePath(name);
                if (String.Equals(name, MarkerFile, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The installer contains a reserved file.");
                hashes.Add(name, line.Substring(0, separator));
            }
        }
        foreach (var required in new string[] {
            "ProtectedSend.exe", "security-dashboard.exe", "runtime/python.exe",
            "runtime/python314.dll", "runtime/python314.zip", "runtime/msvcp140.dll",
            "runtime/Lib/site-packages/security_middleware/overlay_worker.py",
            "model/model_quantized.onnx", "model/tokenizer.json",
        })
        {
            if (!hashes.ContainsKey(required)) throw new InvalidDataException("An installer component is missing: " + required);
        }
        return hashes;
    }

    private static void ReadPayload(string stage, IProgress<int> progress)
    {
        var buffer = new byte[1024 * 1024];
        using (var payload = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadName))
        {
            if (payload == null) throw new InvalidDataException("The bundled application could not be read.");
            using (var archive = new ZipArchive(payload, ZipArchiveMode.Read))
            {
                var expected = ReadManifest(archive);
                if (archive.Entries.Count != expected.Count + 1)
                    throw new InvalidDataException("The installer manifest does not match its files.");
                var root = stage == null ? null : Path.GetFullPath(stage) + Path.DirectorySeparatorChar;
                long total = 0;
                foreach (var entry in archive.Entries) total = checked(total + entry.Length);
                long completed = 0;
                int lastProgress = -1;
                foreach (var entry in archive.Entries)
                {
                    if (entry.FullName == ManifestName) continue;
                    string checksum;
                    if (!expected.TryGetValue(entry.FullName, out checksum))
                        throw new InvalidDataException("The installer contains an unexpected file.");
                    expected.Remove(entry.FullName);
                    var relative = SafeRelativePath(entry.FullName);
                    var destination = root == null ? null : Path.GetFullPath(Path.Combine(root, relative));
                    if (destination != null)
                    {
                        if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("Installer files must stay inside the staging directory.");
                        Directory.CreateDirectory(Path.GetDirectoryName(destination));
                    }
                    using (var output = destination == null ? Stream.Null : File.Open(destination, FileMode.CreateNew))
                    using (var input = entry.Open())
                    using (var digest = SHA256.Create())
                    {
                        int read;
                        long fileBytes = 0;
                        while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            fileBytes += read;
                            if (fileBytes > entry.Length) throw new InvalidDataException("Installer entry exceeds its stated size.");
                            digest.TransformBlock(buffer, 0, read, buffer, 0);
                            output.Write(buffer, 0, read);
                            completed += read;
                            int percentage = total == 0 ? 0 : (int)(90 * completed / total);
                            if (progress != null && percentage != lastProgress)
                            {
                                progress.Report(percentage);
                                lastProgress = percentage;
                            }
                        }
                        digest.TransformFinalBlock(buffer, 0, 0);
                        var actual = BitConverter.ToString(digest.Hash).Replace("-", "");
                        if (fileBytes != entry.Length || !String.Equals(actual, checksum, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("Installer file checksum did not match: " + relative);
                    }
                }
                if (expected.Count != 0) throw new InvalidDataException("Files listed in the installer manifest are missing.");
            }
        }
    }

    internal static void CreateShortcuts(bool desktop)
    {
        var programs = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
        var folder = Path.Combine(programs, "Prompt Security Middleware");
        Directory.CreateDirectory(folder);
        Shortcut(Path.Combine(folder, "Protected Send.lnk"), "ProtectedSend.exe", "");
        var database = Path.Combine(AppRoot, "runtime_data", "security_events.db");
        Shortcut(Path.Combine(folder, "Security Dashboard.lnk"), "security-dashboard.exe", "--db \"" + database + "\"");
        if (desktop)
        {
            Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "Protected Send.lnk"), "ProtectedSend.exe", "");
        }
    }

    private static void Shortcut(string path, string executable, string arguments)
    {
        dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", true));
        dynamic link = shell.CreateShortcut(path);
        link.TargetPath = Path.Combine(InstallPath, executable);
        link.WorkingDirectory = InstallPath;
        link.Arguments = arguments;
        link.Save();
    }
}

internal sealed class InstallerForm : Form
{
    private readonly Label status;
    private readonly Label summary;
    private readonly ProgressBar progress;
    private readonly CheckBox desktop;
    private readonly Button install;
    private readonly Button close;
    private bool active;
    private bool installed;

    internal InstallerForm()
    {
        Text = "Protected Send Setup";
        Width = 612;
        Height = 365;
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var layout = new TableLayoutPanel {
            Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 6
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        layout.Controls.Add(new Label {
            Text = "Install Protected Send", Dock = DockStyle.Fill, Font = new Font("Segoe UI", 21)
        });
        summary = new Label {
            Text = "Installs the Protected Send overlay, local classifier, and Security Dashboard for your Windows account.\r\n\r\n" + Setup.InstallPath,
            Dock = DockStyle.Fill, UseMnemonic = false
        };
        layout.Controls.Add(summary);
        desktop = new CheckBox { Text = "Create a desktop shortcut", Dock = DockStyle.Fill };
        layout.Controls.Add(desktop);
        progress = new ProgressBar { Dock = DockStyle.Fill };
        layout.Controls.Add(progress);
        status = new Label { Text = "Works offline. Setup does not change agent settings.", Dock = DockStyle.Fill, UseMnemonic = false };
        layout.Controls.Add(status);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false };
        install = new Button { Text = "Install", AutoSize = true, MinimumSize = new Size(109, 34) };
        close = new Button { Text = "Close", AutoSize = true, MinimumSize = new Size(84, 34) };
        install.Click += InstallClick;
        close.Click += delegate { Close(); };
        buttons.Controls.Add(install);
        buttons.Controls.Add(close);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        AcceptButton = install;
        CancelButton = close;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (active) e.Cancel = true;
        base.OnFormClosing(e);
    }

    private async void InstallClick(object sender, EventArgs args)
    {
        if (installed)
        {
            try
            {
                Process.Start(new ProcessStartInfo(Path.Combine(Setup.InstallPath, "ProtectedSend.exe")) {
                    WorkingDirectory = Setup.InstallPath, UseShellExecute = true
                });
                Close();
            }
            catch (Exception error) { status.Text = "Could not open Protected Send: " + error.Message; }
            return;
        }
        active = true;
        install.Enabled = close.Enabled = desktop.Enabled = false;
        status.Text = "Verifying and installing the offline files…";
        progress.Value = 0;
        try
        {
            var update = new Progress<int>(value => progress.Value = Math.Max(progress.Value, value));
            await Task.Run(() => Setup.Install(update));
            installed = true;
            progress.Value = 100;
            status.Text = "Installation complete. Open Protected Send, then open an existing conversation in Antigravity.";
            try { Setup.CreateShortcuts(desktop.Checked); }
            catch (Exception)
            {
                status.Text = "Installed. Shortcuts could not be created. You can open ProtectedSend.exe from the install folder.";
            }
            install.Text = "Open Protected Send";
        }
        catch (Exception error)
        {
            status.Text = error.Message + " Close Protected Send and Security Dashboard if they are open, then retry.";
            desktop.Enabled = true;
        }
        finally
        {
            active = false;
            close.Enabled = install.Enabled = true;
        }
    }
}
