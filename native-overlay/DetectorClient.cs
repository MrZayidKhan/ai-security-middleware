using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace ProtectedSend
{
    internal sealed class DetectorClient : IDisposable
    {
        private readonly string root;
        private readonly string audit;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer();
        private Process process;

        internal DetectorClient(string root, string audit) { this.root = root; this.audit = audit; }

        internal async Task<Dictionary<string, string>> Inspect(string text, string target)
        {
            if (process == null)
            {
                var start = new ProcessStartInfo {
                    FileName = Path.Combine(root, "runtime", "python.exe"),
                    Arguments = "-I -X utf8 -m security_middleware.overlay_worker --model-dir \"" +
                                Path.Combine(root, "model") + "\" --audit-db \"" + audit + "\"",
                    WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                };
                start.StandardOutputEncoding = System.Text.Encoding.UTF8;
                process = Process.Start(start);
                process.BeginErrorReadLine();
            }
            if (process.HasExited) throw new IOException("The local detector stopped.");
            string line = json.Serialize(new { operation = "inspect", text = text, target = target });
            // The pipe is UTF-8 on the worker side. Explicitly escape non-ASCII characters
            // so the platform console encoding cannot alter the JSON payload.
            var ascii = new System.Text.StringBuilder();
            foreach (char c in line)
                if (c <= 127) ascii.Append(c); else ascii.Append("\\u").Append(((int)c).ToString("x4"));
            await process.StandardInput.WriteLineAsync(ascii.ToString());
            await process.StandardInput.FlushAsync();
            var reply = process.StandardOutput.ReadLineAsync();
            if (await Task.WhenAny(reply, Task.Delay(TimeSpan.FromSeconds(30))) != reply)
            {
                Stop();
                throw new TimeoutException("The local detector did not respond.");
            }
            string result = await reply;
            if (result == null) throw new IOException("The local detector returned no result.");
            return json.Deserialize<Dictionary<string, string>>(result);
        }

        private void Stop()
        {
            if (process == null) return;
            try { if (!process.HasExited) process.Kill(); }
            catch (InvalidOperationException) { }
            process.Dispose();
            process = null;
        }

        public void Dispose() { Stop(); }
    }
}
