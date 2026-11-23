using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;

namespace ProtectedSend
{
    internal static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            long probeWindow;
            if (args.Length == 3 && args[0] == "--diagnose-window" && Int64.TryParse(args[1], out probeWindow))
            {
                File.WriteAllText(args[2], AntigravityTransport.Diagnose(new IntPtr(probeWindow)));
                return;
            }
            if (args.Length == 1 && args[0] == "--self-test") {
                Environment.Exit(StatusText.IsOutcome("MALICIOUS_BLOCKED", "blocked")
                                 && !StatusText.IsAccepted("UNCERTAIN", "ready")
                                 && AntigravityTransport.HasThreadToken(new Uri(
                                     "https://127.0.0.1:59809/c/12345678-1234-1234-1234-123456789abc"))
                                 && !AntigravityTransport.HasThreadToken(new Uri(
                                     "https://127.0.0.1:59809/?project=outside-of-project"))
                                 && AntigravityTransport.Fingerprint("one\r\ntwo") == AntigravityTransport.Fingerprint("one\ntwo")
                                 && AntigravityTransport.Fingerprint("one") != AntigravityTransport.Fingerprint("two")
                                 && MountSelfTest() && NativeSendMonitor.SelfTest() ? 0 : 1);
            }
            using (var singleton = new Mutex(false, "Local\\PromptSecurityProtectedSend"))
            {
                if (!singleton.WaitOne(0)) return;
                try
                {
                    var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    var controller = new OverlayController(app);
                    app.Exit += delegate { controller.Dispose(); };
                    controller.Start();
                    app.Run();
                }
                finally { singleton.ReleaseMutex(); }
            }
        }

        private static bool MountSelfTest()
        {
            var window = new Rect(0, 0, 1280, 900);
            var input = new Rect(345, 719, 592, 51);
            var send = new Rect(920, 778, 34, 32);
            var context = new Rect(342, 778, 24, 32);
            var model = new Rect(390, 778, 145, 32);
            Rect draftRegion, sendRegion;
            return AntigravityTransport.ComputeMountRegions(input, window, send, new[] { context, model },
                       out draftRegion, out sendRegion) &&
                   draftRegion.Contains(input) && sendRegion.Contains(send) &&
                   !draftRegion.IntersectsWith(model) && !sendRegion.IntersectsWith(model) &&
                   OverlayController.MountHitTest(draftRegion, sendRegion, model) &&
                   !AntigravityTransport.ComputeMountRegions(input, window, model, new[] { context, model },
                       out draftRegion, out sendRegion) &&
                   !AntigravityTransport.ComputeMountRegions(input, window, Rect.Empty, new[] { context, model },
                       out draftRegion, out sendRegion);
        }
    }

    internal static class StatusText
    {
        internal static string Read(Dictionary<string, string> values, string name)
        {
            string value;
            return values != null && values.TryGetValue(name, out value) ? value ?? "" : "";
        }

        internal static bool IsAccepted(string decision, string state)
        {
            return state == "ready" && (decision == "PASS" || decision == "SANITIZE");
        }

        internal static bool IsOutcome(string decision, string state)
        {
            return (decision == "MALICIOUS_BLOCKED" && state == "blocked") || IsAccepted(decision, state);
        }
    }

    internal sealed class OverlayController : IDisposable
    {
        private readonly Application app;
        private readonly AntigravityTransport transport = new AntigravityTransport();
        private readonly DetectorClient detector;
        private readonly DispatcherTimer timer;
        private readonly Window overlay;
        private readonly TextBox draft;
        private readonly Button send;
        private readonly Border draftSurface;
        private Window statusWindow;
        private TextBlock attachmentStatus;
        private TextBlock modeInstructions;
        private readonly string root;
        private readonly string audit;
        private IntPtr hwnd;
        private Rect lastInput = Rect.Empty, lastAction = Rect.Empty;
        private Target target;
        private string targetId;
        private bool locating;
        private bool busy;
        private volatile bool paused;
        private volatile bool disposed;
        private volatile bool nativeMode;
        private volatile int nativeRevision;
        private bool nativeReady;
        private bool nativeKeyboard;
        private NativeSendMonitor nativeMonitor;

        internal OverlayController(Application app)
        {
            this.app = app;
            root = AppDomain.CurrentDomain.BaseDirectory;
            audit = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                 "PromptSecurityMiddleware", "runtime_data", "security_events.db");
            detector = new DetectorClient(root, audit);
            var surface = new SolidColorBrush(Color.FromRgb(23, 23, 24));
            draft = new TextBox { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MaxLength = 20000,
                                  VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                                  Padding = new Thickness(0), Background = Brushes.Transparent, FontSize = 14,
                                  Foreground = Brushes.White, CaretBrush = Brushes.White, BorderThickness = new Thickness(0) };
            AutomationPropertiesName(draft, "Protected draft");
            draft.PreviewKeyDown += async delegate(object sender, KeyEventArgs e) {
                if (e.Key != Key.Enter || Keyboard.Modifiers != ModifierKeys.None) return;
                e.Handled = true;
                if (!e.IsRepeat) await Submit();
            };
            var arrow = new System.Windows.Shapes.Path { Data = Geometry.Parse("M 3,9 L 9,3 15,9 M 9,3 L 9,15"),
                Stroke = Brushes.White, StrokeThickness = 1.8, StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round, Stretch = Stretch.None };
            send = new Button { Content = arrow,
                Foreground = Brushes.White, Background = new SolidColorBrush(Color.FromRgb(57, 103, 222)),
                BorderThickness = new Thickness(0), ToolTip = "Check and send" };
            var circle = new FrameworkElementFactory(typeof(Border));
            circle.SetValue(Border.CornerRadiusProperty, new CornerRadius(18));
            circle.SetBinding(Border.BackgroundProperty,
                new System.Windows.Data.Binding("Background") {
                    RelativeSource = System.Windows.Data.RelativeSource.TemplatedParent });
            var content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            content.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            circle.AppendChild(content);
            send.Template = new ControlTemplate(typeof(Button)) { VisualTree = circle };
            AutomationPropertiesName(send, "Check and send");
            send.Click += async delegate { await Submit(); };
            var badge = new TextBlock { Text = "Protected", Foreground = new SolidColorBrush(Color.FromRgb(162, 180, 165)),
                                        FontSize = 10, VerticalAlignment = VerticalAlignment.Top,
                                        HorizontalAlignment = HorizontalAlignment.Right, IsHitTestVisible = false };
            badge.ToolTip = "Drafts here are checked locally before Antigravity receives them.";
            var input = new DockPanel();
            DockPanel.SetDock(badge, Dock.Right);
            badge.Margin = new Thickness(8, 0, 0, 0);
            input.Children.Add(badge);
            var editor = new Grid();
            var placeholder = new TextBlock { Text = "Ask anything", FontSize = 14,
                Foreground = Brushes.Gray, IsHitTestVisible = false };
            editor.Children.Add(draft);
            editor.Children.Add(placeholder);
            input.Children.Add(editor);
            draft.TextChanged += delegate {
                placeholder.Visibility = draft.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            };
            draftSurface = new Border { Background = surface, Padding = new Thickness(3, 5, 4, 3), Child = input };
            var layout = new Canvas();
            layout.Children.Add(draftSurface);
            layout.Children.Add(send);
            overlay = new Window {
                Title = "Protected Send", WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize,
                ShowActivated = false, ShowInTaskbar = false, Topmost = true,
                Background = surface,
                WindowStartupLocation = WindowStartupLocation.Manual, Content = layout,
            };
            timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            timer.Tick += async delegate { await Follow(); };
        }

        private static void AutomationPropertiesName(DependencyObject element, string name)
        {
            System.Windows.Automation.AutomationProperties.SetName(element, name);
        }

        internal void Start()
        {
            var icon = CreateTrayIcon();
            var tray = new System.Windows.Forms.NotifyIcon {
                Icon = icon, Text = "Protected Send", Visible = true,
            };
            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Protected Send status", null, delegate { ShowStatus(); });
            menu.Items.Add("Start protection", null, delegate { SetPaused(false); });
            menu.Items.Add("Stop protection", null, delegate { SetPaused(true); });
            menu.Items.Add("Use native composer (experimental)", null, delegate { SetNativeMode(true); });
            menu.Items.Add("Use protected overlay", null, delegate { SetNativeMode(false); });
            menu.Items.Add("Discard unsent overlay draft", null, delegate { if (!busy) draft.Clear(); });
            menu.Items.Add("Dashboard", null, delegate { OpenDashboard(); });
            menu.Items.Add("Exit Protected Send", null, delegate { app.Shutdown(); });
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { ShowStatus(); };
            app.Exit += delegate { tray.Dispose(); menu.Dispose(); icon.Dispose(); };
            hwnd = new WindowInteropHelper(overlay).EnsureHandle();
            timer.Start();
            ShowStatus();
        }

        private static System.Drawing.Icon CreateTrayIcon()
        {
            try
            {
                using (var bitmap = new System.Drawing.Bitmap(32, 32))
                using (var graphics = System.Drawing.Graphics.FromImage(bitmap))
                using (var fill = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(62, 107, 219)))
                using (var stroke = new System.Drawing.Pen(System.Drawing.Color.White, 2.5f))
                {
                    graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                    graphics.FillEllipse(fill, 1, 1, 30, 30);
                    stroke.StartCap = stroke.EndCap = System.Drawing.Drawing2D.LineCap.Round;
                    stroke.LineJoin = System.Drawing.Drawing2D.LineJoin.Round;
                    graphics.DrawLines(stroke, new[] {
                        new System.Drawing.Point(9, 16), new System.Drawing.Point(14, 21),
                        new System.Drawing.Point(23, 11),
                    });
                    IntPtr handle = bitmap.GetHicon();
                    try
                    {
                        using (var temporary = System.Drawing.Icon.FromHandle(handle))
                            return (System.Drawing.Icon)temporary.Clone();
                    }
                    finally { DestroyIcon(handle); }
                }
            }
            catch (Exception) { return (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone(); }
        }

        private void ShowStatus()
        {
            if (statusWindow != null) { statusWindow.Activate(); return; }
            var body = new StackPanel { Margin = new Thickness(20) };
            body.Children.Add(new TextBlock { Text = "Protected Send is running",
                FontSize = 21, FontWeight = FontWeights.SemiBold });
            attachmentStatus = new TextBlock { TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 12) };
            body.Children.Add(attachmentStatus);
            UpdateStatus();
            modeInstructions = new TextBlock { TextWrapping = TextWrapping.Wrap };
            body.Children.Add(modeInstructions);
            UpdateStatus();
            var buttons = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            AddAction(buttons, "Start protection", delegate { SetPaused(false); });
            AddAction(buttons, "Stop protection", delegate { SetPaused(true); });
            AddAction(buttons, "Dashboard", delegate { OpenDashboard(); });
            AddAction(buttons, "Exit", delegate { app.Shutdown(); });
            body.Children.Add(buttons);
            var modes = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
            AddAction(modes, "Try native composer", delegate { SetNativeMode(true); });
            AddAction(modes, "Use overlay", delegate { SetNativeMode(false); });
            body.Children.Add(modes);
            statusWindow = new Window { Title = "Protected Send", Width = 425,
                SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.CanMinimize,
                WindowStartupLocation = WindowStartupLocation.CenterScreen, Content = body };
            statusWindow.Closed += delegate {
                statusWindow = null; attachmentStatus = null; modeInstructions = null;
                if (!disposed && !app.Dispatcher.HasShutdownStarted) app.Shutdown();
            };
            statusWindow.Show();
        }

        private static void AddAction(Panel panel, string label, RoutedEventHandler action)
        {
            var button = new Button { Content = label, Margin = new Thickness(0, 0, 6, 0),
                Padding = new Thickness(7, 4, 7, 4) };
            button.Click += action;
            panel.Children.Add(button);
        }

        private void SetPaused(bool value)
        {
            paused = value;
            if (paused)
            {
                nativeRevision++;
                StopNativeMonitor();
                overlay.Hide();
            }
            else if (nativeMode)
            {
                StartNativeMonitor();
            }
            UpdateStatus();
        }

        private void SetNativeMode(bool enabled)
        {
            if (busy || disposed) return;
            nativeRevision++;
            StopNativeMonitor();
            nativeMode = enabled;
            if (enabled) overlay.Hide();
            timer.Interval = TimeSpan.FromMilliseconds(enabled ? 180 : 500);
            SetPaused(false);
        }

        private void StartNativeMonitor()
        {
            if (nativeMonitor != null || disposed) return;
            var monitor = new NativeSendMonitor(app.Dispatcher, GuardNativeSend);
            try
            {
                monitor.Start();
                nativeMonitor = monitor;
            }
            catch (Exception)
            {
                monitor.Dispose();
                paused = true;
                Notify("Native Send unavailable", "Windows did not start the experimental guard.");
            }
        }

        private void StopNativeMonitor()
        {
            var monitor = nativeMonitor;
            nativeMonitor = null;
            nativeReady = false;
            nativeKeyboard = false;
            if (monitor != null) monitor.Dispose();
        }

        private async void GuardNativeSend(NativeSendIntent intent)
        {
            if (busy || paused || disposed || !nativeMode || nativeMonitor == null) return;
            var active = nativeMonitor;
            var revision = nativeRevision;
            Func<bool> cancelled = () => disposed || paused || !nativeMode || nativeRevision != revision;
            busy = true;
            active.SetBusy(true);
            try
            {
                var original = await Task.Run(() => transport.ReadNativeDraft(intent.Target));
                if (cancelled()) return;
                if (String.IsNullOrWhiteSpace(original))
                {
                    Notify("Draft kept local", "The native draft or chat could not be verified.");
                    return;
                }
                var result = await detector.Inspect(original, Guid.NewGuid().ToString("N"));
                if (cancelled()) return;
                var decision = StatusText.Read(result, "decision");
                if (!StatusText.IsAccepted(decision, StatusText.Read(result, "state")))
                {
                    var reason = StatusText.Read(result, "reason");
                    Notify(decision == "UNCERTAIN" ? "Uncertain · Not sent" : "Prompt blocked",
                           String.IsNullOrWhiteSpace(reason) ? "The local check did not approve this draft." : reason);
                    return;
                }
                var approved = StatusText.Read(result, "text");
                var delivery = await Task.Run(() => {
                    string status;
                    bool sent = transport.TrySendNative(intent.Target, original, approved, cancelled, out status);
                    return Tuple.Create(sent, status);
                });
                if (cancelled()) return;
                if (!delivery.Item1) Notify("Delivery not confirmed", delivery.Item2);
                else if (decision == "SANITIZE")
                    Notify("Sanitized and sent", "Removed:\n" + StatusText.Read(result, "removed"));
            }
            catch (Exception)
            {
                if (!cancelled()) Notify("Draft kept local", "The local check failed. Nothing was sent.");
            }
            finally
            {
                if (active == nativeMonitor) active.SetBusy(false);
                busy = false;
            }
        }

        private void UpdateStatus()
        {
            if (attachmentStatus == null) return;
            if (modeInstructions != null)
                modeInstructions.Text = nativeMode
                    ? "Type in Antigravity's regular box. Send is checked when the status says armed. " +
                      "Keep native hooks enabled for unverified submission paths."
                    : "Switch to an existing Antigravity conversation with an empty message box. " +
                      "The overlay appears when the composer can be verified. " +
                      "Minimize this window to keep protection running. Close it to exit.";
            if (nativeMode && !paused)
            {
                attachmentStatus.Text = nativeReady
                    ? (nativeKeyboard ? "Native experiment armed for Enter and Send."
                                      : "Native experiment armed for Send clicks. Enter is unverified.")
                    : "Native experiment waiting for a verified Antigravity draft.";
                return;
            }
            attachmentStatus.Text = paused ? "Paused." :
                (overlay.IsVisible ? "Attached to the Antigravity composer." :
                 "Waiting for a supported Antigravity conversation.");
        }

        private async Task Follow()
        {
            if (disposed || (!nativeMode && busy) || locating) return;
            if (paused) { overlay.Hide(); return; }
            locating = true;
            try
            {
                if (nativeMode)
                {
                    var monitor = nativeMonitor;
                    int observedAt = Environment.TickCount;
                    var candidate = await Task.Run(() => transport.FindNativeCandidate());
                    if (disposed || paused || !nativeMode || monitor == null || monitor != nativeMonitor)
                        return;
                    nativeReady = candidate != null;
                    nativeKeyboard = candidate != null && candidate.Focused;
                    monitor.Update(candidate == null ? null : candidate.Target, nativeKeyboard,
                        candidate == null ? Rect.Empty : candidate.SendBounds, observedAt);
                    return;
                }
                var foreground = GetForegroundWindow();
                var previous = target;
                var found = await Task.Run(() => foreground == hwnd && previous != null
                    ? transport.FindBound(previous) : transport.FindForeground());
                if (disposed || busy || paused) return;
                var current = GetForegroundWindow();
                if (found == null || (current != hwnd && current != found.WindowHandle))
                {
                    overlay.Hide();
                    return;
                }
                if (!SameChat(previous, found))
                {
                    if (!String.IsNullOrEmpty(draft.Text))
                    {
                        overlay.Hide();
                        return;
                    }
                    targetId = Guid.NewGuid().ToString("N");
                }
                target = found;
                Place(found);
            }
            catch (Exception)
            {
                if (!disposed) overlay.Hide();
                if (nativeMonitor != null) nativeMonitor.Update(null, false, Rect.Empty);
                nativeReady = nativeKeyboard = false;
            }
            finally { locating = false; UpdateStatus(); }
        }

        private static bool SameChat(Target left, Target right)
        {
            return left != null && right != null && left.WindowHandle == right.WindowHandle &&
                   String.Equals(left.ThreadIdentity, right.ThreadIdentity, StringComparison.Ordinal);
        }

        private void Place(Target found)
        {
            if (overlay.IsVisible && lastInput == found.InputBounds && lastAction == found.ActionBounds)
                return;
            Rect box = Rect.Union(found.InputBounds, found.ActionBounds);
            int x = (int)box.X, y = (int)box.Y, width = (int)box.Width, height = (int)box.Height;
            Rect input = found.InputBounds, action = found.ActionBounds;
            input.Offset(-x, -y);
            action.Offset(-x, -y);
            if (!ApplyMountRegion(input, action)) { overlay.Hide(); return; }
            if (!SetWindowPos(hwnd, new IntPtr(-1), x, y, width, height, 0x0010)) { overlay.Hide(); return; }
            var source = PresentationSource.FromVisual(overlay);
            var scale = source != null && source.CompositionTarget != null
                ? source.CompositionTarget.TransformFromDevice : Matrix.Identity;
            PlaceControl(draftSurface, input, scale);
            PlaceControl(send, action, scale);
            if (!overlay.IsVisible) overlay.Show();
            if (!SetWindowPos(hwnd, new IntPtr(-1), x, y, width, height, 0x0010))
            {
                overlay.Hide();
                return;
            }
            lastInput = found.InputBounds;
            lastAction = found.ActionBounds;
        }

        private static void PlaceControl(FrameworkElement control, Rect pixels, Matrix transform)
        {
            var position = transform.Transform(pixels.TopLeft);
            var corner = transform.Transform(pixels.BottomRight);
            Canvas.SetLeft(control, position.X);
            Canvas.SetTop(control, position.Y);
            control.Width = corner.X - position.X;
            control.Height = corner.Y - position.Y;
        }

        private bool ApplyMountRegion(Rect input, Rect action)
        {
            IntPtr region = CreateMountRegion(input, action);
            if (region == IntPtr.Zero) return false;
            if (SetWindowRgn(hwnd, region, true) != 0)
                return true; // Windows owns the region after SetWindowRgn succeeds.
            DeleteObject(region);
            return false;
        }

        private static IntPtr CreateMountRegion(Rect input, Rect action)
        {
            IntPtr primary = CreateRectRgn((int)input.Left, (int)input.Top, (int)input.Right, (int)input.Bottom);
            IntPtr extra = CreateRectRgn((int)action.Left, (int)action.Top, (int)action.Right, (int)action.Bottom);
            try
            {
                if (primary == IntPtr.Zero || extra == IntPtr.Zero || CombineRgn(primary, primary, extra, 2) == 0)
                    return IntPtr.Zero;
                IntPtr result = primary;
                primary = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (extra != IntPtr.Zero) DeleteObject(extra);
                if (primary != IntPtr.Zero) DeleteObject(primary);
            }
        }

        internal static bool MountHitTest(Rect input, Rect action, Rect passthrough)
        {
            IntPtr region = CreateMountRegion(input, action);
            if (region == IntPtr.Zero) return false;
            try
            {
                return PtInRegion(region, (int)(input.X + input.Width / 2), (int)(input.Y + input.Height / 2)) &&
                       PtInRegion(region, (int)(action.X + action.Width / 2), (int)(action.Y + action.Height / 2)) &&
                       !PtInRegion(region, (int)(passthrough.X + passthrough.Width / 2),
                           (int)(passthrough.Y + passthrough.Height / 2));
            }
            finally { DeleteObject(region); }
        }

        private async Task Submit()
        {
            if (busy || locating || paused || target == null || String.IsNullOrWhiteSpace(draft.Text)) return;
            busy = true;
            draft.IsReadOnly = true;
            send.IsEnabled = false;
            var expected = target;
            try
            {
                var result = await detector.Inspect(draft.Text, targetId);
                if (disposed || paused) return;
                var decision = StatusText.Read(result, "decision");
                var state = StatusText.Read(result, "state");
                if (!StatusText.IsAccepted(decision, state))
                {
                    var reason = StatusText.Read(result, "reason");
                    if (String.IsNullOrWhiteSpace(reason)) reason = "The local check did not approve this draft.";
                    Notify(decision == "UNCERTAIN" ? "Uncertain · Not sent" : "Prompt blocked",
                           decision == "UNCERTAIN" ? reason + "\nEdit the draft and try again." : reason);
                    return;
                }
                var approved = StatusText.Read(result, "text");
                if (String.IsNullOrWhiteSpace(approved) || GetForegroundWindow() != hwnd ||
                    !SameChat(expected, await Task.Run(() => transport.FindBound(expected))) ||
                    GetForegroundWindow() != hwnd)
                {
                    Notify("Draft kept local", "Return to the original conversation and try again.");
                    return;
                }
                var delivery = await Task.Run(() => {
                    string status;
                    var submitted = transport.TrySend(expected, approved, out status, () => paused || disposed);
                    return Tuple.Create(submitted, status);
                });
                if (disposed) return;
                if (!delivery.Item1)
                {
                    Notify("Delivery not confirmed", delivery.Item2);
                    return;
                }
                overlay.Hide();
                draft.Clear();
                if (decision == "SANITIZE")
                {
                    var removed = StatusText.Read(result, "removed");
                    Notify("Sanitized and sent", String.IsNullOrWhiteSpace(removed)
                        ? "The approved remainder was sent." : "Removed:\n" + removed);
                }
            }
            catch (Exception)
            {
                if (!disposed) Notify("Draft kept local", "Protected Send could not complete the local check.");
            }
            finally
            {
                if (!disposed) { busy = false; draft.IsReadOnly = false; send.IsEnabled = true; }
            }
        }

        private void Notify(string title, string message)
        {
            var content = new StackPanel { Margin = new Thickness(14) };
            content.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.Bold, Foreground = Brushes.White });
            content.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap,
                                                 Foreground = Brushes.White, Margin = new Thickness(0, 6, 0, 0) });
            var notice = new Window { Content = content, Width = 390, SizeToContent = SizeToContent.Height,
                WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false,
                ShowActivated = false, Topmost = true, Background = new SolidColorBrush(Color.FromRgb(31, 41, 55)),
                WindowStartupLocation = WindowStartupLocation.Manual };
            var area = SystemParameters.WorkArea;
            notice.Left = area.Right - notice.Width - 16;
            notice.Top = area.Top + 16;
            notice.Show();
            var expiry = new DispatcherTimer { Interval = TimeSpan.FromSeconds(9) };
            expiry.Tick += delegate { expiry.Stop(); notice.Close(); };
            expiry.Start();
        }

        private void OpenDashboard()
        {
            try { Process.Start(Path.Combine(root, "security-dashboard.exe"), "--db \"" + audit + "\""); }
            catch (Exception) { Notify("Dashboard unavailable", "The bundled dashboard could not be opened."); }
        }

        public void Dispose() { disposed = true; timer.Stop(); StopNativeMonitor(); detector.Dispose(); }

        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr window, IntPtr after,
            int x, int y, int width, int height, uint flags);
        [DllImport("user32.dll")] private static extern int SetWindowRgn(IntPtr window, IntPtr region, bool redraw);
        [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr handle);
        [DllImport("gdi32.dll")] private static extern IntPtr CreateRectRgn(int left, int top, int right, int bottom);
        [DllImport("gdi32.dll")] private static extern int CombineRgn(IntPtr result, IntPtr left, IntPtr right, int mode);
        [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr handle);
        [DllImport("gdi32.dll")] private static extern bool PtInRegion(IntPtr region, int x, int y);
    }
}
