using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace ProtectedSend
{
    internal enum NativeSendTrigger { Enter, Click }

    internal sealed class NativeSendIntent
    {
        internal NativeSendIntent(Target target, NativeSendTrigger trigger)
        {
            Target = target;
            Trigger = trigger;
        }

        internal Target Target { get; private set; }
        internal NativeSendTrigger Trigger { get; private set; }
    }

    /// <summary>
    /// Watches only Send gestures. Accessibility inspection, draft handling and
    /// screening belong to the dispatcher consumer, never the hook callbacks.
    /// All public members must be used on the owning dispatcher.
    /// </summary>
    internal sealed class NativeSendMonitor : IDisposable
    {
        private const int FreshForMilliseconds = 650;
        private const int KeyboardHookId = 13;
        private const int MouseHookId = 14;
        private const int ReturnKey = 0x0D;
        private static readonly IntPtr Suppress = new IntPtr(1);
        private readonly Dispatcher dispatcher;
        private readonly Action<NativeSendIntent> onSend;
        private readonly HookCallback keyboardCallback;
        private readonly HookCallback mouseCallback;
        private readonly int dragWidth;
        private readonly int dragHeight;
        private IntPtr keyboardHook, mouseHook;
        private Snapshot snapshot;
        private readonly Press mainEnter = new Press();
        private readonly Press extendedEnter = new Press();
        private readonly Press mouseLeft = new Press();
        private NativePoint mouseOrigin;
        private bool busy, queued, disposed;

        internal NativeSendMonitor(Dispatcher dispatcher, Action<NativeSendIntent> onSend)
        {
            if (dispatcher == null) throw new ArgumentNullException("dispatcher");
            if (onSend == null) throw new ArgumentNullException("onSend");
            dispatcher.VerifyAccess();
            this.dispatcher = dispatcher;
            this.onSend = onSend;
            keyboardCallback = KeyboardEvent;
            mouseCallback = MouseEvent;
            dragWidth = Math.Max(2, GetSystemMetrics(68) / 2);
            dragHeight = Math.Max(2, GetSystemMetrics(69) / 2);
        }

        internal void Start()
        {
            dispatcher.VerifyAccess();
            if (disposed) throw new ObjectDisposedException(GetType().Name);
            if (keyboardHook != IntPtr.Zero) return;
            IntPtr module = GetModuleHandle(null);
            keyboardHook = SetWindowsHookEx(KeyboardHookId, keyboardCallback, module, 0);
            if (keyboardHook == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not monitor native Enter.");
            mouseHook = SetWindowsHookEx(MouseHookId, mouseCallback, module, 0);
            if (mouseHook == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                UnhookWindowsHookEx(keyboardHook);
                keyboardHook = IntPtr.Zero;
                throw new Win32Exception(error, "Could not monitor native Send clicks.");
            }
        }

        internal void Update(Target target, bool composerFocused, Rect sendBounds, int? observedAt = null)
        {
            dispatcher.VerifyAccess();
            uint pid;
            if (disposed || target == null || target.WindowHandle == IntPtr.Zero ||
                GetWindowThreadProcessId(target.WindowHandle, out pid) == 0 || pid == 0)
            {
                snapshot = null;
                return;
            }
            snapshot = new Snapshot(target, pid, composerFocused, UsableBounds(sendBounds) ? sendBounds : Rect.Empty,
                                    observedAt ?? Environment.TickCount);
        }

        internal void SetBusy(bool value)
        {
            dispatcher.VerifyAccess();
            busy = value;
        }

        public void Dispose()
        {
            dispatcher.VerifyAccess();
            if (disposed) return;
            disposed = true;
            snapshot = null;
            mainEnter.End();
            extendedEnter.End();
            mouseLeft.End();
            if (keyboardHook != IntPtr.Zero) UnhookWindowsHookEx(keyboardHook);
            if (mouseHook != IntPtr.Zero) UnhookWindowsHookEx(mouseHook);
            keyboardHook = mouseHook = IntPtr.Zero;
        }

        private IntPtr KeyboardEvent(int code, IntPtr message, IntPtr data)
        {
            if (code < 0 || disposed) return CallNextHookEx(keyboardHook, code, message, data);
            try
            {
                // Read no other key payload. Track only the two physical Enter keys.
                if (Marshal.ReadInt32(data, 0) != ReturnKey)
                    return CallNextHookEx(keyboardHook, code, message, data);
                int flags = Marshal.ReadInt32(data, 8);
                if ((flags & 0x12) != 0) // injected / lower-integrity injected
                    return CallNextHookEx(keyboardHook, code, message, data);
                var press = (flags & 0x01) != 0 ? extendedEnter : mainEnter;
                int kind = message.ToInt32();
                if (kind == 0x101 || kind == 0x105)
                {
                    bool consumed = press.Consumed;
                    var captured = press.End();
                    if (consumed)
                    {
                        if (!ModifiersDown()) QueueIntent(captured, NativeSendTrigger.Enter);
                        return Suppress;
                    }
                }
                else if (kind == 0x100 || kind == 0x104)
                {
                    if (press.Consumed) return Suppress;
                    var current = snapshot;
                    if (!press.Observed && kind == 0x100 && (flags & 0x20) == 0 && IsCurrent(current) &&
                        current.ComposerFocused && !ModifiersDown())
                    {
                        press.Begin(busy || queued ? null : current);
                        return Suppress;
                    }
                    press.Pass();
                }
            }
            catch (Exception) { }
            return CallNextHookEx(keyboardHook, code, message, data);
        }

        private IntPtr MouseEvent(int code, IntPtr message, IntPtr data)
        {
            if (code < 0 || disposed) return CallNextHookEx(mouseHook, code, message, data);
            try
            {
                int kind = message.ToInt32();
                if ((kind == 0x201 && !mouseLeft.Consumed && !IsCurrent(snapshot)) ||
                    (kind == 0x202 && !mouseLeft.Consumed) ||
                    (kind != 0x201 && kind != 0x202 && !(kind == 0x200 && mouseLeft.Captured != null)))
                    return CallNextHookEx(mouseHook, code, message, data);
                // Never read movement outside a captured button press.
                int flags = Marshal.ReadInt32(data, 12);
                if ((flags & 0x03) != 0)
                    return CallNextHookEx(mouseHook, code, message, data);
                var point = new NativePoint { X = Marshal.ReadInt32(data, 0), Y = Marshal.ReadInt32(data, 4) };
                if (kind == 0x200)
                {
                    if (MovedBeyondClick(point)) mouseLeft.CancelIntent();
                }
                else if (kind == 0x202)
                {
                    var captured = mouseLeft.End();
                    // A drag, click moved off the target, or changed Send geometry never submits.
                    if (captured != null && !MovedBeyondClick(point) &&
                        Matches(captured, snapshot) && captured.SendBounds == snapshot.SendBounds &&
                        HitsSend(snapshot, point) && !ModifiersDown())
                        QueueIntent(captured, NativeSendTrigger.Click);
                    return Suppress;
                }
                else
                {
                    if (mouseLeft.Consumed) return Suppress;
                    var current = snapshot;
                    if (HitsSend(current, point) && !ModifiersDown())
                    {
                        mouseOrigin = point;
                        mouseLeft.Begin(busy || queued ? null : current);
                        return Suppress;
                    }
                }
            }
            catch (Exception) { }
            return CallNextHookEx(mouseHook, code, message, data);
        }

        private void QueueIntent(Snapshot captured, NativeSendTrigger trigger)
        {
            if (captured == null || busy || queued || !Matches(captured, snapshot) ||
                !IsCurrent(snapshot))
                return;
            queued = true;
            try
            {
                dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(delegate
                {
                    queued = false;
                    var current = snapshot;
                    if (!disposed && !busy && Matches(captured, current) && IsCurrent(current) &&
                        (trigger != NativeSendTrigger.Enter || current.ComposerFocused) &&
                        (trigger != NativeSendTrigger.Click || current.SendBounds == captured.SendBounds))
                        onSend(new NativeSendIntent(captured.Target, trigger));
                }));
            }
            catch (InvalidOperationException) { queued = false; }
        }

        private bool MovedBeyondClick(NativePoint point)
        {
            return MovedBeyondClick(mouseOrigin, point, dragWidth, dragHeight);
        }

        private static bool MovedBeyondClick(NativePoint origin, NativePoint point, int width, int height)
        {
            return Math.Abs((long)point.X - origin.X) > width ||
                   Math.Abs((long)point.Y - origin.Y) > height;
        }

        private static bool HitsSend(Snapshot current, NativePoint point)
        {
            if (!IsCurrent(current) || !ContainsPoint(current.SendBounds, point))
                return false;
            return GetAncestor(WindowFromPoint(point), 2) == current.Target.WindowHandle; // GA_ROOT
        }

        private static bool ContainsPoint(Rect bounds, NativePoint point)
        {
            return !bounds.IsEmpty && point.X >= bounds.Left && point.X < bounds.Right &&
                   point.Y >= bounds.Top && point.Y < bounds.Bottom;
        }

        private static bool IsCurrent(Snapshot current)
        {
            uint pid;
            return current != null && IsFresh(current.ObservedAt, Environment.TickCount) &&
                   GetForegroundWindow() == current.Target.WindowHandle &&
                   GetWindowThreadProcessId(current.Target.WindowHandle, out pid) != 0 && pid == current.ProcessId;
        }

        private static bool IsFresh(int observedAt, int now)
        {
            return unchecked((uint)(now - observedAt)) <= FreshForMilliseconds;
        }

        private static bool Matches(Snapshot first, Snapshot second)
        {
            return first != null && second != null &&
                   first.ProcessId == second.ProcessId && first.Target.WindowHandle == second.Target.WindowHandle &&
                   String.Equals(first.Target.ThreadIdentity, second.Target.ThreadIdentity, StringComparison.Ordinal);
        }

        private static bool UsableBounds(Rect bounds)
        {
            return !bounds.IsEmpty && bounds.Width > 0 && bounds.Height > 0 &&
                   bounds.Left >= Int32.MinValue && bounds.Top >= Int32.MinValue &&
                   bounds.Right <= Int32.MaxValue && bounds.Bottom <= Int32.MaxValue;
        }

        private static bool ModifiersDown()
        {
            return (GetAsyncKeyState(0x10) & 0x8000) != 0 || (GetAsyncKeyState(0x11) & 0x8000) != 0 ||
                   (GetAsyncKeyState(0x12) & 0x8000) != 0 || (GetAsyncKeyState(0x5B) & 0x8000) != 0 ||
                   (GetAsyncKeyState(0x5C) & 0x8000) != 0;
        }

        internal static bool SelfTest()
        {
            var rect = new Rect(-40, 20, 30, 30);
            var point = new NativePoint { X = -40, Y = 20 };
            if (!UsableBounds(rect) || UsableBounds(Rect.Empty) ||
                UsableBounds(new Rect(0, 0, Double.PositiveInfinity, 1)) ||
                !ContainsPoint(rect, point) ||
                ContainsPoint(rect, new NativePoint { X = -10, Y = 20 }) ||
                ContainsPoint(rect, new NativePoint { X = -40, Y = 50 }) ||
                MovedBeyondClick(point, new NativePoint { X = -38, Y = 22 }, 2, 2) ||
                !MovedBeyondClick(point, new NativePoint { X = -37, Y = 20 }, 2, 2))
                return false;

            var target = new Target(new IntPtr(7), "thread-one", rect, rect);
            var first = new Snapshot(target, 9, true, rect, Int32.MaxValue - 100);
            var second = new Snapshot(target, 9, false, rect, Int32.MinValue + 100);
            var changedThread = new Target(new IntPtr(7), "thread-two", rect, rect);
            if (!Matches(first, second) || Matches(first, new Snapshot(target, 10, true, rect, 0)) ||
                Matches(first, new Snapshot(changedThread, 9, true, rect, 0)) ||
                !IsFresh(first.ObservedAt, second.ObservedAt) ||
                !IsFresh(1000, 1650) || IsFresh(1000, 1651) || IsFresh(1000, 999))
                return false;

            var press = new Press();
            press.Pass();
            if (!press.Observed || press.Consumed || press.End() != null || press.Observed) return false;
            press.Begin(first);
            if (!press.Observed || !press.Consumed || press.End() != first || press.Consumed) return false;
            press.Begin(first);
            press.CancelIntent();
            return press.Consumed && press.End() == null && !press.Observed;
        }

        private sealed class Press
        {
            internal bool Observed { get; private set; }
            internal bool Consumed { get; private set; }
            internal Snapshot Captured { get; private set; }
            internal void Begin(Snapshot current) { Observed = Consumed = true; Captured = current; }
            internal void Pass() { Observed = true; }
            internal void CancelIntent() { Captured = null; }
            internal Snapshot End()
            {
                var result = Captured;
                Observed = Consumed = false;
                Captured = null;
                return result;
            }
        }

        private sealed class Snapshot
        {
            internal readonly Target Target;
            internal readonly uint ProcessId;
            internal readonly bool ComposerFocused;
            internal readonly Rect SendBounds;
            internal readonly int ObservedAt;

            internal Snapshot(Target target, uint pid, bool focused, Rect bounds, int observedAt)
            {
                Target = target;
                ProcessId = pid;
                ComposerFocused = focused;
                SendBounds = bounds;
                ObservedAt = observedAt;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativePoint { internal int X, Y; }
        private delegate IntPtr HookCallback(int code, IntPtr message, IntPtr data);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int hookId, HookCallback callback, IntPtr module, uint threadId);
        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hook);
        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr message, IntPtr data);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string name);
        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
        [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int key);
        [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
        [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(NativePoint point);
        [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr window, uint flags);
    }
}
