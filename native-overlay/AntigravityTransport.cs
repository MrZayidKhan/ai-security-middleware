using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Automation;
using Condition = System.Windows.Automation.Condition;

namespace ProtectedSend
{
    internal sealed class Target
    {
        internal Target(IntPtr window, string threadIdentity, Rect input, Rect action, string draftFingerprint = null)
        {
            WindowHandle = window;
            ThreadIdentity = threadIdentity;
            InputBounds = input;
            ActionBounds = action;
            DraftFingerprint = draftFingerprint;
        }

        internal IntPtr WindowHandle { get; private set; }
        internal string ThreadIdentity { get; private set; }
        internal Rect InputBounds { get; private set; }
        internal Rect ActionBounds { get; private set; }
        internal string DraftFingerprint { get; private set; }
    }

    internal sealed class AntigravityTransport
    {
        private const int MaxDraft = 20000;
        private const string ComposerName = "Message input";
        private const string Placeholder = "Ask anything, @ to mention, / for actions";
        private const string SendName = "Send message";
        private const string VoiceName = "Start Voice mode";
        private static readonly Regex ThreadToken = new Regex(
            @"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly HashSet<string> ThreadKeys = new HashSet<string>(
            new[] { "conversationId", "conversation", "conversation_id", "threadId", "thread", "thread_id" },
            StringComparer.OrdinalIgnoreCase);
        private readonly object sendLock = new object();

        internal sealed class NativeCandidate
        {
            internal Target Target;
            internal bool Focused;
            internal Rect SendBounds;
        }

        internal NativeCandidate FindNativeCandidate()
        {
            try
            {
                var snapshot = ReadWindow(GetForegroundWindow());
                if (snapshot == null) return null;
                var send = FindButton(snapshot.Scope, SendName);
                if (send == null || !send.Current.IsEnabled) return null;
                string draft = ReadText(snapshot.Composer);
                if (!CanInsert(draft)) return null;
                var target = snapshot.Target;
                return new NativeCandidate { Target = new Target(target.WindowHandle, target.ThreadIdentity,
                    target.InputBounds, target.ActionBounds, Fingerprint(draft)), Focused = ComposerHasFocus(snapshot),
                    SendBounds = send.Current.BoundingRectangle };
            }
            catch (Exception) { return null; }
        }

        internal string ReadNativeDraft(Target expected)
        {
            try
            {
                if (GetForegroundWindow() != expected.WindowHandle) return null;
                var snapshot = ReadWindow(expected.WindowHandle);
                if (!SameTarget(expected, snapshot)) return null;
                string text = ReadText(snapshot.Composer);
                return CanInsert(text) && expected.DraftFingerprint != null &&
                    String.Equals(expected.DraftFingerprint, Fingerprint(text), StringComparison.Ordinal) ? text : null;
            }
            catch (Exception) { return null; }
        }

        internal static string Fingerprint(string text)
        {
            using (var hash = SHA256.Create())
                return Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(NormalizeLineEndings(text))));
        }

        internal bool TrySendNative(Target target, string original, string approved, Func<bool> cancelled,
            out string status)
        {
            lock (sendLock)
            {
                bool invoked = false;
                status = "The conversation or native draft changed. Nothing was sent.";
                try
                {
                    if (cancelled() || !CanInsert(approved) ||
                        GetForegroundWindow() != target.WindowHandle) return false;
                    var before = ReadWindow(target.WindowHandle);
                    if (!SameTarget(target, before) || !MatchesApproved(before.Composer, original)) return false;
                    var ready = before;
                    if (!String.Equals(original, approved, StringComparison.Ordinal))
                    {
                        object textPattern;
                        before.Composer.SetFocus();
                        var focused = ReadWindow(target.WindowHandle);
                        if (!SameComposer(before, focused) || !ComposerHasFocus(focused) ||
                            !MatchesApproved(focused.Composer, original) ||
                            !focused.Composer.TryGetCurrentPattern(TextPattern.Pattern, out textPattern))
                        {
                            status = "The native draft cannot be safely selected for cleanup. Nothing was sent.";
                            return false;
                        }
                        if (!TrySelectNativeDraft(focused, (TextPattern)textPattern, original, cancelled))
                        {
                            status = "The selected draft did not match the checked text. Nothing was sent.";
                            return false;
                        }
                        var selectionTarget = ReadWindow(target.WindowHandle);
                        if (!SameComposer(focused, selectionTarget) || !ComposerHasFocus(selectionTarget) ||
                            !MatchesApproved(selectionTarget.Composer, original) ||
                            !SelectionMatches((TextPattern)textPattern, original) ||
                            cancelled() || ModifiersDown() || !InsertText(approved))
                            return false;
                        ready = WaitForReadback(focused, approved);
                        if (ready == null)
                        {
                            status = "The cleaned text could not be verified in Antigravity. Nothing was sent.";
                            return false;
                        }
                    }
                    var button = FindButton(ready.Scope, SendName);
                    object action;
                    if (button == null || !button.Current.IsEnabled ||
                        !button.TryGetCurrentPattern(InvokePattern.Pattern, out action)) return false;
                    var last = ReadWindow(target.WindowHandle);
                    if (cancelled() || GetForegroundWindow() != target.WindowHandle || !SameComposer(ready, last) ||
                        !MatchesApproved(last.Composer, approved) ||
                        !SameElement(button, FindButton(last.Scope, SendName)) || !button.Current.IsEnabled) return false;
                    invoked = true;
                    ((InvokePattern)action).Invoke();
                    status = "Checked draft submitted to Antigravity.";
                    return true;
                }
                catch (Exception)
                {
                    status = invoked ? "Submission could not be confirmed. Check Antigravity before retrying."
                        : "Native draft verification failed. Nothing was sent.";
                    return false;
                }
            }
        }

        internal Target FindForeground()
        {
            try
            {
                Snapshot current = ReadWindow(GetForegroundWindow());
                return EmptyComposer(current) ? current.Target : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal Target FindBound(Target original)
        {
            if (original == null || !UserIsInBoundWindowOrOverlay(original.WindowHandle))
                return null;
            try
            {
                Snapshot current = ReadWindow(original.WindowHandle);
                return SameTarget(original, current) ? current.Target : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal bool TrySend(Target target, string approved, out string status, Func<bool> cancelled)
        {
            lock (sendLock)
            {
                bool invokeStarted = false;
                try
                {
                    if (cancelled() || target == null || !CanInsert(approved))
                    {
                        status = "This draft cannot be sent through the verified composer.";
                        return false;
                    }

                    Snapshot before = ReadWindow(target.WindowHandle);
                    if (!SameTarget(target, before) || !EmptyComposer(before) ||
                        !UserIsInBoundWindowOrOverlay(target.WindowHandle))
                    {
                        status = "The conversation or native draft changed. Nothing was sent.";
                        return false;
                    }

                    if (GetForegroundWindow() != target.WindowHandle &&
                        !SetForegroundWindow(target.WindowHandle))
                    {
                        status = "Antigravity could not be activated. Nothing was sent.";
                        return false;
                    }
                    before.Composer.SetFocus();
                    Snapshot focused = ReadWindow(target.WindowHandle);
                    if (!SameComposer(before, focused) || !EmptyComposer(focused) ||
                        !ComposerHasFocus(focused) || ModifiersDown())
                    {
                        status = "Focus and an empty Antigravity composer could not be verified. Nothing was sent.";
                        return false;
                    }

                    if (cancelled() || !InsertText(approved))
                    {
                        status = "Text could not be inserted reliably. Nothing was sent. Check the native draft.";
                        return false;
                    }

                    Snapshot ready = WaitForReadback(focused, approved);
                    if (ready == null)
                    {
                        status = "The approved text or conversation could not be verified. Nothing was sent. Check the native draft.";
                        return false;
                    }
                    AutomationElement button = FindButton(ready.Scope, SendName);
                    object action;
                    if (button == null || !button.Current.IsEnabled ||
                        !button.TryGetCurrentPattern(InvokePattern.Pattern, out action))
                    {
                        status = "Antigravity did not expose a verified Send action. Nothing was sent.";
                        return false;
                    }

                    // Recheck after resolving the action. Never use a synthetic Enter as a fallback.
                    Snapshot last = ReadWindow(target.WindowHandle);
                    AutomationElement lastButton = SameComposer(ready, last) ? FindButton(last.Scope, SendName) : null;
                    if (cancelled() || lastButton == null || !lastButton.Current.IsEnabled ||
                        !SameElement(button, lastButton) || !ComposerHasFocus(last) ||
                        !MatchesApproved(last.Composer, approved))
                    {
                        status = "The conversation, draft, or Send button changed. Nothing was sent.";
                        return false;
                    }
                    invokeStarted = true;
                    ((InvokePattern)action).Invoke();
                    status = "Approved text handed to Antigravity.";
                    return true;
                }
                catch (Exception)
                {
                    status = invokeStarted
                        ? "Antigravity submission was not confirmed. Check the chat before retrying."
                        : "The Antigravity handoff could not be verified. Nothing was sent.";
                    return false;
                }
            }
        }

        private static bool EmptyComposer(Snapshot snapshot)
        {
            if (snapshot == null || HasVisibleButton(snapshot.Scope, SendName)) return false;
            var placeholder = FindUniqueVisible(snapshot.Scope, new AndCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text),
                new PropertyCondition(AutomationElement.NameProperty, Placeholder)));
            return ReadText(snapshot.Composer) == "" ||
                (placeholder != null && FindButton(snapshot.Scope, VoiceName) != null);
        }

        private static Snapshot WaitForReadback(Snapshot expected, string approved)
        {
            // Keyboard packets are queued asynchronously. A bounded wait can observe the app's
            // updated accessibility tree; no further input is sent while waiting.
            for (int attempt = 0; attempt < 12; attempt++)
            {
                Snapshot current = ReadWindow(expected.Target.WindowHandle);
                if (!SameComposer(expected, current) || !ComposerHasFocus(current))
                    return null;
                if (MatchesApproved(current.Composer, approved) && FindButton(current.Scope, SendName) != null)
                    return current;
                if (attempt < 11)
                    Thread.Sleep(25);
            }
            return null;
        }

        internal static string Diagnose(IntPtr hwnd)
        {
            var steps = new List<string>();
            try
            {
                var snapshot = ReadWindow(hwnd, steps.Add);
                if (snapshot != null)
                    steps.Add(EmptyComposer(snapshot) ? "Empty composer verified." : "Composer is not recognized as empty.");
            }
            catch (Exception error) { steps.Add(error.GetType().Name + ": " + error.Message); }
            return String.Join(Environment.NewLine, steps);
        }

        private static Snapshot ReadWindow(IntPtr hwnd, Action<string> trace = null)
        {
            trace = trace ?? delegate { };
            trace("Checking native window.");
            if (hwnd == IntPtr.Zero || !IsWindowVisible(hwnd) || IsIconic(hwnd))
                return null;

            uint processId;
            GetWindowThreadProcessId(hwnd, out processId);
            if (processId == 0)
                return null;
            string processStamp;
            using (var process = Process.GetProcessById(checked((int)processId)))
            {
                trace("Checking supported executable.");
                if (!IsSupportedExecutable(process.MainModule.FileName))
                    return null;
                processStamp = processId.ToString(CultureInfo.InvariantCulture) + ":" +
                    process.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture);
            }

            AutomationElement window = AutomationElement.FromHandle(hwnd);
            trace("Looking for a unique visible Message input control.");
            AutomationElement composer = FindUniqueVisible(window, new AndCondition(
                new PropertyCondition(AutomationElement.NameProperty, ComposerName),
                new OrCondition(
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ComboBox),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))));
            if (composer != null) trace("Composer enabled=" + composer.Current.IsEnabled +
                "; focusable=" + composer.Current.IsKeyboardFocusable + "; bounds=" + composer.Current.BoundingRectangle);
            if (composer == null || !composer.Current.IsEnabled || !composer.Current.IsKeyboardFocusable ||
                composer.Current.BoundingRectangle.IsEmpty || composer.Current.BoundingRectangle.Width < 20 ||
                composer.Current.BoundingRectangle.Height < 10)
                return null;

            string identity = ConversationIdentity(composer, window, trace);
            trace("Conversation route verified=" + (identity != null));
            AutomationElement scope = FindComposerScope(composer, window);
            trace("Composer controls verified=" + (scope != null));
            if (identity == null || scope == null)
                return null;
            var action = FindButton(scope, SendName) ?? FindButton(scope, VoiceName);
            var nativeControls = new List<Rect>();
            int modelSelectors = 0;
            foreach (AutomationElement button in scope.FindAll(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)))
            {
                if (button.Current.IsOffscreen || SameElement(button, action)) continue;
                if ((button.Current.Name ?? "").StartsWith("Select model", StringComparison.Ordinal)) modelSelectors++;
                nativeControls.Add(button.Current.BoundingRectangle);
            }
            Rect inputRegion = Rect.Empty;
            Rect sendRegion = Rect.Empty;
            bool mounted = modelSelectors == 1 && ComputeMountRegions(composer.Current.BoundingRectangle,
                window.Current.BoundingRectangle, action == null ? Rect.Empty : action.Current.BoundingRectangle,
                nativeControls, out inputRegion, out sendRegion);
            trace("Draft and Send coverage, native controls preserved=" + mounted);
            if (!mounted) return null;
            return new Snapshot(new Target(hwnd, processStamp + ":" + identity, inputRegion, sendRegion), composer, scope);
        }

        internal static bool ComputeMountRegions(Rect input, Rect window, Rect action,
            IEnumerable<Rect> nativeControls, out Rect inputRegion, out Rect actionRegion)
        {
            inputRegion = Rect.Empty;
            actionRegion = Rect.Empty;
            if (input.IsEmpty || window.IsEmpty || action.IsEmpty || !window.Contains(input) ||
                !window.Contains(action) || input.Width < 240 || input.Height < 20 ||
                action.Width < 16 || action.Width > 80 || action.Height < 16 || action.Height > 80)
                return false;
            var combined = Rect.Union(input, action);
            if (combined.Width > input.Width + 170 || combined.Height > input.Height + 115)
                return false;
            input = RoundOut(input);
            action = RoundOut(action);
            if (!window.Contains(input) || !window.Contains(action)) return false;
            foreach (Rect control in nativeControls)
                if (!control.IsEmpty && (Overlaps(input, control) || Overlaps(action, control)))
                    return false;
            inputRegion = input;
            actionRegion = action;
            return true;
        }

        private static Rect RoundOut(Rect rect)
        {
            double x = Math.Floor(rect.Left), y = Math.Floor(rect.Top);
            return new Rect(x, y, Math.Ceiling(rect.Right) - x, Math.Ceiling(rect.Bottom) - y);
        }

        private static bool Overlaps(Rect left, Rect right)
        {
            var intersection = Rect.Intersect(left, right);
            return !intersection.IsEmpty && intersection.Width > 0 && intersection.Height > 0;
        }

        private static bool IsSupportedExecutable(string path)
        {
            string userInstall = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs", "Antigravity", "Antigravity.exe");
            string machineInstall = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Antigravity", "Antigravity.exe");
            return string.Equals(path, userInstall, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(path, machineInstall, StringComparison.OrdinalIgnoreCase);
        }

        private static string ConversationIdentity(AutomationElement composer, AutomationElement window, Action<string> trace)
        {
            AutomationElement current = composer;
            for (int depth = 0; depth < 100 && current != null && !SameElement(current, window); depth++)
            {
                if (current.Current.ControlType == ControlType.Document)
                {
                    object value;
                    string route = null;
                    if (current.TryGetCurrentPattern(ValuePattern.Pattern, out value))
                        route = ((ValuePattern)value).Current.Value;
                    if (String.IsNullOrWhiteSpace(route))
                    {
                        // UIA_LegacyIAccessibleValuePropertyId. Chromium may expose the
                        // document URL here even when it lacks the managed Value pattern.
                        var legacyValue = AutomationProperty.LookupById(30093);
                        if (legacyValue != null)
                            route = current.GetCurrentPropertyValue(legacyValue, true) as string;
                    }
                    trace("Document route available=" + !String.IsNullOrWhiteSpace(route));
                    Uri uri;
                    if (!Uri.TryCreate(route, UriKind.Absolute, out uri) ||
                        !uri.IsLoopback || uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) ||
                        !HasThreadToken(uri))
                        return null;
                    // Use the actual document identity as well as the route, not its mutable window title.
                    return string.Join(".", current.GetRuntimeId()) + ":" + uri.AbsoluteUri;
                }
                current = TreeWalker.RawViewWalker.GetParent(current);
            }
            return null;
        }

        internal static bool HasThreadToken(Uri uri)
        {
            string identified = null;
            foreach (string entry in uri.Query.TrimStart('?').Split('&'))
            {
                string[] parts = entry.Split(new[] { '=' }, 2);
                if (!ThreadKeys.Contains(Uri.UnescapeDataString(parts[0])))
                    continue;
                if (parts.Length != 2 || identified != null)
                    return false;
                identified = Uri.UnescapeDataString(parts[1]);
            }
            if (identified != null)
                return IsThreadToken(identified);

            string[] path = uri.AbsolutePath.Trim('/').Split('/');
            return path.Length == 2 && (path[0] == "c" || ThreadKeys.Contains(path[0].TrimEnd('s'))) &&
                IsThreadToken(path[1]);
        }

        private static bool IsThreadToken(string token)
        {
            Guid parsed;
            return ThreadToken.IsMatch(token) && Guid.TryParse(token, out parsed) && parsed != Guid.Empty;
        }

        private static AutomationElement FindComposerScope(AutomationElement composer, AutomationElement window)
        {
            AutomationElement current = TreeWalker.RawViewWalker.GetParent(composer);
            for (int depth = 0; depth < 8 && current != null && !SameElement(current, window); depth++)
            {
                AutomationElement send = FindButton(current, SendName);
                AutomationElement voice = FindButton(current, VoiceName);
                if (FindButton(current, "Add context") != null && (send != null || voice != null))
                    return RecognizedComposerControls(current) ? current : null;
                current = TreeWalker.RawViewWalker.GetParent(current);
            }
            return null;
        }

        private static bool RecognizedComposerControls(AutomationElement scope)
        {
            var condition = new OrCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Hyperlink),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
            foreach (AutomationElement item in scope.FindAll(TreeScope.Descendants, condition))
            {
                if (item.Current.IsOffscreen)
                    continue;
                string name = item.Current.Name ?? "";
                if (item.Current.ControlType != ControlType.Button ||
                    !(name == SendName || name == VoiceName || name == "Add context" ||
                      name == "Record voice memo" ||
                      name.StartsWith("Select model", StringComparison.Ordinal) ||
                      name.StartsWith("Agent permissions preset selector", StringComparison.Ordinal)))
                    return false;
            }
            return true;
        }

        private static AutomationElement FindButton(AutomationElement root, string name)
        {
            return FindUniqueVisible(root, ButtonCondition(name));
        }

        private static bool HasVisibleButton(AutomationElement root, string name)
        {
            foreach (AutomationElement item in root.FindAll(TreeScope.Descendants, ButtonCondition(name)))
                if (!item.Current.IsOffscreen)
                    return true;
            return false;
        }

        private static Condition ButtonCondition(string name)
        {
            return new AndCondition(
                new PropertyCondition(AutomationElement.NameProperty, name),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button));
        }

        private static AutomationElement FindUniqueVisible(AutomationElement root, Condition condition)
        {
            AutomationElement found = null;
            foreach (AutomationElement candidate in root.FindAll(TreeScope.Descendants, condition))
            {
                if (candidate.Current.IsOffscreen)
                    continue;
                if (found != null)
                    return null;
                found = candidate;
            }
            return found;
        }

        private static string ReadText(AutomationElement composer)
        {
            object pattern;
            if (composer.TryGetCurrentPattern(TextPattern.Pattern, out pattern))
            {
                var document = ((TextPattern)pattern).DocumentRange;
                string textValue = document.GetText(MaxDraft + 1);
                // A multiline composer can expose paragraph descendants. Read its
                // editable range, but refuse object placeholders and silent truncation.
                if (textValue != null && textValue.Length <= MaxDraft && textValue.IndexOf('\uFFFC') < 0)
                    return NormalizeLineEndings(textValue);
            }

            // Chromium's ValuePattern can stay stale after application input has changed.
            // A single visible text leaf is usable. Unfamiliar rich/multiline trees fail closed.
            AutomationElement text = FindUniqueVisible(composer,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text));
            if (text == null)
                return null;
            return text.Current.Name == Placeholder ? "" : text.Current.Name;
        }

        private static bool MatchesApproved(AutomationElement composer, string approved)
        {
            string actual = ReadText(composer);
            return actual != null && string.Equals(actual, NormalizeLineEndings(approved), StringComparison.Ordinal);
        }

        private static string NormalizeLineEndings(string text)
        {
            return text == null ? null : text.Replace("\r\n", "\n");
        }

        internal static bool CanInsert(string text)
        {
            if (string.IsNullOrWhiteSpace(text) || text.Length > MaxDraft)
                return false;
            foreach (char character in text)
            {
                if (char.IsControl(character) && character != '\n' && character != '\r')
                    return false;
            }
            // Lone CR can have Enter semantics. LF is inserted only as a Unicode packet.
            return NormalizeLineEndings(text).IndexOf('\r') < 0;
        }

        private static bool SameTarget(Target expected, Snapshot current)
        {
            return expected != null && current != null && expected.WindowHandle == current.Target.WindowHandle &&
                string.Equals(expected.ThreadIdentity, current.Target.ThreadIdentity, StringComparison.Ordinal);
        }

        private static bool SameComposer(Snapshot expected, Snapshot current)
        {
            return SameTarget(expected.Target, current) && SameElement(expected.Composer, current.Composer);
        }

        private static bool SameElement(AutomationElement first, AutomationElement second)
        {
            return first != null && second != null && Automation.Compare(first, second);
        }

        private static bool ComposerHasFocus(Snapshot snapshot)
        {
            return snapshot != null && GetForegroundWindow() == snapshot.Target.WindowHandle &&
                (snapshot.Composer.Current.HasKeyboardFocus ||
                 SameElement(snapshot.Composer, AutomationElement.FocusedElement));
        }

        private static bool UserIsInBoundWindowOrOverlay(IntPtr hwnd)
        {
            IntPtr foreground = GetForegroundWindow();
            uint owner;
            GetWindowThreadProcessId(foreground, out owner);
            return foreground == hwnd || owner == GetCurrentProcessId();
        }

        private static bool ModifiersDown()
        {
            return (GetAsyncKeyState(0x10) & 0x8000) != 0 || (GetAsyncKeyState(0x11) & 0x8000) != 0 ||
                (GetAsyncKeyState(0x12) & 0x8000) != 0 || (GetAsyncKeyState(0x5B) & 0x8000) != 0 ||
                (GetAsyncKeyState(0x5C) & 0x8000) != 0;
        }

        private bool TrySelectNativeDraft(Snapshot focused, TextPattern pattern, string original, Func<bool> cancelled)
        {
            if (cancelled() || !ComposerHasFocus(focused) || ModifiersDown())
                return false;
            try { pattern.DocumentRange.Select(); }
            catch (InvalidOperationException) { } // The provider may expose text without implementing Select.
            if (WaitForSelection(focused, pattern, original, cancelled))
                return true;

            // Some Chromium composers expose a readable range but fail to select it through UI Automation.
            // Ask the verified editor to select its draft as a user would, then check the entire selection.
            var current = ReadWindow(focused.Target.WindowHandle);
            if (cancelled() || !SameComposer(focused, current) || !ComposerHasFocus(current) ||
                !MatchesApproved(current.Composer, original) || ModifiersDown())
                return false;
            var selectAll = new[] {
                KeyboardPacket('\0', 0, 0x11), KeyboardPacket('\0', 0, 0x41),
                KeyboardPacket('\0', 0x0002, 0x41), KeyboardPacket('\0', 0x0002, 0x11)
            };
            if (SendInput((uint)selectAll.Length, selectAll, Marshal.SizeOf(typeof(INPUT))) != selectAll.Length)
                return false;
            return WaitForSelection(focused, pattern, original, cancelled);
        }

        private static bool WaitForSelection(Snapshot focused, TextPattern pattern, string original, Func<bool> cancelled)
        {
            // Accessibility selection events can lag behind the editor's input processing.
            for (int attempt = 0; attempt < 8; attempt++)
            {
                if (cancelled() || !ComposerHasFocus(focused) || ModifiersDown())
                    return false;
                if (SelectionMatches(pattern, original))
                    return true;
                Thread.Sleep(20);
            }
            return false;
        }

        private static bool SelectionMatches(TextPattern pattern, string original)
        {
            var selection = pattern.GetSelection();
            return selection != null && selection.Length == 1 &&
                String.Equals(NormalizeLineEndings(selection[0].GetText(MaxDraft + 1)),
                    NormalizeLineEndings(original), StringComparison.Ordinal);
        }

        private static bool InsertText(string text)
        {
            string normalized = NormalizeLineEndings(text);
            var input = new INPUT[normalized.Length * 2];
            for (int index = 0; index < normalized.Length; index++)
            {
                input[2 * index] = KeyboardPacket(normalized[index], 0x0004);
                input[2 * index + 1] = KeyboardPacket(normalized[index], 0x0004 | 0x0002);
            }
            return SendInput((uint)input.Length, input, Marshal.SizeOf(typeof(INPUT))) == input.Length;
        }

        private static INPUT KeyboardPacket(char character, uint flags, ushort virtualKey = 0)
        {
            return new INPUT
            {
                Type = 1,
                Value = new InputUnion
                {
                    Keyboard = new KeyboardInput { Scan = character, Flags = flags, VirtualKey = virtualKey },
                },
            };
        }

        private sealed class Snapshot
        {
            internal Snapshot(Target target, AutomationElement composer, AutomationElement scope)
            {
                Target = target;
                Composer = composer;
                Scope = scope;
            }

            internal readonly Target Target;
            internal readonly AutomationElement Composer;
            internal readonly AutomationElement Scope;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT
        {
            internal uint Type;
            internal InputUnion Value;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct InputUnion
        {
            // Include the largest Win32 union member so sizeof(INPUT) is correct on x64 and x86.
            [FieldOffset(0)] internal MouseInput Mouse;
            [FieldOffset(0)] internal KeyboardInput Keyboard;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MouseInput
        {
            internal int X, Y;
            internal uint MouseData, Flags, Time;
            internal IntPtr ExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KeyboardInput
        {
            internal ushort VirtualKey, Scan;
            internal uint Flags, Time;
            internal IntPtr ExtraInfo;
        }

        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint process);
        [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int key);
        [DllImport("user32.dll")] private static extern uint SendInput(uint count, INPUT[] input, int size);
        [DllImport("kernel32.dll")] private static extern uint GetCurrentProcessId();
    }
}
