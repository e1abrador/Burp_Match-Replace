from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import (JPanel, JLabel, JTextField, JButton, BorderFactory,
                         BoxLayout, Box, JCheckBox, JComboBox, JOptionPane)
from java.awt import BorderLayout
import re

VERSION = "1.0"

MAX_UNDO = 10

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Match & Replace (Request) Enhanced")
        callbacks.registerMessageEditorTabFactory(self)

        print("MatchReplaceTab - Version %s" % VERSION)

    def createNewInstance(self, controller, editable):
        return MatchReplaceTab(self.callbacks, self.helpers, controller, editable)


class MatchReplaceTab(IMessageEditorTab):
    def __init__(self, callbacks, helpers, controller, editable):
        self.callbacks = callbacks
        self.helpers = helpers
        self._controller = controller
        self._editable = editable

        # Burp native editor (Pretty/Raw/Hex support)
        self._txtInput = callbacks.createMessageEditor(None, editable)

        # Main panel
        self._panel = JPanel(BorderLayout())
        self._panel.add(self._txtInput.getComponent(), BorderLayout.CENTER)

        # Top panel with 2 rows
        self._topPanel = JPanel()
        self._topPanel.setLayout(BoxLayout(self._topPanel, BoxLayout.Y_AXIS))

        # --- First row: Match / Replace inputs + buttons ---
        firstRow = JPanel()
        firstRow.setLayout(BoxLayout(firstRow, BoxLayout.X_AXIS))
        self._lblMatch = JLabel("Match: ")
        self._txtMatch = JTextField(20)
        self._lblReplace = JLabel("Replace: ")
        self._txtReplace = JTextField(20)
        self._btnDo = JButton("Apply Replace", actionPerformed=self.do_replace)
        self._btnUndo = JButton("Undo", actionPerformed=self.do_undo)
        self._btnClearHistory = JButton("Clear History", actionPerformed=self.clear_history)

        firstRow.add(self._lblMatch)
        firstRow.add(self._txtMatch)
        firstRow.add(Box.createHorizontalStrut(10))
        firstRow.add(self._lblReplace)
        firstRow.add(self._txtReplace)
        firstRow.add(Box.createHorizontalStrut(10))
        firstRow.add(self._btnDo)
        firstRow.add(Box.createHorizontalStrut(6))
        firstRow.add(self._btnUndo)
        firstRow.add(Box.createHorizontalStrut(6))
        firstRow.add(self._btnClearHistory)

        # --- Second row: checkboxes + scope ---
        secondRow = JPanel()
        secondRow.setLayout(BoxLayout(secondRow, BoxLayout.X_AXIS))
        self._chkRegex = JCheckBox("Regex", False)        # deselected
        self._chkIcase = JCheckBox("Ignore case", True)   # selected by default
        self._scopeOptions = ["Selection", "Body", "Headers", "URL", "Whole request"]
        self._cmbScope = JComboBox(self._scopeOptions)
        self._cmbScope.setSelectedIndex(0)  # default Selection

        secondRow.add(self._chkRegex)
        secondRow.add(Box.createHorizontalStrut(10))
        secondRow.add(self._chkIcase)
        secondRow.add(Box.createHorizontalStrut(10))
        secondRow.add(self._cmbScope)

        # Add rows to top panel
        self._topPanel.add(firstRow)
        self._topPanel.add(Box.createVerticalStrut(6))
        self._topPanel.add(secondRow)

        # Add top panel to main panel
        self._panel.add(self._topPanel, BorderLayout.NORTH)

        # Store current message and state
        self._currentMessage = None
        self._isRequest = True
        self._modified = False

        # Undo/history stack: list of bytes
        self._undo_stack = []

    # IMessageEditorTab methods
    def getTabCaption(self):
        return "Match&Replace"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return isRequest and content is not None

    def setMessage(self, content, isRequest):
        self._isRequest = isRequest
        if content is None:
            self._txtInput.setMessage(None, isRequest)
            self._currentMessage = None
            self._modified = False
            self._undo_stack = []
            return
        self._currentMessage = content
        self._txtInput.setMessage(content, isRequest)
        self._modified = False
        self._undo_stack = []

    def getMessage(self):
        # Ensure Burp always receives the latest bytes from our editor
        msg = self._txtInput.getMessage()
        if msg is not None:
            self._currentMessage = msg
        return self._currentMessage

    def isModified(self):
        return self._modified or self._txtInput.isMessageModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedData()

    # Undo stack helpers
    def push_undo(self, bytes_msg):
        try:
            if bytes_msg is None:
                return
            # if stack top equals new, skip
            if len(self._undo_stack) > 0 and self._undo_stack[-1] == bytes_msg:
                return
            self._undo_stack.append(bytes_msg)
            if len(self._undo_stack) > MAX_UNDO:
                # drop oldest
                self._undo_stack.pop(0)
        except Exception:
            pass

    def do_undo(self, event):
        try:
            if not self._undo_stack:
                JOptionPane.showMessageDialog(None, "No history to undo.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            # Pop current if equals editor state
            current = self.getMessage()
            if self._undo_stack and self._undo_stack[-1] == current:
                self._undo_stack.pop()  # current state on top
            if not self._undo_stack:
                JOptionPane.showMessageDialog(None, "No earlier state to restore.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            previous = self._undo_stack.pop()
            # apply previous
            self._txtInput.setMessage(previous, self._isRequest)
            self._currentMessage = previous
            self._modified = True
        except Exception as ex:
            self.callbacks.printError("Error in do_undo: %s" % str(ex))

    def clear_history(self, event):
        self._undo_stack = []
        JOptionPane.showMessageDialog(None, "History cleared.", "Info", JOptionPane.INFORMATION_MESSAGE)

    # Utility: split request into head (start-line + headers) and body string
    def split_request(self, request_str):
        # Return (head_str, body_str) where head_str includes start-line and headers
        sep = "\r\n\r\n"
        if sep in request_str:
            parts = request_str.split(sep, 1)
            return parts[0], parts[1]
        else:
            return request_str, ""

    # Replace helpers for each scope
    def replace_in_selection(self, orig_str, match_str, repl_str, use_regex, ignore_case, sel_start, sel_end):
        selected_part = orig_str[sel_start:sel_end]
        new_selected = self.perform_replace(selected_part, match_str, repl_str, use_regex, ignore_case)
        return orig_str[:sel_start] + new_selected + orig_str[sel_end:], sel_start, sel_start + len(new_selected)

    def replace_in_body(self, orig_str, match_str, repl_str, use_regex, ignore_case):
        head, body = self.split_request(orig_str)
        new_body = self.perform_replace(body, match_str, repl_str, use_regex, ignore_case)
        new_full = head + "\r\n\r\n" + new_body
        # body region start index:
        body_start = len(head) + 4
        return new_full, body_start, body_start + len(new_body)

    def replace_in_headers(self, orig_str, match_str, repl_str, use_regex, ignore_case):
        head, body = self.split_request(orig_str)
        lines = head.split("\r\n")
        if not lines:
            return orig_str, None, None
        start_line = lines[0]
        headers = lines[1:]
        headers_str = "\r\n".join(headers)
        new_headers = self.perform_replace(headers_str, match_str, repl_str, use_regex, ignore_case)
        new_head = start_line
        if new_headers != "":
            new_head = new_head + "\r\n" + new_headers
        new_full = new_head + "\r\n\r\n" + body
        # headers region start and end
        headers_start = len(start_line) + 2  # after start-line + CRLF
        headers_end = headers_start + len(new_headers)
        return new_full, headers_start, headers_end

    def replace_in_url(self, orig_bytes, match_str, repl_str, use_regex, ignore_case):
        # Use analyzeRequest to get the URL and reconstruct start-line
        try:
            analyzed = self.helpers.analyzeRequest(self._controller.getHttpService(), orig_bytes)
            url_obj = analyzed.getUrl()
            # get components
            protocol = url_obj.getProtocol()  # "http" or "https" as string? In some Jython/Java versions it's string
            # We'll parse start-line by hand to ensure compatibility
            orig_str = self.helpers.bytesToString(orig_bytes)
            lines = orig_str.split("\r\n")
            if not lines:
                return orig_bytes, None, None
            start_line = lines[0]
            # start_line format: METHOD SP path SP HTTP/version
            parts = start_line.split(" ")
            if len(parts) < 3:
                return orig_bytes, None, None
            method = parts[0]
            path = parts[1]
            version = " ".join(parts[2:])  # HTTP/1.1
            # Replace inside path only
            new_path = path
            if use_regex:
                flags = re.IGNORECASE if ignore_case else 0
                new_path = re.sub(match_str, repl_str, path, flags=flags)
            else:
                if ignore_case:
                    # naive case-insensitive replace: find occurrences ignoring case
                    pattern = re.compile(re.escape(match_str), re.IGNORECASE)
                    new_path = pattern.sub(repl_str, path)
                else:
                    new_path = path.replace(match_str, repl_str)
            # rebuild start-line
            new_start_line = "%s %s %s" % (method, new_path, version)
            # rebuild whole request
            rest = "\r\n".join(lines[1:])
            new_full = new_start_line + "\r\n" + rest
            # the URL region is within start-line between method+space and space+version
            url_region_start = len(method) + 1
            url_region_end = url_region_start + len(new_path)
            return self.helpers.stringToBytes(new_full), url_region_start, url_region_end
        except Exception:
            # fallback: do nothing
            return orig_bytes, None, None

    def perform_replace(self, input_text, match_str, repl_str, use_regex, ignore_case):
        if use_regex:
            try:
                flags = re.IGNORECASE if ignore_case else 0
                return re.sub(match_str, repl_str, input_text, flags=flags)
            except re.error:
                # invalid regex -> show message and do no change
                JOptionPane.showMessageDialog(None, "Invalid regular expression.", "Regex error", JOptionPane.ERROR_MESSAGE)
                return input_text
        else:
            if ignore_case:
                # case-insensitive simple replace
                pattern = re.compile(re.escape(match_str), re.IGNORECASE)
                return pattern.sub(repl_str, input_text)
            else:
                return input_text.replace(match_str, repl_str)

    # Custom logic
    def do_replace(self, event):
        try:
            match_str = self._txtMatch.getText()
            repl_str = self._txtReplace.getText()
            use_regex = self._chkRegex.isSelected()
            ignore_case = self._chkIcase.isSelected()
            scope = self._cmbScope.getSelectedItem()

            if match_str is None or match_str == "":
                JOptionPane.showMessageDialog(None, "Please enter a Match string.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return

            # Get current message bytes (latest)
            orig_bytes = self.getMessage()
            if orig_bytes is None:
                return
            orig_str = self.helpers.bytesToString(orig_bytes)

            # push current state to undo stack
            self.push_undo(orig_bytes)

            # Based on scope, compute new_full and selection region
            new_bytes = orig_bytes
            sel_start = None
            sel_end = None

            if scope == "Selection":
                sel_bounds = self._txtInput.getSelectionBounds()
                if sel_bounds is None:
                    JOptionPane.showMessageDialog(None, "No selection. Please select the region where you want replacements to occur.", "No selection", JOptionPane.INFORMATION_MESSAGE)
                    # pop the pushed state since nothing changed
                    if self._undo_stack and self._undo_stack[-1] == orig_bytes:
                        self._undo_stack.pop()
                    return
                start = sel_bounds[0]
                end = sel_bounds[1]
                if end <= start:
                    JOptionPane.showMessageDialog(None, "Empty selection. Please select a non-empty region.", "Empty selection", JOptionPane.INFORMATION_MESSAGE)
                    if self._undo_stack and self._undo_stack[-1] == orig_bytes:
                        self._undo_stack.pop()
                    return
                new_full, sel_start, sel_end = self.replace_in_selection(orig_str, match_str, repl_str, use_regex, ignore_case, start, end)
                new_bytes = self.helpers.stringToBytes(new_full)

            elif scope == "Body":
                new_full, sel_start, sel_end = self.replace_in_body(orig_str, match_str, repl_str, use_regex, ignore_case)
                new_bytes = self.helpers.stringToBytes(new_full)

            elif scope == "Headers":
                new_full, sel_start, sel_end = self.replace_in_headers(orig_str, match_str, repl_str, use_regex, ignore_case)
                new_bytes = self.helpers.stringToBytes(new_full)

            elif scope == "URL":
                new_bytes, sel_start, sel_end = self.replace_in_url(orig_bytes, match_str, repl_str, use_regex, ignore_case)
                # new_bytes already bytes

            elif scope == "Whole request":
                new_full = self.perform_replace(orig_str, match_str, repl_str, use_regex, ignore_case)
                new_bytes = self.helpers.stringToBytes(new_full)
                sel_start = 0
                sel_end = len(new_full)

            else:
                # fallback: do selection
                sel_bounds = self._txtInput.getSelectionBounds()
                if sel_bounds is None:
                    JOptionPane.showMessageDialog(None, "No selection. Please select the region where you want replacements to occur.", "No selection", JOptionPane.INFORMATION_MESSAGE)
                    if self._undo_stack and self._undo_stack[-1] == orig_bytes:
                        self._undo_stack.pop()
                    return
                start = sel_bounds[0]
                end = sel_bounds[1]
                new_full, sel_start, sel_end = self.replace_in_selection(orig_str, match_str, repl_str, use_regex, ignore_case, start, end)
                new_bytes = self.helpers.stringToBytes(new_full)

            # Update editor and internal state, mark modified so Burp syncs to Pretty
            self._txtInput.setMessage(new_bytes, self._isRequest)
            self._currentMessage = new_bytes
            self._modified = True

            # Try to restore selection if we have numeric region values
            try:
                if sel_start is not None and sel_end is not None:
                    editor_comp = self._txtInput.getComponent()
                    if hasattr(editor_comp, "setSelection"):
                        editor_comp.setSelection(int(sel_start), int(sel_end))
            except Exception:
                pass

        except Exception as ex:
            # On exception, try to rollback last pushed state to avoid orphaning history
            try:
                if self._undo_stack:
                    last = self._undo_stack.pop()
                    self._txtInput.setMessage(last, self._isRequest)
                    self._currentMessage = last
                self._modified = True
            except Exception:
                pass
            self.callbacks.printError("Error in do_replace: %s" % str(ex))
