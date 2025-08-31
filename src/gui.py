import tkinter as tk
from tkinter import messagebox, scrolledtext
import os
import threading
from .core import ReportService
from .exceptions import ReportGenerationError, ToolNotFoundError, SubprocessFailedError

# === Theme Definitions ========================================================

THEMES = {
    "dark": {
        "bg": "#2E3440",
        "primary_frame_bg": "#3B4252",
        "secondary_frame_bg": "#4C566A",
        "text_color": "#E5E9F0",
        "heading_color": "#E5E9F0",
        "entry_bg": "#4C566A",
        "entry_fg": "#E5E9F0",
        "entry_insert": "#E5E9F0",
        "button_bg": "#88C0D0",
        "button_fg": "#2E3440",
        "button_hover": "#81A1C1",
        "listbox_bg": "#4C566A",
        "listbox_fg": "#E5E9F0",
        "listbox_select_bg": "#5E81AC",
        "listbox_select_fg": "#ECEFF4",
        "report_bg": "#2E3440",
        "report_fg": "#ECEFF4",
        "status_bg": "#3B4252",
        "status_fg": "#D8DEE9",
        "error_bg": "#BF616A",
        "error_fg": "#2E3440",
    },
    "light": {
        "bg": "#ECEFF4",
        "primary_frame_bg": "#D8DEE9",
        "secondary_frame_bg": "#E5E9F0",
        "text_color": "#4C566A",
        "heading_color": "#2E3440",
        "entry_bg": "#ECEFF4",
        "entry_fg": "#4C566A",
        "entry_insert": "#4C566A",
        "button_bg": "#81A1C1",
        "button_fg": "#ECEFF4",
        "button_hover": "#88C0D0",
        "listbox_bg": "#E5E9F0",
        "listbox_fg": "#4C566A",
        "listbox_select_bg": "#8FBCBB",
        "listbox_select_fg": "#2E3400",
        "report_bg": "#ECEFF4",
        "report_fg": "#2E3400",
        "status_bg": "#D8DEE9",
        "status_fg": "#4C566A",
        "error_bg": "#D08770",
        "error_fg": "#ECEFF4",
    },
}

# === GUI Application ==========================================================

class DomainAnalyzerGUI(tk.Tk):
    """A simple GUI for the Domain Analyzer tool."""
    def __init__(self, config):
        super().__init__()
        self.reports_dir = config.get("paths", {}).get("reports_dir", "reports")
        self.report_service = ReportService(config)
        self.analysis_thread = None
        self.cancel_event = threading.Event()
        self.current_theme = "dark"

        self.title("Domain Analyzer")
        self.geometry("1000x800")
        
        self.create_widgets()
        self.set_theme(self.current_theme)
        self.load_report_files()
        
        self.domain_entry.bind("<Return>", self.run_analysis_in_thread)
        self.report_text.bind("<Button-3>", self.show_context_menu)
        self.domain_entry.bind("<Button-3>", self.show_context_menu_for_entry)

    def create_widgets(self):
        """Creates all the GUI widgets."""
        self.main_frame = tk.Frame(self, padx=20, pady=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Top Section: Title, Input, and Controls
        self.top_frame = tk.Frame(self.main_frame)
        self.top_frame.pack(fill=tk.X)
        self.title_label = tk.Label(self.top_frame, text="Domain Security Analyzer", font=("Helvetica", 24, "bold"))
        self.title_label.pack(side=tk.LEFT, pady=(0, 20))

        self.button_frame = tk.Frame(self.top_frame)
        self.button_frame.pack(side=tk.RIGHT, pady=(0, 20))
        
        self.light_button = tk.Button(self.button_frame, text="Light", command=lambda: self.set_theme("light"), font=("Helvetica", 10), bd=0, relief="flat", padx=10, pady=5)
        self.light_button.pack(side=tk.LEFT, padx=(10, 5))
        self.dark_button = tk.Button(self.button_frame, text="Dark", command=lambda: self.set_theme("dark"), font=("Helvetica", 10), bd=0, relief="flat", padx=10, pady=5)
        self.dark_button.pack(side=tk.LEFT)

        self.input_frame = tk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=(0, 10))
        self.domain_label = tk.Label(self.input_frame, text="Enter Domain or IP:", font=("Helvetica", 12))
        self.domain_label.pack(side=tk.LEFT, padx=(0, 10))
        self.domain_entry = tk.Entry(self.input_frame, font=("Helvetica", 12), bd=0, relief="flat")
        self.domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.domain_entry.focus()

        self.run_button = tk.Button(self.button_frame, text="Analyze", command=self.run_analysis_in_thread, font=("Helvetica", 12, "bold"), bd=0, relief="flat", padx=15, pady=5)
        self.run_button.pack(side=tk.RIGHT, padx=(10, 0))

        # Main content area: Reports and Files
        self.content_frame = tk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        self.file_frame = tk.Frame(self.content_frame)
        self.file_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self.file_label = tk.Label(self.file_frame, text="Saved Reports", font=("Helvetica", 14))
        self.file_label.pack(pady=(0, 5))

        self.report_listbox = tk.Listbox(self.file_frame, font=("Courier", 10), bd=0, relief="flat", exportselection=False)
        self.report_listbox.bind("<<ListboxSelect>>", self.load_selected_report)
        self.report_listbox.pack(fill=tk.Y, expand=True)

        self.refresh_button = tk.Button(self.file_frame, text="Refresh", command=self.load_report_files, font=("Helvetica", 10), bd=1, relief="solid", padx=5, pady=2)
        self.refresh_button.pack(pady=(5, 0))

        self.report_display_frame = tk.Frame(self.content_frame)
        self.report_display_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.status_text = scrolledtext.ScrolledText(self.report_display_frame, height=5, font=("Helvetica", 10), bd=0, relief="flat")
        self.status_text.pack(fill=tk.X, pady=(0, 10))
        self.status_text.config(state=tk.DISABLED)

        self.report_text = scrolledtext.ScrolledText(self.report_display_frame, font=("Courier", 10), bd=0, relief="flat")
        self.report_text.pack(fill=tk.BOTH, expand=True)
        self.report_text.config(state=tk.DISABLED)

    def set_theme(self, theme_name):
        """Applies the selected theme to all widgets."""
        self.current_theme = theme_name
        colors = THEMES[theme_name]
        
        self.configure(bg=colors["bg"])
        self.main_frame.configure(bg=colors["primary_frame_bg"])
        
        self.report_listbox.configure(
            bg=colors["listbox_bg"],
            fg=colors["listbox_fg"],
            selectbackground=colors["listbox_select_bg"],
            selectforeground=colors["listbox_select_fg"],
        )
        self.report_text.configure(bg=colors["report_bg"], fg=colors["report_fg"])
        self.status_text.configure(bg=colors["status_bg"], fg=colors["status_fg"])

        for widget in [self.title_label, self.domain_label, self.file_label]:
            widget.configure(bg=colors["primary_frame_bg"], fg=colors["heading_color"])
        
        for widget in [self.domain_entry]:
            widget.configure(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_insert"])
        
        for widget in [self.run_button, self.refresh_button, self.light_button, self.dark_button]:
            widget.configure(bg=colors["button_bg"], fg=colors["button_fg"])
            
        for frame in [self.top_frame, self.file_frame, self.report_display_frame, self.input_frame, self.button_frame, self.content_frame]:
            frame.configure(bg=colors["primary_frame_bg"])
            
        # Bindings for hover effects
        self.run_button.bind("<Enter>", lambda e: self.run_button.config(bg=THEMES[self.current_theme]["button_hover"]))
        self.run_button.bind("<Leave>", lambda e: self.run_button.config(bg=THEMES[self.current_theme]["button_bg"]))
        self.refresh_button.bind("<Enter>", lambda e: self.refresh_button.config(bg=THEMES[self.current_theme]["listbox_select_bg"]))
        self.refresh_button.bind("<Leave>", lambda e: self.refresh_button.config(bg=THEMES[self.current_theme]["secondary_frame_bg"]))

    def show_context_menu(self, event):
        """Displays a right-click context menu for the report text area."""
        context_menu = tk.Menu(self, tearoff=0, bg=THEMES[self.current_theme]["secondary_frame_bg"], fg=THEMES[self.current_theme]["text_color"], activebackground=THEMES[self.current_theme]["listbox_select_bg"], activeforeground=THEMES[self.current_theme]["listbox_select_fg"])
        context_menu.add_command(label="Copy", command=self.copy_to_clipboard)
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def show_context_menu_for_entry(self, event):
        """Displays a right-click context menu for the entry widget."""
        context_menu = tk.Menu(self, tearoff=0, bg=THEMES[self.current_theme]["secondary_frame_bg"], fg=THEMES[self.current_theme]["text_color"], activebackground=THEMES[self.current_theme]["listbox_select_bg"], activeforeground=THEMES[self.current_theme]["listbox_select_fg"])
        context_menu.add_command(label="Paste", command=lambda: self.domain_entry.event_generate("<<Paste>>"))
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def copy_to_clipboard(self):
        """Copies the selected text from the report area to the clipboard."""
        try:
            selected_text = self.report_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def run_analysis_in_thread(self, event=None):
        """Starts the analysis in a separate thread or cancels it if running."""
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.cancel_event.set()
            self.run_button.config(text="Stopping...")
            self.log_status("Canceling analysis...")
            return

        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain or IP address.")
            return

        self.run_button.config(text="Cancel", bg="#BF616A", activebackground="#D08770")
        self.domain_entry.config(state=tk.DISABLED)
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        self.report_text.config(state=tk.DISABLED)
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.status_text.config(state=tk.DISABLED)
        self.cancel_event.clear()

        self.analysis_thread = threading.Thread(target=self.perform_analysis, args=(domain,), daemon=True)
        self.analysis_thread.start()

    def perform_analysis(self, domain):
        """The core analysis logic, run in a separate thread."""
        try:
            self.after(0, self.log_status, f"Starting security analysis for target: {domain}")
            
            # The heavy lifting is now in the service class
            report = self.report_service.generate_security_report(domain, self.cancel_event)
            
            if self.cancel_event.is_set():
                self.after(0, self.log_status, "Analysis canceled.")
                return

            self.after(0, self.log_status, "Report generated and saved.")
            self.after(0, self.display_report, report)
            self.after(0, self.load_report_files)
        except (ReportGenerationError, ToolNotFoundError, SubprocessFailedError) as e:
            self.after(0, self.show_custom_error, f"Error during analysis: {e}")
        except Exception as e:
            self.after(0, self.show_custom_error, f"An unexpected error occurred: {e}")
        finally:
            self.after(0, self._reset_ui)

    def _reset_ui(self):
        """Resets the UI elements to their initial state after analysis completes or is canceled."""
        self.run_button.config(text="Analyze", bg=THEMES[self.current_theme]["button_bg"], activebackground=THEMES[self.current_theme]["button_hover"])
        self.domain_entry.config(state=tk.NORMAL)
        self.domain_entry.delete(0, tk.END)
        self.cancel_event.clear()

    def show_custom_error(self, message):
        """Displays an error message in a custom, copyable window."""
        error_window = tk.Toplevel(self)
        error_window.title("Error")
        error_window.geometry("500x300")
        error_window.configure(bg="#2E3440")

        error_label = tk.Label(error_window, text="An error occurred:", font=("Helvetica", 14), bg="#2E3440", fg="#E5E9F0")
        error_label.pack(pady=(10, 5))

        error_text = scrolledtext.ScrolledText(error_window, font=("Courier", 10), bg="#4C566A", fg="#E5E9F0", bd=0, relief="flat", wrap=tk.WORD)
        error_text.insert(tk.END, message)
        error_text.config(state=tk.DISABLED)
        error_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        close_button = tk.Button(error_window, text="Close", command=error_window.destroy, font=("Helvetica", 10, "bold"), bg="#BF616A", fg="#2E3440", bd=0, relief="flat", padx=10, pady=5)
        close_button.pack(pady=10)
        close_button.bind("<Enter>", lambda e: e.widget.config(bg="#D08770"))
        close_button.bind("<Leave>", lambda e: e.widget.config(bg="#BF616A"))

    def log_status(self, message):
        """Appends a message to the status text area."""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)

    def display_report(self, report):
        """Displays the final report in the text area."""
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, report)
        self.report_text.config(state=tk.DISABLED)

    def load_report_files(self, event=None):
        """Loads and displays existing report files."""
        self.report_listbox.delete(0, tk.END)
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

        reports = [f for f in os.listdir(self.reports_dir) if f.endswith('_security_report.txt')]
        for report in sorted(reports):
            self.report_listbox.insert(tk.END, report)

    def load_selected_report(self, event):
        """Loads the content of the selected report file."""
        if not self.report_listbox.curselection():
            return
        
        selected_index = self.report_listbox.curselection()[0]
        filename = self.report_listbox.get(selected_index)
        
        try:
            file_path = os.path.join(self.reports_dir, filename)
            with open(file_path, "r") as f:
                report_content = f.read()
            self.display_report(report_content)
            self.log_status(f"Loaded report: {filename}")
        except Exception as e:
            self.show_custom_error(f"Could not read file: {e}")
