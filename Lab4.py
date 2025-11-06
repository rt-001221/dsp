import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Simple vulnerability patterns (extendable)
VULN_PATTERNS = {
    "Hardcoded Password": ["password =", "passwd =", "pwd =", "secret =", "api_key =", "token ="],
    "Use of eval": ["eval("],
    "SQL Injection Risk": ["SELECT * FROM", "INSERT INTO", "DELETE FROM", "UPDATE ", "exec(", "execute("],
    "Command Injection Risk": ["os.system(", "subprocess.call(", "subprocess.Popen("],
    "Weak Crypto": ["md5(", "sha1("],
    "Unvalidated Input": ["input(", "gets(", "scanf("],
    "Debug Code": ["print(", "console.log(", "System.out.println("],
    "Wildcard Import": ["import *", "#include <*"],
}

class VulnerabilityAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Analyzer Tool")
        master.geometry("900x600")

        ttk.Label(master, text="Vulnerability Analyzer Tool", font=("Segoe UI", 18, "bold")).pack(pady=10)
        ttk.Button(master, text="Select Source Code File", command=self.select_file).pack(pady=5)

        self.file_label = ttk.Label(master, text="No file selected.", font=("Segoe UI", 11))
        self.file_label.pack(pady=5)

        ttk.Button(master, text="Scan File", command=self.scan_file).pack(pady=5)

        self.result_box = tk.Text(master, font=("Consolas", 11), height=25, width=110)
        self.result_box.pack(padx=10, pady=10, fill="both", expand=True)

        ttk.Button(master, text="Export Report", command=self.export_report).pack(pady=5)

        self.filepath = None
        self.scan_results = []

    def select_file(self):
        self.filepath = filedialog.askopenfilename(title="Select Source Code File")
        if self.filepath:
            self.file_label.config(text=f"Selected: {self.filepath}")
        else:
            self.file_label.config(text="No file selected.")

    def scan_file(self):
        if not self.filepath:
            messagebox.showwarning("No File", "Please select a source code file first.")
            return
        self.result_box.delete(1.0, tk.END)
        self.scan_results.clear()
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for idx, line in enumerate(lines, 1):
                for vuln, patterns in VULN_PATTERNS.items():
                    for pat in patterns:
                        if pat in line:
                            result = f"Line {idx}: [{vuln}] {line.strip()}"
                            self.scan_results.append(result)
                            self.result_box.insert(tk.END, result + "\n")
            if not self.scan_results:
                self.result_box.insert(tk.END, "No common vulnerabilities or bad patterns found.\n")
            else:
                self.result_box.insert(tk.END, f"\nScan complete. {len(self.scan_results)} issues found.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan file:\n{e}")

    def export_report(self):
        if not self.scan_results:
            messagebox.showinfo("Export", "No results to export.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for line in self.scan_results:
                    f.write(line + "\n")
            messagebox.showinfo("Export", f"Report exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityAnalyzer(root)
    root.mainloop()