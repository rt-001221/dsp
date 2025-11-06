import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import csv

def check_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Medium"
    else:
        return "Weak"

def brute_force(password_hash, charset, max_length, progress_callback):
    import itertools
    for length in range(1, max_length+1):
        for idx, attempt in enumerate(itertools.product(charset, repeat=length)):
            attempt_pwd = ''.join(attempt)
            hashed = hashlib.sha256(attempt_pwd.encode()).hexdigest()
            progress_callback(idx)
            if hashed == password_hash:
                return attempt_pwd
    return None

class PasswordCrackerGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        master.title("Password Cracker Pro")
        master.state('zoomed')  # Full screen on Windows
        self.pack(fill="both", expand=True)
        self.results = {"Weak": [], "Medium": [], "Strong": []}

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Segoe UI", 12))
        style.configure("TLabel", font=("Segoe UI", 12))
        style.configure("TEntry", font=("Segoe UI", 12))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))

        # Header
        header = ttk.Label(self, text="Password Cracker Pro", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=(20,10), sticky="n")

        # Input Section
        input_frame = ttk.LabelFrame(self, text="Input")
        input_frame.grid(row=1, column=0, padx=30, pady=10, sticky="ew")
        input_frame.columnconfigure(1, weight=1)
        ttk.Label(input_frame, text="Plaintext or Hash:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.input_entry = ttk.Entry(input_frame, width=40)
        self.input_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Strength Checker Section
        strength_frame = ttk.LabelFrame(self, text="Password Strength Checker")
        strength_frame.grid(row=2, column=0, padx=30, pady=10, sticky="ew")
        ttk.Button(strength_frame, text="Check Strength", command=self.check_strength).grid(row=0, column=0, padx=10, pady=10)
        self.strength_label = ttk.Label(strength_frame, text="Strength: ")
        self.strength_label.grid(row=0, column=1, padx=10, pady=10)

        # Attack Section
        attack_frame = ttk.LabelFrame(self, text="Attack Simulation")
        attack_frame.grid(row=1, column=1, rowspan=2, padx=30, pady=10, sticky="nsew")
        attack_frame.columnconfigure(0, weight=1)
        attack_frame.columnconfigure(1, weight=1)
        ttk.Button(attack_frame, text="Dictionary Attack", command=self.dictionary_attack).grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        ttk.Button(attack_frame, text="Brute-force Attack", command=self.brute_force_attack).grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.progress = ttk.Progressbar(attack_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Export Section
        export_frame = ttk.LabelFrame(self, text="Export Results")
        export_frame.grid(row=3, column=0, columnspan=2, padx=30, pady=10, sticky="ew")
        ttk.Button(export_frame, text="Export as TXT", command=lambda: self.export_results('txt')).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(export_frame, text="Export as CSV", command=lambda: self.export_results('csv')).grid(row=0, column=1, padx=10, pady=10)

        # Results Display
        results_frame = ttk.LabelFrame(self, text="Results")
        results_frame.grid(row=1, column=2, rowspan=3, padx=30, pady=10, sticky="nsew")
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        self.result_box = tk.Text(results_frame, font=("Consolas", 12))
        self.result_box.grid(row=0, column=0, sticky="nsew")
        results_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.result_box.yview)
        results_scroll.grid(row=0, column=1, sticky="ns")
        self.result_box['yscrollcommand'] = results_scroll.set

        # Make grid cells expand
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        results_frame.grid_propagate(False)
        results_frame.config(width=500, height=500)

    def check_strength(self):
        pwd = self.input_entry.get()
        strength = check_strength(pwd)
        self.strength_label.config(text=f"Strength: {strength}")
        self.results[strength].append(pwd)
        self.result_box.insert(tk.END, f"Password: {pwd} | Strength: {strength}\n")

    def dictionary_attack(self):
        # Simulate dictionary attack (add your logic here)
        self.result_box.insert(tk.END, "Dictionary attack simulated.\n")

    def brute_force_attack(self):
        hash_input = self.input_entry.get()
        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
        max_length = 12  # Support longer passwords
        total_attempts = sum(len(charset)**i for i in range(1, max_length+1))
        self.progress["maximum"] = total_attempts

        def update_progress(idx):
            self.progress["value"] = idx
            self.update_idletasks()

        result = brute_force(hash_input, charset, max_length, update_progress)
        if result:
            self.result_box.insert(tk.END, f"Brute-force found: {result}\n")
        else:
            self.result_box.insert(tk.END, "Brute-force failed.\n")

    def export_results(self, filetype):
        filename = filedialog.asksaveasfilename(defaultextension=f".{filetype}")
        if not filename:
            return
        if filetype == 'txt':
            with open(filename, 'w') as f:
                for category, pwds in self.results.items():
                    f.write(f"{category}:\n")
                    for pwd in pwds:
                        f.write(f"  {pwd}\n")
        elif filetype == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Password'])
                for category, pwds in self.results.items():
                    for pwd in pwds:
                        writer.writerow([category, pwd])
        messagebox.showinfo("Export", f"Results exported to {filename}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackerGUI(root)
    root.mainloop()