import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib, time, itertools, string, csv, threading

# ---------- Password Strength Checker ----------
def check_strength(password):
    if len(password) < 6:
        return "Weak", "Your password is too short and easy to guess."
    elif any(c.isdigit() for c in password) and any(c.isalpha() for c in password):
        if len(password) >= 10 and any(c in string.punctuation for c in password):
            return "Strong", "Great! Your password is strong and safe."
        return "Medium", "Your password is okay, but can be improved."
    else:
        return "Weak", "Your password is too simple, easy to guess."

# ---------- Dictionary Attack ----------
def run_dictionary_attack():
    input_val = dict_input_entry.get().strip()
    input_type = input_type_var.get()
    algo = algo_var.get()
    wordlist = dict_wordlist_entry.get().strip()

    result_text.delete(1.0, tk.END)
    summary_label.config(text="", bg="white")

    try:
        with open(wordlist, "r", encoding="utf-8") as f:
            words = [w.strip() for w in f.readlines()]
    except:
        messagebox.showerror("Error", "Could not open wordlist file")
        return

    # determine target hash
    if input_type == "Word":
        target_hash = getattr(hashlib, algo)(input_val.encode()).hexdigest()
        result_text.insert(tk.END, f"Hashed input word '{input_val}' using {algo}: {target_hash}\n")
    else:
        target_hash = input_val

    tested = 0
    for word in words:
        hashed = getattr(hashlib, algo)(word.encode()).hexdigest()
        tested += 1
        if hashed == target_hash:
            result_text.insert(tk.END, f"✅ Found: {word}\n")
            summary_label.config(
                text=f"✅ Password FOUND → {word}",
                bg="green", fg="white", font=("Arial", 16, "bold")
            )
            return

    result_text.insert(tk.END, f"❌ Not Found. Tested {tested} words.\n")
    summary_label.config(
        text="❌ Password NOT FOUND in dictionary list",
        bg="red", fg="white", font=("Arial", 16, "bold")
    )

# ---------- Brute Force Simulation ----------
def run_bruteforce():
    target = brute_entry.get().strip()
    max_len = int(maxlen_spin.get())
    charset = string.ascii_letters + string.digits

    result_text.delete(1.0, tk.END)
    summary_label.config(text="", bg="white")

    def worker():
        start_time = time.time()
        attempts = 0
        found = False

        for length in range(1, max_len + 1):
            for guess in itertools.product(charset, repeat=length):
                attempts += 1
                guess_word = ''.join(guess)

                if attempts % 1000 == 0:
                    progress_var.set((attempts % 10000) / 100)  # smoother updates
                    root.update_idletasks()

                if guess_word == target:
                    elapsed = time.time() - start_time
                    result_text.insert(tk.END, f"✅ Brute-force success! Password: {guess_word}\n")
                    result_text.insert(tk.END, f"Attempts: {attempts}, Time: {elapsed:.2f}s\n")
                    summary_label.config(
                        text=f"✅ Brute Force SUCCESS → {guess_word}\nTime taken: {elapsed:.2f}s",
                        bg="green", fg="white", font=("Arial", 16, "bold")
                    )
                    found = True
                    return
            if found:
                break

        if not found:
            elapsed = time.time() - start_time
            result_text.insert(tk.END, f"❌ Failed to brute-force within length {max_len}\n")
            result_text.insert(tk.END, f"Attempts: {attempts}, Time: {elapsed:.2f}s\n")
            summary_label.config(
                text=f"❌ Brute Force FAILED (Max length {max_len})",
                bg="red", fg="white", font=("Arial", 16, "bold")
            )

    threading.Thread(target=worker, daemon=True).start()

# ---------- Strength Checker ----------
def check_password_strength():
    pwd = strength_entry.get().strip()
    result, msg = check_strength(pwd)

    colors = {"Weak": "red", "Medium": "orange", "Strong": "green"}
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"{msg}\n")

    summary_label.config(
        text=f"Password Strength: {result}",
        bg=colors[result], fg="white", font=("Arial", 16, "bold")
    )

# ---------- Export Results ----------
def export_results(filetype):
    content = result_text.get(1.0, tk.END).strip()
    if not content:
        messagebox.showinfo("No Data", "No results to export!")
        return

    filetypes = [("Text Files", "*.txt")] if filetype == "txt" else [("CSV Files", "*.csv")]
    filename = filedialog.asksaveasfilename(defaultextension=f".{filetype}", filetypes=filetypes)

    if not filename:
        return

    if filetype == "txt":
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    elif filetype == "csv":
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for line in content.split("\n"):
                writer.writerow([line])

    messagebox.showinfo("Exported", f"Results exported to {filename}")

# ---------- GUI ----------
root = tk.Tk()
root.title("Password Security Tool")
root.state("zoomed")  # full screen

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# ----- Strength Checker Tab -----
frame1 = ttk.Frame(notebook)
notebook.add(frame1, text="Password Strength Checker")

tk.Label(frame1, text="Enter Password:").pack(pady=5)
strength_entry = tk.Entry(frame1, width=40, font=("Arial", 14))
strength_entry.pack(pady=5)
tk.Button(frame1, text="Check Strength", command=check_password_strength).pack(pady=5)

# ----- Dictionary Attack Tab -----
frame2 = ttk.Frame(notebook)
notebook.add(frame2, text="Dictionary Attack")

tk.Label(frame2, text="Input Type:").pack(pady=5)
input_type_var = tk.StringVar(value="Hash")
ttk.Combobox(frame2, textvariable=input_type_var, values=["Word", "Hash"], width=10).pack(pady=5)

tk.Label(frame2, text="Enter Word/Hash:").pack(pady=5)
dict_input_entry = tk.Entry(frame2, width=60, font=("Arial", 14))
dict_input_entry.pack(pady=5)

tk.Label(frame2, text="Hash Algorithm:").pack(pady=5)
algo_var = tk.StringVar(value="md5")
ttk.Combobox(frame2, textvariable=algo_var, values=["md5", "sha1", "sha256"], width=10).pack(pady=5)

tk.Label(frame2, text="Wordlist File Path:").pack(pady=5)
dict_wordlist_entry = tk.Entry(frame2, width=60, font=("Arial", 14))
dict_wordlist_entry.pack(pady=5)
tk.Button(frame2, text="Run Dictionary Attack", command=run_dictionary_attack).pack(pady=5)

# ----- Brute Force Tab -----
frame3 = ttk.Frame(notebook)
notebook.add(frame3, text="Brute Force Simulation")

tk.Label(frame3, text="Enter Password to Crack:").pack(pady=5)
brute_entry = tk.Entry(frame3, width=40, font=("Arial", 14))
brute_entry.pack(pady=5)

tk.Label(frame3, text="Max Length:").pack(pady=5)
maxlen_spin = tk.Spinbox(frame3, from_=1, to=8, width=5)  # support longer passwords
maxlen_spin.pack(pady=5)

tk.Button(frame3, text="Run Brute Force", command=run_bruteforce).pack(pady=5)

progress_var = tk.DoubleVar()
progress = ttk.Progressbar(frame3, maximum=100, variable=progress_var)
progress.pack(pady=10, fill="x")

# ----- Results & Export (common) -----
result_frame = ttk.Frame(root)
result_frame.pack(fill="both", expand=True)

tk.Label(result_frame, text="Results:", font=("Arial", 12, "bold")).pack(anchor="w")
result_text = tk.Text(result_frame, height=12, font=("Consolas", 12))
result_text.pack(fill="both", expand=True, padx=10, pady=5)

summary_label = tk.Label(result_frame, text="", font=("Arial", 16), pady=10)
summary_label.pack(fill="x")

tk.Button(result_frame, text="Export as TXT", command=lambda: export_results("txt")).pack(side="left", padx=20, pady=10)
tk.Button(result_frame, text="Export as CSV", command=lambda: export_results("csv")).pack(side="left", padx=20, pady=10)

root.mainloop()
