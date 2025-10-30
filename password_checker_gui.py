# password_checker_gui_with_copy.py
# GUI Password Checker & Generator مع زر نسخ للكليپبورد وتخزين SHA1 في CSV
import tkinter as tk
from tkinter import messagebox
import os
import csv
import hashlib
import re
import math
import requests
import random
import string
from datetime import datetime

# ---------------- Helper functions ----------------

def check_local_strength(password):
    """Return (score:int, label:str)"""
    score = 0
    rules = [
        (r".{8,}", "At least 8 characters long"),
        (r"[A-Z]", "Contains uppercase letter"),
        (r"[a-z]", "Contains lowercase letter"),
        (r"[0-9]", "Contains a digit"),
        (r"[^A-Za-z0-9]", "Contains special character"),
        (r"\s", "No spaces allowed"),
    ]
    for pattern, _ in rules:
        if re.search(pattern, password):
            score += 1
    if len(password) > 12:
        score += 1
    label = "Weak" if score <= 3 else "Medium" if score == 4 else "Strong"
    return score, label

def shannon_entropy(password):
    """Return total Shannon entropy (bits)"""
    if not password:
        return 0.0
    counts = {}
    length = len(password)
    for c in password:
        counts[c] = counts.get(c, 0) + 1
    entropy_per_char = -sum((cnt/length) * math.log2(cnt/length) for cnt in counts.values())
    total_entropy = entropy_per_char * length
    return round(total_entropy, 2)

def check_pwned(password):
    """
    Check Have I Been Pwned PwnedPasswords range API.
    Returns:
      -1 on error
       0 if not found
      >0 occurrences found
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url, timeout=10)
        if res.status_code != 200:
            return -1
        for line in res.text.splitlines():
            parts = line.split(':')
            if len(parts) != 2:
                continue
            if parts[0].strip() == suffix:
                try:
                    return int(parts[1].strip())
                except:
                    return 0
        return 0
    except requests.RequestException:
        return -1

def save_result_sha1(password, score, label, pwned_count, entropy, filename="password_check_results.csv"):
    """
    Save result to CSV but store password as SHA1 (uppercase hex) and include timestamp.
    Columns: Timestamp, Password(SHA1), Local_Score, Strength_Label, Pwned_Count, Entropy
    """
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    headers = ["Timestamp", "Password(SHA1)", "Local_Score", "Strength_Label", "Pwned_Count", "Entropy"]
    file_exists = os.path.exists(filename)
    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow([now, sha1_pw, score, label, pwned_count, f"{entropy:.2f}"])

def generate_strong_password(length=16):
    """Generate a strong password ensuring at least one upper, lower, digit and symbol."""
    rng = random.SystemRandom()
    # required chars
    parts = [
        rng.choice(string.ascii_uppercase),
        rng.choice(string.ascii_lowercase),
        rng.choice(string.digits),
        rng.choice("!@#$%^&*()-_=+[]{};:,.<>?/\\|")
    ]
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
    parts += [rng.choice(all_chars) for _ in range(max(0, length - len(parts)))]
    rng.shuffle(parts)
    return ''.join(parts)

# ---------------- GUI ----------------

class PasswordCheckerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔒 Password Checker & Generator")
        self.geometry("700x520")
        self.configure(bg="#1f1f2e")
        self.resizable(False, False)

        # Title
        tk.Label(self, text="Secure Password Checker & Generator", font=("Segoe UI", 18, "bold"),
                 fg="#f8f8f2", bg="#1f1f2e").pack(pady=(12,6))

        # Input frame
        input_frame = tk.Frame(self, bg="#2e2e44", bd=0)
        input_frame.pack(padx=18, pady=8, fill="x")

        tk.Label(input_frame, text="Enter password:", fg="#f8f8f2", bg="#2e2e44",
                 font=("Segoe UI", 11)).pack(anchor="w", padx=8, pady=(6,0))

        entry_row = tk.Frame(input_frame, bg="#2e2e44")
        entry_row.pack(fill="x", padx=8, pady=6)

        self.pw_var = tk.StringVar()
        self.entry = tk.Entry(entry_row, textvariable=self.pw_var, show="*", font=("Segoe UI", 12), width=40,
                              relief="flat", bg="#f6f6f7")
        self.entry.pack(side="left", padx=(0,8))

        # Show checkbox
        self.show_var = tk.BooleanVar(value=False)
        self.show_chk = tk.Checkbutton(entry_row, text="Show", variable=self.show_var, command=self.toggle_show,
                                       bg="#2e2e44", fg="#f8f8f2", selectcolor="#2e2e44")
        self.show_chk.pack(side="left")

        # Buttons row
        btn_frame = tk.Frame(input_frame, bg="#2e2e44")
        btn_frame.pack(fill="x", padx=8, pady=(0,8))

        self.check_btn = tk.Button(btn_frame, text="Check Password", bg="#6272a4", fg="#fff", font=("Segoe UI", 11),
                                   width=16, command=self.on_check)
        self.check_btn.pack(side="left", padx=6, pady=6)

        self.generate_btn = tk.Button(btn_frame, text="Generate Strong Password", bg="#50fa7b", fg="#111",
                                      font=("Segoe UI", 11), width=22, command=self.on_generate)
        self.generate_btn.pack(side="left", padx=6)

        self.copy_btn = tk.Button(btn_frame, text="Copy Password", bg="#8be9fd", fg="#111", font=("Segoe UI", 11),
                                  width=14, command=self.copy_to_clipboard)
        self.copy_btn.pack(side="left", padx=6)

        self.open_csv_btn = tk.Button(btn_frame, text="Open CSV Results", bg="#ffb86c", fg="#111",
                                      font=("Segoe UI", 11), width=16, command=self.open_csv)
        self.open_csv_btn.pack(side="left", padx=6)

        # Results frame
        results_frame = tk.Frame(self, bg="#282a36")
        results_frame.pack(padx=18, pady=(6,12), fill="both", expand=True)

        # Local strength label
        self.strength_label = tk.Label(results_frame, text="Local strength: -", font=("Segoe UI", 12),
                                       bg="#282a36", fg="#f8f8f2", anchor="w")
        self.strength_label.pack(fill="x", padx=8, pady=(8,4))

        # Entropy label
        self.entropy_label = tk.Label(results_frame, text="Shannon Entropy (total): -", font=("Segoe UI", 12),
                                      bg="#282a36", fg="#f8f8f2", anchor="w")
        self.entropy_label.pack(fill="x", padx=8, pady=4)

        # Pwned label
        self.pwned_label = tk.Label(results_frame, text="Pwned check: -", font=("Segoe UI", 12),
                                    bg="#282a36", fg="#f8f8f2", anchor="w")
        self.pwned_label.pack(fill="x", padx=8, pady=4)

        # Advice text box (read-only behavior)
        tk.Label(results_frame, text="Advice:", font=("Segoe UI", 12, "bold"), bg="#282a36", fg="#f8f8f2").pack(anchor="w", padx=8, pady=(10,0))
        self.advice_box = tk.Text(results_frame, height=9, wrap="word", bg="#44475a", fg="#f8f8f2",
                                  font=("Segoe UI", 11), bd=0)
        self.advice_box.pack(fill="both", padx=8, pady=6, expand=True)
        self.advice_box.config(state=tk.DISABLED)

        # Status label
        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(self, textvariable=self.status_var, bg="#1f1f2e", fg="#f8f8f2", font=("Segoe UI", 10))
        self.status_label.pack(anchor="w", padx=18, pady=(0,8))

    # ---------------- Methods ----------------

    def toggle_show(self):
        if self.show_var.get():
            self.entry.config(show="")
        else:
            self.entry.config(show="*")

    def set_status(self, txt):
        self.status_var.set(txt)
        self.update_idletasks()

    def clear_advice(self):
        self.advice_box.config(state=tk.NORMAL)
        self.advice_box.delete("1.0", tk.END)
        self.advice_box.config(state=tk.DISABLED)

    def append_advice(self, line):
        self.advice_box.config(state=tk.NORMAL)
        self.advice_box.insert(tk.END, line + "\n")
        self.advice_box.config(state=tk.DISABLED)

    def copy_to_clipboard(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("Copy", "No password to copy.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(pw)
            messagebox.showinfo("Copied", "✅ Password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Clipboard error", f"Could not copy to clipboard:\n{e}")

    def on_generate(self):
        new_pw = generate_strong_password()
        self.pw_var.set(new_pw)
        # reveal generated password for easy copying (user can hide again)
        self.entry.config(show="")
        self.show_var.set(True)
        self.set_status("Generated a strong password (visible). You can copy it with 'Copy Password' button.")

    def on_check(self):
        pw = self.pw_var.get().strip()
        if not pw:
            messagebox.showwarning("Input required", "Please enter a password first.")
            return

        # disable buttons briefly
        self.check_btn.config(state=tk.DISABLED)
        self.generate_btn.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.DISABLED)
        self.set_status("Checking... (may take a few seconds if contacting HIBP)")

        # Local strength
        score, label = check_local_strength(pw)
        color_map = {"Strong":"#50fa7b", "Medium":"#ffd866", "Weak":"#ff6b6b"}
        color = color_map.get(label, "#f8f8f2")
        self.strength_label.config(text=f"Local strength: {label} ({score}/6)", fg=color)

        # Entropy
        entropy = shannon_entropy(pw)
        if entropy < 25:
            e_color = "#ff6b6b"; e_status = "Low"
        elif entropy < 40:
            e_color = "#ffd866"; e_status = "Medium"
        else:
            e_color = "#50fa7b"; e_status = "High"
        self.entropy_label.config(text=f"Shannon Entropy (total): {entropy} bits ({e_status})", fg=e_color)

        # Pwned check
        pwned = check_pwned(pw)
        if pwned == -1:
            self.pwned_label.config(text="Pwned check: Error connecting to HIBP API.", fg="#ffd866")
        elif pwned == 0:
            self.pwned_label.config(text="Pwned check: NOT found in breaches.", fg="#50fa7b")
        else:
            self.pwned_label.config(text=f"Pwned check: Found {pwned} times in known breaches!", fg="#ff6b6b")

        # Advice
        self.clear_advice()
        if pwned > 0:
            self.append_advice(f"⚠️ This password was seen {pwned} times in breaches. Do NOT use it.")
        else:
            self.append_advice("✅ This password was NOT found in known breach lists (HIBP).")

        if label == "Weak":
            self.append_advice("⚠️ Weak: Change it immediately. Add length and variety.")
        elif label == "Medium":
            self.append_advice("⚠️ Medium: Consider adding more length and at least one special character.")
        else:
            self.append_advice("✅ Strong: Good job — still avoid dictionary words and common patterns.")

        if entropy < 25:
            self.append_advice("⚠️ Entropy: Very Low – password is weak.")
        elif entropy < 40:
            self.append_advice("⚠️ Entropy: Medium – could be stronger with more variety.")
        else:
            self.append_advice("✅ Entropy: High – password is strong and random.")

        self.append_advice("💡 Use a passphrase (3+ random words) or a password manager to store passwords.")
        self.append_advice("💡 Never reuse passwords across important accounts.")

        # Save SHA1 result
        try:
            save_result_sha1(pw, score, label, pwned, entropy)
            self.set_status("Result saved to CSV (SHA1 stored).")
        except Exception as e:
            messagebox.showerror("Save error", f"Could not save result to CSV:\n{e}")
            self.set_status("Save failed.")

        # re-enable buttons
        self.check_btn.config(state=tk.NORMAL)
        self.generate_btn.config(state=tk.NORMAL)
        self.copy_btn.config(state=tk.NORMAL)

    def open_csv(self):
        filename = "password_check_results.csv"
        if os.path.exists(filename):
            try:
                os.startfile(filename)
            except Exception:
                messagebox.showinfo("Open file", f"Can't open file automatically.\nPath: {filename}")
        else:
            messagebox.showwarning("File not found", f"{filename} not found.")

# ---------------- Run ----------------

if __name__ == "__main__":
    app = PasswordCheckerGUI()
    app.mainloop()
