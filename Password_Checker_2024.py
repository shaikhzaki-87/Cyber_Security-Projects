"""
Shaikh Zaki | 2024
Password Strength Checker Tool
This is a simple password strength checker that evaluates the strength of a password based on length,
 character variety, and common patterns. It provides feedback to help users create stronger passwords.
"""

import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength_gui():
    password = entry.get()
    score = 0

    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[@$!%*?&]", password):
        score += 1

    if score <= 2:
        result = "Weak"
        color = "red"
    elif score <= 4:
        result = "Moderate"
        color = "orange"
    else:
        result = "Strong"
        color = "green"

    result_label.config(text=f"Password is: {result}", fg=color)

# GUI Setup
root = tk.Tk()
root.title("🔒 Password Strength Checker")
root.geometry("400x250")
root.configure(bg="#f0f0f0")

tk.Label(root, text="Enter Your Password", font=("Helvetica", 14), bg="#f0f0f0").pack(pady=(20, 5))
entry = tk.Entry(root, show="*", font=("Arial", 12), width=30)
entry.pack(pady=5)

tk.Button(root, text="Check Strength", font=("Arial", 12), command=check_password_strength_gui, bg="#007acc", fg="white", padx=10, pady=5).pack(pady=10)

result_label = tk.Label(root, text="", font=("Helvetica", 14), bg="#f0f0f0")
result_label.pack(pady=10)

root.mainloop()
