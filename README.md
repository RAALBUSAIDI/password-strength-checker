# password-strength-checker
A Python GUI tool to check password strength, entropy, and data breaches using Have I Been Pwned API.
# 🔒 Password Strength Checker

A Python GUI tool built with **Tkinter** that evaluates password strength using:
- Local rule-based analysis (uppercase, lowercase, digits, symbols)
- **Shannon Entropy** for randomness estimation
- **Have I Been Pwned API** check for known data breaches
- Generates strong passwords
- Saves results securely in CSV (passwords stored as SHA1 hashes)

---

## 🚀 Features
✅ Modern Tkinter UI  
✅ Generates strong passwords  
✅ Detects breached passwords using the HIBP API  
✅ Calculates password entropy  
✅ Saves SHA1 hash + analysis in CSV  
✅ Copy password to clipboard  

---

## 🧰 Technologies
- Python 3
- Tkinter (GUI)
- Requests
- CSV, hashlib, re, math

---
## 💻 How to Run

1. **Install dependencies** (make sure Python 3.10+ is installed):
   ```bash
   pip install -r requirements.txt
---
 ## 💻 How to Run the app  
  python password_checker_gui.py
