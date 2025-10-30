import re
import hashlib
import requests
import math
import csv
import os
import random
import string
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for coloring terminal output
init(autoreset=True)

# === Local password strength checker ===
def check_local_strength(password):
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


# === Shannon Entropy (total) ===
def shannon_entropy(password):
    if not password:
        return 0
    probabilities = [float(password.count(c)) / len(password) for c in set(password)]
    entropy_per_char = -sum([p * math.log2(p) for p in probabilities])
    total_entropy = entropy_per_char * len(password)
    return round(total_entropy, 2)


# === Check password breach using Have I Been Pwned API ===
def check_pwned(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=10)
    except requests.RequestException as e:
        # network error
        return -1
    if res.status_code != 200:
        return -1
    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


# === Save results to CSV (store SHA1, not plaintext) ===
def save_result(password, score, label, pwned_count, entropy):
    """
    Save result to CSV, but store password as SHA1 (uppercase hex) and include timestamp.
    """
    filename = "password_check_results.csv"
    headers = ["Timestamp", "Password(SHA1)", "Local_Score", "Strength_Label", "Pwned_Count", "Entropy"]
    file_exists = os.path.exists(filename)

    sha1_pw = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow([now, sha1_pw, score, label, pwned_count, f"{entropy:.2f}"])

    print("\n✅ Result saved to password_check_results.csv (password stored as SHA1)")


# === Generate a strong random password ===
def generate_strong_password(length=14):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
    return password


# === Main ===
def main():
    print(f"{Fore.CYAN}>> Secure Password Checker & Generator <<{Style.RESET_ALL}\n")
    password = input("Enter your password to check its strength: ")
    # optional: avoid printing the raw password in shared/screenshotted output
    print("Your entered password is: ", password)

    # Local check
    local_score, label = check_local_strength(password)
    if label == "Strong":
        color = Fore.GREEN
    elif label == "Medium":
        color = Fore.YELLOW
    else:
        color = Fore.RED
    print(f"Local strength: {color}{label}{Style.RESET_ALL} ({local_score}/6)")

    # Entropy
    entropy = shannon_entropy(password)
    if entropy < 25:
        entropy_color = Fore.RED
        entropy_status = "Low"
    elif entropy < 40:
        entropy_color = Fore.YELLOW
        entropy_status = "Medium"
    else:
        entropy_color = Fore.GREEN
        entropy_status = "High"
    print(f"Shannon Entropy (total): {entropy_color}{entropy} bits ({entropy_status}){Style.RESET_ALL}")

    # Pwned check
    pwned_count = check_pwned(password)
    if pwned_count == -1:
        print(Fore.YELLOW + "Pwned check: Error connecting to HIBP API." + Style.RESET_ALL)
    elif pwned_count == 0:
        print(Fore.GREEN + "Pwned check: NOT found in breaches." + Style.RESET_ALL)
    else:
        print(Fore.RED + f"Pwned check: Found {pwned_count} times in known breaches!" + Style.RESET_ALL)

    # Advice
    print("\nAdvice:")
    if pwned_count > 0:
        print(f"- {Fore.RED}This password was seen {pwned_count} times in breaches. Do NOT use it.{Style.RESET_ALL}")
    else:
        print("- This password was NOT found in the known breach list (using HIBP).")

    if label == "Weak":
        print(Fore.RED + "- Weak: Change it immediately. Add length and variety." + Style.RESET_ALL)
    elif label == "Medium":
        print(Fore.YELLOW + "- Medium: Consider adding more length and at least one special character." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "- Strong: Good job — still avoid dictionary words and common patterns." + Style.RESET_ALL)

    if entropy < 25:
        print(Fore.RED + "- Entropy: Very Low – password is weak." + Style.RESET_ALL)
    elif entropy < 40:
        print(Fore.YELLOW + "- Entropy: Medium – could be stronger with more variety." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "- Entropy: High – password is strong and random." + Style.RESET_ALL)

    print("- Use a passphrase (3+ random words) or a reputable password manager to generate/store passwords.")
    print("- Never reuse passwords across important accounts.")

    save_result(password, local_score, label, pwned_count, entropy)

    # === Suggest new strong password if weak ===
    if label != "Strong" or pwned_count > 0:
        print(f"\n⚠️ {Fore.YELLOW}Your password is not fully secure.{Style.RESET_ALL}")
        choice = input("Would you like me to generate a strong random password for you? (y/n): ").strip().lower()
        if choice == "y":
            new_password = generate_strong_password()
            print(f"\n✅ Suggested Strong Password: {Fore.CYAN}{new_password}{Style.RESET_ALL}\n")
            print("💡 Tip: Save it securely using a password manager.")


if __name__ == "__main__":
    main()
