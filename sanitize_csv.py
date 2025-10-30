# sanitize_csv.py
import csv
import hashlib
import re
import os
from datetime import datetime

INPUT = "password_check_results.csv"
OUTPUT = "password_check_results_sanitized.csv"

sha1_re = re.compile(r'^[A-Fa-f0-9]{40}$')

if not os.path.exists(INPUT):
    print("File not found:", INPUT)
    exit(1)

with open(INPUT, newline="", encoding="utf-8") as fin, open(OUTPUT, "w", newline="", encoding="utf-8") as fout:
    reader = csv.reader(fin)
    writer = csv.writer(fout)
    rows = list(reader)
    if not rows:
        print("Empty file.")
        exit(1)

    # assume first row is header if it contains non-hex in second column
    header = rows[0]
    # make sure header has at least 2 cols
    if len(header) >= 2 and not sha1_re.match(header[1]):
        # it's a header row; write new header ensuring Timestamp exists
        new_header = ["Timestamp", "Password(SHA1)", "Local_Score", "Strength_Label", "Pwned_Count", "Entropy"]
        writer.writerow(new_header)
        data_rows = rows[1:]
    else:
        # no header, write new header then treat all rows as data
        new_header = ["Timestamp", "Password(SHA1)", "Local_Score", "Strength_Label", "Pwned_Count", "Entropy"]
        writer.writerow(new_header)
        data_rows = rows

    for row in data_rows:
        # normalize row length
        while len(row) < 6:
            row.append("")
        # If second column is SHA1 already, keep; else hash it
        possible_pw = row[1].strip()
        if sha1_re.match(possible_pw):
            sha1_pw = possible_pw.upper()
        else:
            # if row[0] looks like timestamp and row[1] is plaintext pw (common case),
            # otherwise if row has plaintext in first col, try that.
            plaintext_candidate = possible_pw
            # if possible_pw empty and row[0] is not timestamp, maybe plaintext stored in first col
            if not plaintext_candidate or re.match(r'^\d{4}-\d{2}-\d{2} ', plaintext_candidate) is None and len(row[0]) > 0 and not sha1_re.match(row[0]):
                # if first column seems like plaintext password (no timestamp), use it
                plaintext_candidate = row[0]
            # fallback: use plaintext_candidate as-is
            sha1_pw = hashlib.sha1(plaintext_candidate.encode('utf-8')).hexdigest().upper()

        # build output row: if original had timestamp use it, else add current timestamp
        timestamp = row[0] if re.match(r'^\d{4}-\d{2}-\d{2} ', row[0]) else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        local_score = row[2] if len(row) > 2 else ""
        label = row[3] if len(row) > 3 else ""
        pwned = row[4] if len(row) > 4 else ""
        entropy = row[5] if len(row) > 5 else ""
        writer.writerow([timestamp, sha1_pw, local_score, label, pwned, entropy])

print("Sanitized file written to:", OUTPUT)
print("If OK, you can replace original file with the sanitized one (keep backup).")
