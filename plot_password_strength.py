# plot_password_strength.py
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt

# اسم ملف البيانات (استخدم الملف الآمن الناتج من السكربت sanitize)
FILENAME = "password_check_results_sanitized.csv"

def load_dataframe(filename):
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        sys.exit(1)
    df = pd.read_csv(filename, dtype=str)  # اقرأ كل الأعمدة كنص لتجنب مشاكل الصيغ
    return df

def ensure_columns(df):
    required = ["Strength_Label"]
    for col in required:
        if col not in df.columns:
            print(f"Required column missing in CSV: {col}")
            print("CSV columns:", df.columns.tolist())
            sys.exit(1)

def plot_pie(df):
    counts = df['Strength_Label'].value_counts().reindex(["Strong","Medium","Weak"]).fillna(0)
    labels = counts.index.tolist()
    sizes = counts.values.tolist()

    # ألوان: Strong=green, Medium=yellow, Weak=red
    color_map = {"Strong":"#4CAF50", "Medium":"#FFD700", "Weak":"#FF4C4C"}
    colors = [color_map.get(l, "#CCCCCC") for l in labels]

    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140)
    plt.title("Password Strength Distribution")
    plt.tight_layout()
    plt.show()

def plot_bar_entropy(df):
    # نحول عمود Entropy لرقم إذا موجود
    if 'Entropy' in df.columns:
        df['Entropy'] = pd.to_numeric(df['Entropy'], errors='coerce')
        plt.figure(figsize=(8,5))
        # نرسم متوسط الـ entropy لكل فئة قوة
        grouped = df.groupby('Strength_Label')['Entropy'].mean().reindex(["Strong","Medium","Weak"])
        grouped.plot(kind='bar', color=["#4CAF50","#FFD700","#FF4C4C"])
        plt.ylabel("Average Entropy (bits)")
        plt.title("Average Shannon Entropy by Strength Label")
        plt.tight_layout()
        plt.show()
    else:
        print("Column 'Entropy' not found — skipping entropy chart.")

def main():
    df = load_dataframe(FILENAME)
    ensure_columns(df)

    # إذا الأعمدة محصورة بأسماء مختلفة، حاول نطبع الأعمدة للمستخدم
    print("CSV columns detected:", df.columns.tolist())

    # رسم مخطط دائري لنسب القيم
    plot_pie(df)

    # رسم مخطط عمودي لمتوسط الـ Entropy (اختياري)
    plot_bar_entropy(df)

    # حفظ نسخة من الرسم الدائري كصورة (اختياري)
    save_choice = input("Save pie chart as PNG? (y/n): ").strip().lower()
    if save_choice == "y":
        counts = df['Strength_Label'].value_counts().reindex(["Strong","Medium","Weak"]).fillna(0)
        color_map = {"Strong":"#4CAF50", "Medium":"#FFD700", "Weak":"#FF4C4C"}
        colors = [color_map.get(l, "#CCCCCC") for l in counts.index.tolist()]
        plt.figure(figsize=(6,6))
        plt.pie(counts.values.tolist(), labels=counts.index.tolist(), autopct='%1.1f%%', colors=colors, startangle=140)
        plt.title("Password Strength Distribution")
        out_name = "password_strength_pie.png"
        plt.tight_layout()
        plt.savefig(out_name)
        print(f"Saved pie chart to {out_name}")

if __name__ == "__main__":
    main()
