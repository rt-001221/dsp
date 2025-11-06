import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from tkinter import Tk, ttk, StringVar, Entry, Button, Label

# --- Feature Extraction ---
def extract_features(url):
    features = []
    features.append(len(url))  # URL length
    features.append(1 if "@" in url else 0)  # Presence of '@'
    features.append(1 if url.startswith("https") else 0)  # Uses HTTPS
    features.append(1 if "-" in url else 0)  # Presence of '-'
    features.append(1 if re.search(r"\d", url) else 0)  # Contains digit
    features.append(1 if url.count('.') > 2 else 0)  # Multiple subdomains
    return features

# --- Load Dataset ---
# Dataset format: url,label (label: 1=phishing, 0=legitimate)
# Example row: http://example.com,0
df = pd.read_csv("phishing_dataset.csv")  # Place your dataset in the same folder

X = df['url'].apply(extract_features).tolist()
y = df['label']

# --- Train Model ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = LogisticRegression()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

# --- Simple GUI for Testing URLs ---
def predict_url():
    url = url_var.get()
    feats = [extract_features(url)]
    pred = model.predict(feats)[0]
    result = "Phishing" if pred == 1 else "Legitimate"
    result_var.set(f"Result: {result}")

root = Tk()
root.title("Phishing Website Detector")
root.geometry("400x200")

Label(root, text="Phishing Website Detector", font=("Segoe UI", 16, "bold")).pack(pady=10)
Label(root, text=f"Model Accuracy: {acc:.2f}").pack(pady=5)

url_var = StringVar()
Entry(root, textvariable=url_var, width=40).pack(pady=5)
Button(root, text="Check URL", command=predict_url).pack(pady=5)
result_var = StringVar()
Label(root, textvariable=result_var, font=("Segoe UI", 12)).pack(pady=10)

root.mainloop()