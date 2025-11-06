import streamlit as st
import pandas as pd
import numpy as np
import re
from io import StringIO

st.set_page_config(page_title="PII Detection & k-Anonymity Tool", layout="wide")

# -----------------------------------
# Helper functions
# -----------------------------------
PII_PATTERNS = {
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    'phone': re.compile(r'(\+?\d{1,3}[\s-]?)?(\(?\d{3}\)?[\s-]?)?[\d\s-]{6,12}\d'),
    'zip': re.compile(r'\b\d{5}(?:-\d{4})?\b'),
}

def looks_like_name(val):
    if pd.isna(val) or not isinstance(val, str):
        return False
    parts = val.strip().split()
    if len(parts) >= 2 and all(p[0].isupper() for p in parts if p):
        return True
    return False

def detect_pii(val):
    found = []
    if pd.isna(val): return found
    s = str(val)
    for t, p in PII_PATTERNS.items():
        if p.search(s): found.append(t)
    if looks_like_name(s): found.append('name')
    if re.search(r'\b(st|street|ave|road|rd|blvd)\b', s, re.I): found.append('address')
    if re.fullmatch(r'\d{1,3}', s):
        n = int(s)
        if 0 <= n <= 120: found.append('age')
    return list(set(found))

def classify_col(series):
    if pd.api.types.is_numeric_dtype(series): return "Structured"
    avg_len = series.astype(str).map(len).mean()
    uniq_frac = series.nunique() / len(series)
    return "Unstructured" if avg_len > 50 or uniq_frac > 0.8 else "Structured"

def compute_k(df, qis):
    grp = df.groupby(qis).size().reset_index(name='count')
    merged = df.merge(grp, on=qis, how='left')
    k = merged['count'].min()
    risk = (1 / merged['count']).mean()
    return int(k), float(risk), grp

def generalize(df, qis, target_k=3):
    df = df.copy()
    if 'age' in df.columns:
        df['age'] = df['age'].apply(lambda x: f"{int(x)//10*10}-{int(x)//10*10+9}" if pd.notna(x) and str(x).isdigit() else x)
    if 'zip_code' in df.columns:
        df['zip_code'] = df['zip_code'].astype(str).apply(lambda z: z[:3] + "***" if len(z) >= 3 else z)
    grp = df.groupby(qis).size().reset_index(name='count')
    merged = df.merge(grp, on=qis, how='left')
    small = merged[merged['count'] < target_k].index
    df = df.drop(small)
    return df

# -----------------------------------
# Streamlit UI
# -----------------------------------
st.title("🔐 PII Detection & k-Anonymity Analyzer")

st.write("""
Upload a CSV file to:
- Identify **PII elements**
- Classify columns (Structured / Unstructured)
- Apply **k-Anonymity** (generalization + suppression)
""")

uploaded = st.file_uploader("📂 Upload your CSV dataset", type=["csv"])

if uploaded:
    df = pd.read_csv(uploaded)
    st.subheader("📊 Preview of Uploaded Data")
    st.dataframe(df.head())

    # --- Part A: PII Detection ---
    st.subheader("🕵️ PII Detection Results")

    pii_cells = []
    for c in df.columns:
        for i, v in df[c].items():
            found = detect_pii(v)
            if found:
                pii_cells.append({"Row": i, "Column": c, "Detected PII": ", ".join(found), "Value": v})

    pii_df = pd.DataFrame(pii_cells)
    if not pii_df.empty:
        st.write("Detected PII elements:")
        st.dataframe(pii_df)
    else:
        st.success("No obvious PII detected by regex patterns!")

    # Column classification
    col_info = [{"Column": c, "Type": classify_col(df[c])} for c in df.columns]
    st.write("Column Classification:")
    st.dataframe(pd.DataFrame(col_info))

    # --- Part B: k-Anonymity ---
    st.subheader("🔒 k-Anonymity Analyzer")

    quasi_cols = st.multiselect(
        "Select quasi-identifiers (columns used for k-anonymity):",
        options=list(df.columns),
        default=[c for c in df.columns if c.lower() in ['age', 'gender', 'zip_code']]
    )
    k_val = st.slider("Choose target k value:", 2, 10, 3)

    if st.button("Apply k-Anonymity"):
        if not quasi_cols:
            st.warning("Please select at least one quasi-identifier.")
        else:
            # Before anonymization
            k_before, risk_before, grp_before = compute_k(df, quasi_cols)
            st.write(f"**Before Anonymization:** k = {k_before}, Re-ID Risk ≈ {risk_before:.4f}")

            # Apply generalization
            anon_df = generalize(df, quasi_cols, target_k=k_val)

            # After anonymization
            k_after, risk_after, grp_after = compute_k(anon_df, quasi_cols)
            st.write(f"**After Anonymization:** k = {k_after}, Re-ID Risk ≈ {risk_after:.4f}")

            # Show data
            st.write("Anonymized Data Preview:")
            st.dataframe(anon_df.head())

            # Download anonymized dataset
            csv = anon_df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Anonymized CSV", csv, "anonymized.csv", "text/csv")

else:
    st.info("Please upload a CSV file to get started.")
