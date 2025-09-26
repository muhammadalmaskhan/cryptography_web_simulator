import streamlit as st
import pandas as pd
import ciphers
from collections import Counter
import string

st.set_page_config(page_title="Cryptography Simulator", layout="wide")

st.title("🔐 Cryptography Simulator")
st.markdown("**Developed by Muhammad Almas (for educational simulation purposes only)**")

# English benchmark distribution (percentages)
ENGLISH_FREQ = {
    'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 13.0,
    'F': 2.2, 'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15,
    'K': 0.77, 'L': 4.0, 'M': 2.4, 'N': 6.7, 'O': 7.5,
    'P': 1.9, 'Q': 0.095,'R': 6.0, 'S': 6.3, 'T': 9.1,
    'U': 2.8, 'V': 0.98,'W': 2.4, 'X': 0.15,'Y': 2.0,
    'Z': 0.074
}

algorithms = ["Caesar", "ROT13", "Affine", "Rail Fence", "Columnar", "Frequency Analysis"]
choice = st.selectbox("Select an Algorithm", algorithms)

text = st.text_area("Enter your text (plaintext or ciphertext):")

# Frequency Analysis special block
if choice == "Frequency Analysis":
    st.markdown("### Frequency Analysis & English Benchmark")
    if st.button("Analyze"):
        if not text.strip():
            st.warning("Please enter some text for analysis.")
        else:
            # Get counts using the function from ciphers (counts by letter A-Z)
            freq_counts = ciphers.frequency_analysis(text)  # dict A-Z -> counts
            total = sum(freq_counts.values()) or 1

            # Compute percentage for ciphertext
            ciphertext_perc = {k: (v / total) * 100 for k, v in freq_counts.items()}

            # Prepare DataFrame
            letters = list(string.ascii_uppercase)
            df = pd.DataFrame({
                "Letter": letters,
                "Ciphertext %": [ciphertext_perc[ch] for ch in letters],
                "English %": [ENGLISH_FREQ[ch] for ch in letters]
            }).set_index("Letter")

            st.subheader("Letter Frequency (Ciphertext vs English)")
            st.dataframe(df, use_container_width=True)

            st.subheader("Distribution Comparison")
            st.line_chart(df)  # shows both series on same chart

            # Show raw counts as well (optional small table)
            counts_df = pd.DataFrame({
                "Letter": letters,
                "Count": [freq_counts[ch] for ch in letters]
            }).set_index("Letter")
            st.subheader("Raw Letter Counts")
            st.dataframe(counts_df, use_container_width=True)

            # Automatic Caesar key suggestion (most frequent letter -> 'E')
            most_common = max(freq_counts.items(), key=lambda x: (x[1], -ord(x[0])))[0] if total > 0 else None
            if most_common and freq_counts[most_common] > 0:
                # If ciphertext letter C maps to plaintext 'E', shift = C - 'E'
                suggested_shift = (ord(most_common) - ord('E')) % 26
                st.markdown(f"**Most frequent ciphertext letter:** `{most_common}`")
                st.markdown(f"**Suggested Caesar shift** (assuming `{most_common}` -> `E`): **{suggested_shift}**")

                if st.button("Apply Suggested Caesar Decryption"):
                    candidate = ciphers.caesar_decrypt(text, suggested_shift)
                    st.subheader("Decryption Using Suggested Shift")
                    st.code(candidate)
            else:
                st.info("No alphabetic characters found to suggest a Caesar key.")

# All other ciphers (shared flow, no duplication)
else:
    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if choice == "Caesar":
        shift = st.number_input("Shift", value=3, step=1)
        if st.button("Run"):
            func = ciphers.caesar_encrypt if operation == "Encrypt" else ciphers.caesar_decrypt
            st.subheader("Result")
            st.code(func(text, shift))

    elif choice == "ROT13":
        if st.button("Run"):
            st.subheader("Result")
            st.code(ciphers.rot13(text))

    elif choice == "Affine":
        a = st.number_input("a (must be coprime with 26)", value=5, step=1)
        b = st.number_input("b", value=8, step=1)
        if st.button("Run"):
            func = ciphers.affine_encrypt if operation == "Encrypt" else ciphers.affine_decrypt
            st.subheader("Result")
            st.code(func(text, a, b))

    elif choice == "Rail Fence":
        key = st.number_input("Key (Rails)", value=2, step=1, min_value=2)
        if st.button("Run"):
            func = ciphers.rail_fence_encrypt if operation == "Encrypt" else ciphers.rail_fence_decrypt
            st.subheader("Result")
            st.code(func(text, key))

    elif choice == "Columnar":
        key = st.text_input("Key", value="HACK")
        if st.button("Run"):
            func = ciphers.columnar_encrypt if operation == "Encrypt" else ciphers.columnar_decrypt
            st.subheader("Result")
            st.code(func(text, key))
