import streamlit as st
import pandas as pd
import string
import math
import ciphers
import altair as alt

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

LETTERS = list(string.ascii_uppercase)

# ------- helper functions -------
def counts_to_percent(counts):
    total = sum(counts.values()) or 1
    return {k: (v / total) * 100 for k, v in counts.items()}

def get_letter_counts_from_text(text):
    text = (text or "").upper()
    counts = {ch: 0 for ch in LETTERS}
    for ch in text:
        if ch in counts:
            counts[ch] += 1
    return counts

def coprimes_with_26():
    return [a for a in range(1, 26) if math.gcd(a, 26) == 1]

# ------- Layout: Tabs for separation -------
tab_cipher, tab_analysis, tab_block = st.tabs(["Cipher Schemes", "Cryptoanalysis", "Block Ciphers"])

# ----------------- Cipher Schemes Tab -----------------
with tab_cipher:
    st.header("Cipher Schemes")
    col1, col2 = st.columns([2, 1])
    with col1:
        algorithm = st.selectbox("Choose cipher", ["Caesar", "ROT13", "Affine", "Rail Fence", "Columnar"])
        input_text = st.text_area("Input text (plaintext or ciphertext)", height=180)
    with col2:
        st.markdown("### Parameters")
        if algorithm == "Caesar":
            shift = st.number_input("Shift", value=3, step=1)
        elif algorithm == "Affine":
            a = st.number_input("a (must be coprime with 26)", value=5, step=1)
            b = st.number_input("b", value=8, step=1)
        elif algorithm == "Rail Fence":
            rails = st.number_input("Rails (key)", value=2, min_value=2, step=1)
        elif algorithm == "Columnar":
            col_key = st.text_input("Key (columnar)", value="HACK")

        operation = st.radio("Operation", ["Encrypt", "Decrypt"])

        if st.button("Run"):
            if algorithm == "Caesar":
                func = ciphers.caesar_encrypt if operation == "Encrypt" else ciphers.caesar_decrypt
                result = func(input_text, shift)
            elif algorithm == "ROT13":
                result = ciphers.rot13(input_text)
            elif algorithm == "Affine":
                func = ciphers.affine_encrypt if operation == "Encrypt" else ciphers.affine_decrypt
                result = func(input_text, a, b)
            elif algorithm == "Rail Fence":
                func = ciphers.rail_fence_encrypt if operation == "Encrypt" else ciphers.rail_fence_decrypt
                result = func(input_text, rails)
            elif algorithm == "Columnar":
                func = ciphers.columnar_encrypt if operation == "Encrypt" else ciphers.columnar_decrypt
                result = func(input_text, col_key)
            else:
                result = "Unsupported option."

            st.subheader("Result")
            st.code(result)

# ----------------- Cryptoanalysis Tab -----------------
with tab_analysis:
    st.header("Cryptoanalysis Techniques")
    fa_tab, bf_tab = st.tabs(["Frequency Analysis", "Brute-force / Exhaustive Search"])

    with fa_tab:
        st.subheader("Frequency Analysis (with English benchmark)")
        fa_text = st.text_area("Enter ciphertext to analyze", height=200, key="fa_text")

        if st.button("Analyze Frequency", key="analyze_freq"):
            if not fa_text.strip():
                st.warning("Please enter some text to analyze.")
            else:
                counts = get_letter_counts_from_text(fa_text)
                perc = counts_to_percent(counts)
                df = pd.DataFrame({
                    "Letter": LETTERS,
                    "Count": [counts[ch] for ch in LETTERS],
                    "Ciphertext %": [perc[ch] for ch in LETTERS],
                    "English %": [ENGLISH_FREQ[ch] for ch in LETTERS]
                }).set_index("Letter")

                st.subheader("Frequency Table")
                st.dataframe(df, use_container_width=True)

                # --- prepare long-form DF for grouped bar chart
                letters = df.reset_index()['Letter'].tolist()
                df_long = df.reset_index().melt(
                    id_vars='Letter',
                    value_vars=['Ciphertext %', 'English %'],
                    var_name='Distribution',
                    value_name='Frequency'
                )

                # --- Grouped side-by-side bar chart
                chart = alt.Chart(df_long).mark_bar().encode(
                    x=alt.X('Letter:N', sort=letters, title='Letter'),
                    xOffset='Distribution:N',
                    y=alt.Y('Frequency:Q', title='Frequency (%)'),
                    color=alt.Color('Distribution:N',
                                    scale=alt.Scale(domain=['Ciphertext %','English %'],
                                                    range=['#1f77b4','#ff7f0e'])),
                    tooltip=['Letter','Distribution', alt.Tooltip('Frequency:Q', format='.2f')]
                ).properties(width=800, height=360)

                st.subheader("Distribution Comparison")
                st.altair_chart(chart, use_container_width=True)

                # --- Normalized frequency vector
                st.subheader("Normalized Frequencies (F(p))")
                total_letters = df['Count'].sum() or 1
                st.write(f"Total alphabetic letters counted = {total_letters}")
                F_table = pd.DataFrame({
                    'Letter': df.index,
                    'Count': df['Count'].values,
                    'F(p) %': df['Ciphertext %'].values
                }).set_index('Letter')
                st.dataframe(F_table, use_container_width=True)

    # Brute-force Affine/Caesar left as-is
    with bf_tab:
        st.subheader("Brute-force & Exhaustive Key Search Simulations")
        st.info("This section is unchanged — only Frequency Analysis plotting updated.")

# ----------------- Block Ciphers Tab -----------------
with tab_block:
    st.header("Modern Block Ciphers (DES Simulation)")

    des_text = st.text_input("Enter plaintext (e.g., A):", value="A")
    key = st.text_input("Key (8 characters)", value="12345678", max_chars=8)

    if st.button("Run DES Simulation"):
        from ciphers import des_simulate
        steps = des_simulate(des_text, key)

        for step, value in steps.items():
            st.subheader(step)
            st.write(value)

# ----------------- Footer -----------------
st.markdown("---")
st.markdown("**Tips:** Classical = old ciphers, Cryptoanalysis = attacks, Block Ciphers = modern algorithms like DES (insecure in practice, but good for teaching).")
