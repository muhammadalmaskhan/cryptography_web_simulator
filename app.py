import streamlit as st
import pandas as pd
import string
import math
import ciphers

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

# helper: letters
LETTERS = list(string.ascii_uppercase)

# ------- helper functions -------
def counts_to_percent(counts):
    total = sum(counts.values()) or 1
    return {k: (v / total) * 100 for k, v in counts.items()}

def chi_squared_score(observed_counts):
    """Chi-squared score: lower means closer to English distribution."""
    total = sum(observed_counts.values()) or 1
    score = 0.0
    for ch in LETTERS:
        obs = observed_counts.get(ch, 0)
        exp = total * (ENGLISH_FREQ[ch] / 100.0)
        # avoid division by zero: if exp is extremely small, add large penalty if obs differs
        if exp < 1e-6:
            if obs > 0:
                score += 1e6
            continue
        score += (obs - exp) ** 2 / exp
    return score

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
tab_cipher, tab_analysis = st.tabs(["Cipher Schemes", "Cryptoanalysis"])

# ----------------- Cipher Tools Tab -----------------
with tab_cipher:
    st.header("Cipher Tools")
    col1, col2 = st.columns([2, 1])
    with col1:
        algorithm = st.selectbox("Choose cipher", ["Caesar", "ROT13", "Affine", "Rail Fence", "Columnar"])
        input_text = st.text_area("Input text (plaintext or ciphertext)", height=180)
    with col2:
        st.markdown("### Parameters")
        # dynamic parameters
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
    # Sub-tabs for different analysis tools
    fa_tab, bf_tab = st.tabs(["Frequency Analysis", "Brute-force / Exhaustive Search"])

    # ---- Frequency Analysis ----
    with fa_tab:
        st.subheader("Frequency Analysis (with English benchmark)")
        fa_text = st.text_area("Enter ciphertext to analyze", height=200, key="fa_text")
        fa_cols = st.columns([2, 1])
        with fa_cols[1]:
            show_percent = st.checkbox("Show percentages", value=True)
            apply_suggested = st.checkbox("Show Caesar suggestion (most frequent -> E)", value=True)
            show_chart_type = st.selectbox("Chart type", ["Line", "Bar"])

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

                st.subheader("Distribution Comparison")
                if show_chart_type == "Line":
                    st.line_chart(df[["Ciphertext %", "English %"]])
                else:
                    st.bar_chart(df[["Ciphertext %", "English %"]])

                # Caesar suggestion
                if apply_suggested:
                    most_common = max(counts.items(), key=lambda x: (x[1], -ord(x[0])))[0] if sum(counts.values()) > 0 else None
                    if most_common and counts[most_common] > 0:
                        suggested_shift = (ord(most_common) - ord('E')) % 26
                        st.markdown(f"**Most frequent ciphertext letter:** `{most_common}`")
                        st.markdown(f"**Suggested Caesar shift** (assuming `{most_common}` -> `E`): **{suggested_shift}**")
                        if st.button("Apply suggested Caesar decryption", key="apply_sugg"):
                            dec = ciphers.caesar_decrypt(fa_text, suggested_shift)
                            st.subheader("Decrypted Candidate")
                            st.code(dec)
                    else:
                        st.info("No alphabetic characters found.")

    # ---- Brute-force / Exhaustive Search ----
    with bf_tab:
        st.subheader("Brute-force & Exhaustive Key Search Simulations")
        bf_text = st.text_area("Enter ciphertext to bruteforce", height=160, key="bf_text")
        st.markdown("Try exhaustive search for Caesar (all shifts) or Affine (all valid a, all b). Results are ranked by similarity to English (chi-squared).")
        bf_cols = st.columns([1, 1, 1])
        with bf_cols[0]:
            run_caesar = st.button("Bruteforce Caesar", key="bf_caesar")
        with bf_cols[1]:
            run_affine = st.button("Bruteforce Affine", key="bf_affine")
        with bf_cols[2]:
            top_n = st.number_input("Show top N candidates", value=10, min_value=1, step=1, key="topn")

        # Caesar brute-force
        if run_caesar:
            if not bf_text.strip():
                st.warning("Please enter ciphertext.")
            else:
                candidates = []
                for shift_try in range(26):
                    plain = ciphers.caesar_decrypt(bf_text, shift_try)
                    counts = get_letter_counts_from_text(plain)
                    score = chi_squared_score(counts)
                    candidates.append((shift_try, score, plain))
                # sort by score (ascending)
                candidates.sort(key=lambda x: x[1])
                st.subheader("Top Caesar Candidates (lower chi-sq better)")
                rows = []
                for shift_try, score, plain in candidates[:top_n]:
                    rows.append({"Shift": shift_try, "ChiSq": round(score, 2), "Plaintext (preview)": plain[:200]})
                st.table(pd.DataFrame(rows))

                # Let user pick one to apply
                choose_shift = st.number_input("Apply which shift? (enter shift value)", value=candidates[0][0], min_value=0, max_value=25, step=1, key="apply_shift")
                if st.button("Apply chosen shift", key="apply_shift_btn"):
                    decrypted = ciphers.caesar_decrypt(bf_text, int(choose_shift))
                    st.subheader("Decryption")
                    st.code(decrypted)

        # Affine brute-force
        if run_affine:
            if not bf_text.strip():
                st.warning("Please enter ciphertext.")
            else:
                candidates = []
                for a_try in coprimes_with_26():
                    for b_try in range(26):
                        try:
                            plain = ciphers.affine_decrypt(bf_text, a_try, b_try)
                            counts = get_letter_counts_from_text(plain)
                            score = chi_squared_score(counts)
                            candidates.append((a_try, b_try, score, plain))
                        except Exception:
                            # modular inverse error or other, skip
                            continue
                candidates.sort(key=lambda x: x[2])
                st.subheader("Top Affine Candidates (lower chi-sq better)")
                rows = []
                for a_try, b_try, score, plain in candidates[:top_n]:
                    rows.append({"a": a_try, "b": b_try, "ChiSq": round(score, 2), "Plaintext (preview)": plain[:200]})
                st.table(pd.DataFrame(rows))

                # Apply chosen (a,b)
                col_a, col_b = st.columns(2)
                with col_a:
                    apply_a = st.number_input("Apply a", value=candidates[0][0] if candidates else 1, min_value=1, max_value=25, step=1, key="apply_affine_a")
                with col_b:
                    apply_b = st.number_input("Apply b", value=candidates[0][1] if candidates else 0, min_value=0, max_value=25, step=1, key="apply_affine_b")
                if st.button("Apply chosen (a,b)", key="apply_affine_btn"):
                    try:
                        dec = ciphers.affine_decrypt(bf_text, int(apply_a), int(apply_b))
                        st.subheader("Decryption")
                        st.code(dec)
                    except Exception as e:
                        st.error(f"Could not decrypt with (a={apply_a}, b={apply_b}): {e}")

# ----------------- Footer / Tips -----------------
st.markdown("---")
st.markdown("**Tips:** Use Frequency Analysis to inspect letter distribution. Use Brute-force to generate candidate plaintexts , the chi-squared ranking often places likely English plaintexts near the top.")
