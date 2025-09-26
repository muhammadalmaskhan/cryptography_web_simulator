import streamlit as st
import ciphers

st.title("🔐 Cryptography Simulator")
st.markdown("**Developed by Muhammad Almas (for educational simulation purposes only)**")

algorithms = ["Caesar", "ROT13", "Affine", "Rail Fence", "Columnar"]
choice = st.selectbox("Select an Algorithm", algorithms)

text = st.text_area("Enter your text (plaintext or ciphertext):")
operation = st.radio("Operation", ["Encrypt", "Decrypt"])

if choice == "Caesar":
    shift = st.number_input("Shift", value=3, step=1)
    if st.button("Run"):
        if operation == "Encrypt":
            st.write(ciphers.caesar_encrypt(text, shift))
        else:
            st.write(ciphers.caesar_decrypt(text, shift))

elif choice == "ROT13":
    if st.button("Run"):
        st.write(ciphers.rot13(text))

elif choice == "Affine":
    a = st.number_input("a (must be coprime with 26)", value=5)
    b = st.number_input("b", value=8)
    if st.button("Run"):
        if operation == "Encrypt":
            st.write(ciphers.affine_encrypt(text, a, b))
        else:
            st.write(ciphers.affine_decrypt(text, a, b))

elif choice == "Rail Fence":
    key = st.number_input("Key (Rails)", value=2)
    if st.button("Run"):
        if operation == "Encrypt":
            st.write(ciphers.rail_fence_encrypt(text, key))
        else:
            st.write(ciphers.rail_fence_decrypt(text, key))

elif choice == "Columnar":
    key = st.text_input("Key", value="HACK")
    if st.button("Run"):
        if operation == "Encrypt":
            st.write(ciphers.columnar_encrypt(text, key))
        else:
            st.write(ciphers.columnar_decrypt(text, key))
