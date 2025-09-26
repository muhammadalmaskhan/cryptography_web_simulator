# ciphers.py
# Cryptography algorithms for simulation

# Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ROT13 (special Caesar shift of 13)
def rot13(text):
    return caesar_encrypt(text, 13)

# Affine Cipher
def affine_encrypt(text, a=5, b=8):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr(((a * (ord(ch) - base) + b) % 26) + base)
        else:
            result += ch
    return result

def affine_decrypt(cipher, a=5, b=8):
    result = ""
    m = 26
    # Modular inverse of a
    a_inv = pow(a, -1, m)
    for ch in cipher:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr(((a_inv * ((ord(ch) - base) - b)) % m) + base)
        else:
            result += ch
    return result

# Rail Fence Cipher
def rail_fence_encrypt(text, key=2):
    fence = [[] for _ in range(key)]
    rail, var = 0, 1
    for ch in text:
        fence[rail].append(ch)
        rail += var
        if rail == 0 or rail == key-1:
            var = -var
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(cipher, key=2):
    fence = [[''] * len(cipher) for _ in range(key)]
    rail, var = 0, 1
    index = list(range(len(cipher)))
    for _ in range(len(cipher)):
        fence[rail][index.pop(0)] = '*'
        rail += var
        if rail == 0 or rail == key-1:
            var = -var
    result, i = [''] * len(cipher), 0
    for r in range(key):
        for c in range(len(cipher)):
            if fence[r][c] == '*' and i < len(cipher):
                fence[r][c] = cipher[i]
                i += 1
    rail, var = 0, 1
    for c in range(len(cipher)):
        result[c] = fence[rail][c]
        rail += var
        if rail == 0 or rail == key-1:
            var = -var
    return ''.join(result)

# Columnar Cipher
def columnar_encrypt(text, key="HACK"):
    key_order = sorted(list(key))
    n_cols = len(key)
    n_rows = (len(text) + n_cols - 1) // n_cols
    padded = text.ljust(n_rows * n_cols)
    grid = [padded[i:i+n_cols] for i in range(0, len(padded), n_cols)]
    cipher = ''
    for k in key_order:
        col = key.index(k)
        cipher += ''.join(row[col] for row in grid)
    return cipher

def columnar_decrypt(cipher, key="HACK"):
    key_order = sorted(list(key))
    n_cols = len(key)
    n_rows = (len(cipher) + n_cols - 1) // n_cols
    grid = [[''] * n_cols for _ in range(n_rows)]
    col_len = n_rows
    idx = 0
    for k in key_order:
        col = key.index(k)
        for r in range(n_rows):
            if idx < len(cipher):
                grid[r][col] = cipher[idx]
                idx += 1
    return ''.join(''.join(row) for row in grid).strip()
