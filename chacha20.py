import struct

# --- Funciones Auxiliares ---
def rotate_left(x, n):
    """Rotación de bits a la izquierda (32 bits)"""
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def qr(a, b, c, d):
    """Quarter Round: Función fundamental de ChaCha20"""
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotate_left(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotate_left(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotate_left(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotate_left(b, 7)
    return a, b, c, d

def print_matrix(matrix, title):
    """Imprime la matriz de estado 4x4 en formato hexadecimal RFC"""
    print(f"\n--- {title} ---")
    for i in range(0, 16, 4):
        print(" ".join(f"{matrix[j]:08x}" for j in range(i, i+4)))

# --- Implementación principal ---
def chacha20_block(key, counter, nonce):
    """Genera un bloque de cifrado ChaCha20"""
    # Constantes "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    # Convertir clave (32 bytes) a 8 palabras de 32 bits (Little Endian)
    key_words = [struct.unpack('<I', key[i:i+4])[0] for i in range(0, 32, 4)]
    
    # Convertir nonce (12 bytes) a 3 palabras de 32 bits (Little Endian)
    nonce_words = [struct.unpack('<I', nonce[i:i+4])[0] for i in range(0, 12, 4)]
    
    # Estado inicial (16 palabras)
    initial_state = constants + key_words + [counter] + nonce_words
    state = list(initial_state)

    # 10 ciclos de 2 rondas cada uno (total 20 rondas)
    for i in range(10):
        # Rondas de columna (Odd)
        state[0], state[4], state[8], state[12] = qr(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = qr(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = qr(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = qr(state[3], state[7], state[11], state[15])
        # Rondas de diagonal (Even)
        state[0], state[5], state[10], state[15] = qr(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = qr(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = qr(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = qr(state[3], state[4], state[9], state[14])

    # Sumar estado inicial al estado final (Mod 2^32)
    return [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]

# --- EJECUCIÓN DE PRUEBAS PARA EL INFORME ---

# 1. Prueba de la función QR (Sección 2.1.1)
print("Prueba 1: Función QR (Sección 2.1.1)")
a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
a, b, c, d = qr(a, b, c, d)
print(f"Resultado QR: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
print("Esperado: e4e7f110 23456789 56789012 89012345")

# 2. Prueba RFC 7539 (Sección 2.3.2)
print("\nPrueba 2: Cifrado estándar (RFC 7539 - 2.3.2)")
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
nonce = bytes.fromhex("000000090000004a00000000")
counter = 1
result = chacha20_block(key, counter, nonce)
print_matrix(result, "Estado Final del Bloque (Prueba 2)")

# 3. Prueba cambio de Nonce
print("\nPrueba 3: Cambio de Nonce")
nonce_mod = bytes.fromhex("010000090000004a00000000")
result_nonce = chacha20_block(key, counter, nonce_mod)
print_matrix(result_nonce, "Estado Final con Nonce Modificado")

# 4. Prueba cambio de bit en Clave
print("\nPrueba 4: Cambio de bit en Clave")
key_mod = bytes.fromhex("010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
result_key = chacha20_block(key_mod, counter, nonce)
print_matrix(result_key, "Estado Final con Clave Modificada")

