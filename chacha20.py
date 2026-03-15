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
def chacha20_block(key, counter, nonce, show_rounds=False):
    """Genera un bloque de cifrado ChaCha20"""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    key_words = [struct.unpack('<I', key[i:i+4])[0] for i in range(0, 32, 4)]
    nonce_words = [struct.unpack('<I', nonce[i:i+4])[0] for i in range(0, 12, 4)]
    
    initial_state = constants + key_words + [counter] + nonce_words
    state = list(initial_state)

    if show_rounds:
        print_matrix(state, "Estado Inicial")

    for i in range(10):
        # Odd round
        state[0], state[4], state[8], state[12] = qr(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = qr(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = qr(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = qr(state[3], state[7], state[11], state[15])
        if show_rounds:
            print_matrix(state, f"Ronda {i*2 + 1} (Columna)")

        # Even round
        state[0], state[5], state[10], state[15] = qr(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = qr(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = qr(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = qr(state[3], state[4], state[9], state[14])
        if show_rounds:
            print_matrix(state, f"Ronda {i*2 + 2} (Diagonal)")

    final_state = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]
    if show_rounds:
        print_matrix(final_state, "Estado Final del Bloque")
        
    return final_state

def serialize_block(block):
    """Convierte el bloque de 16 palabras de 32 bits a 64 bytes (Little Endian)"""
    return struct.pack('<16I', *block)

def chacha20_encrypt_decrypt(message, key, nonce, initial_counter=1, show_rounds=False):
    """Cifra o descifra un mensaje con ChaCha20"""
    # Padding a bloques de 512 bits (64 bytes)
    padded_len = (len(message) + 63) // 64 * 64
    padded_msg = message + bytes([0] * (padded_len - len(message)))
    
    ciphertext = bytearray()
    counter = initial_counter
    
    for i in range(0, len(padded_msg), 64):
        if show_rounds and i == 0:
            print(f"\nGenerando bloque de keystream para el bloque {i//64}")
            block = chacha20_block(key, counter, nonce, show_rounds=True)
        else:
            block = chacha20_block(key, counter, nonce, show_rounds=False)
            
        keystream = serialize_block(block)
        
        # XOR bit a bit (byte a byte)
        for j in range(64):
            if i + j < len(padded_msg):
                ciphertext.append(padded_msg[i+j] ^ keystream[j])
        
        counter += 1
        
    return bytes(ciphertext), counter, padded_msg

# --- EJECUCIÓN DE PRUEBAS PARA EL INFORME ---
if __name__ == "__main__":
    print("=======================================")
    print("PARTE 1: CHACHA20")
    print("=======================================")

    # 1. Prueba de la función QR
    print("\n[+] Prueba 1: Función QR (Sección 2.1.1)")
    a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
    print(f"Estado Inicial QR: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
    a, b, c, d = qr(a, b, c, d)
    print(f"Resultado QR: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
    print("Esperado:     a=ea2a92f4, b=cb1cf8ce, c=4581472e, d=5881c4bb")

    # 2. Prueba de cifrado
    print("\n[+] Prueba 2: Cifrar mensaje")
    msg1 = "Este mensaje de prueba será cifrado con ChaCha20, un algoritmo de flujo rápido y seguro que usa una clave de 256 bits ahora.".encode('utf-8')
    key1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce1 = bytes.fromhex("000000090000004a00000000")
    ct1, final_counter1, padded_msg1 = chacha20_encrypt_decrypt(msg1, key1, nonce1, initial_counter=1, show_rounds=True)
    print(f"\nClave: {key1.hex()}")
    print(f"Nonce Final: {nonce1.hex()} (Contador final: {final_counter1})")
    print(f"Texto Plano (hex): {padded_msg1.hex()}")
    print(f"Texto Cifrado (hex): {ct1.hex()}")

    # 3. Cambio de Nonce
    print("\n[+] Prueba 3: Cifrar mensaje (Cambio de Nonce)")
    nonce2 = bytes.fromhex("010000090000004a00000000")
    ct2, final_counter2, _ = chacha20_encrypt_decrypt(msg1, key1, nonce2, initial_counter=1, show_rounds=True)
    print(f"\nNonce Modificado: {nonce2.hex()}")
    print(f"Texto Cifrado (hex): {ct2.hex()}")

    # 4. Cambio de Clave
    print("\n[+] Prueba 4: Cifrar mensaje (Cambio de 1 bit en Clave)")
    key3 = bytes.fromhex("010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ct3, final_counter3, _ = chacha20_encrypt_decrypt(msg1, key3, nonce1, initial_counter=1, show_rounds=True)
    print(f"\nClave Modificada: {key3.hex()}")
    print(f"Texto Cifrado (hex): {ct3.hex()}")
    diff_bits = sum(bin(b1 ^ b3).count('1') for b1, b3 in zip(ct1, ct3))

    # 5. Cambio de Mensaje
    print("\n[+] Prueba 5: Cifrar mensaje (Cambio de 1 bit en Mensaje)")
    msg4 = "Este mensaje de prueba será cifrado con ChaCha21, un algoritmo de flujo rápido y seguro que usa una clave de 256 bits ahora.".encode('utf-8')
    ct4, final_counter4, padded_msg4 = chacha20_encrypt_decrypt(msg4, key1, nonce1, initial_counter=1, show_rounds=True)
    print(f"\nMensaje Modificado: {msg4}")
    print(f"Texto Cifrado (hex): {ct4.hex()}")
    diff_bits_msg = sum(bin(b1 ^ b4).count('1') for b1, b4 in zip(ct1, ct4))

    # 6. Descrifrar 
    # 6.1. El texto cifrado en formato hexadecimal
    ciphertext_hex = "55829381f1563c7b236eb77a834414e4b7a381a251a148706150693be3b70528a0e3002927fcc5673481bf649ae36390843ebca4b0362fd5acbff181d63d536e6eeda31155a2d521d8be6f119a42ddb9bd2fe3e7cf52688fca9f34ea6f0eea9b86018dfc34d9a7eade5702bc0c586fae69c4da45ef2155203a6ea5452da8af3b"
    # 6.2. Convertir el hexadecimal a bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    # 6.3. Las llaves y nonce usados en el punto 5 originales (key1 y nonce1)
    key1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce1 = bytes.fromhex("000000090000004a00000000")
    # 6.4. Usas chacha20_encrypt_decrypt pasando el CIPHERTEXT en lugar del mensaje plano
    mensaje_descifrado_bytes, _, _ = chacha20_encrypt_decrypt(
        message=ciphertext_bytes, 
        key=key1, 
        nonce=nonce1, 
        initial_counter=1
    )
    # 6.5. Como ChaCha20 en tu código añade un "padding" (rellenos de ceros) para múltiplos de 64 bytes, lo removemos
    mensaje_descifrado_limpio = mensaje_descifrado_bytes.rstrip(b'\x00')
    # 6.6. Imprimir el resultado decodificando de bytes a string (utf-8)
    print(mensaje_descifrado_limpio.decode('utf-8'))