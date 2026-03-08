class LFSR:
    def __init__(self, seed, length, taps):
        self.state = seed
        self.length = length
        self.taps = taps

    def shift_byte(self):
        val = 0
        for _ in range(8):
            feedback = 0
            for t in self.taps:
                feedback ^= (self.state >> t) & 1
            out_bit = self.state & 1
            self.state = (self.state >> 1) | (feedback << (self.length - 1))
            val = (val << 1) | out_bit
        return val

def css_keystream(key_bytes, length):
    # Clave de 40 bits (5 bytes)
    key_int = int.from_bytes(key_bytes, byteorder='big')
    
    # 16 MSB para S1 (17 bits total con el bit más significativo en 1)
    seed1 = (key_int >> 24) & 0xFFFF
    seed1 = (1 << 16) | seed1
    
    # 24 LSB para S2 (25 bits total con el bit más significativo en 1)
    seed2 = key_int & 0xFFFFFF
    seed2 = (1 << 24) | seed2
    
    # S1 taps = {14, 0}, S2 taps = {12, 4, 3, 0}
    lfsr1 = LFSR(seed1, 17, [14, 0])
    lfsr2 = LFSR(seed2, 25, [12, 4, 3, 0])
    
    c = 0
    keystream = bytearray()
    
    for _ in range(length):
        x = lfsr1.shift_byte()
        y = lfsr2.shift_byte()
        z = x + y + c
        s = z % 256
        c = z // 256
        keystream.append(s)
        
    return keystream

def css_encrypt(msg_bytes, key_bytes):
    # Genera el keystream y hace un XOR con el mensaje
    ks = css_keystream(key_bytes, len(msg_bytes))
    return bytes([m ^ k for m, k in zip(msg_bytes, ks)]), ks

# --- PRUEBAS PARA EL INFORME ---
if __name__ == "__main__":
    print("=======================================")
    print("PARTE 2: CIFRADOR LFSR - CSS")
    print("=======================================")

    msg_str = "El algoritmo CSS fue diseñado para proteger el contenido de los DVD mediante un cifrado de flujo basado en registros de desplazamiento. Aunque su seguridad fue superada, sigue siendo un hito clave en la historia de la gestión de los derechos digitales."
    msg = msg_str.encode('utf-8')
    key1 = bytes.fromhex("1A2B3C4D5E")

    print("\n[+] Prueba 1: Cifrado Base")
    print(f"Mensaje Plano: {msg_str}")
    print(f"Clave (Hex): {key1.hex()}")

    ct1, ks1 = css_encrypt(msg, key1)
    print(f"\nKeystream (primeros 16 bytes): {ks1[:16].hex()}...")
    print(f"Texto Cifrado (Hex, primeros 32 bytes): {ct1[:32].hex()}...")

    print("\n[+] Prueba Avalancha 1: Cambio de 1 bit en la Clave")
    # Cambiamos LSB de la clave: 5E (01011110) a 5F (01011111)
    key2 = bytes.fromhex("1A2B3C4D5F")
    ct2, ks2 = css_encrypt(msg, key2)
    print(f"Clave Modificada (Hex): {key2.hex()}")
    
    diff_keys = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
    total_bits = len(msg) * 8
    print(f"Bits diferentes generados en Ciphertext (Avalancha Clave): {diff_keys} / {total_bits} ({(diff_keys/total_bits)*100:.2f}%)")

    print("\n[+] Prueba Avalancha 2: Cambio de 1 bit en el Mensaje")
    # Cambiamos un dígito del string. 
    msg_mod_str = "fl algoritmo CSS fue diseñado para proteger el contenido de los DVD mediante un cifrado de flujo basado en registros de desplazamiento. Aunque su seguridad fue superada, sigue siendo un hito clave en la historia de la gestión de los derechos digitales."
    msg_mod = msg_mod_str.encode('utf-8')
    
    ct3, ks3 = css_encrypt(msg_mod, key1)
    print(f"Mensaje Modificado: {msg_mod_str}")
    
    diff_msg = sum(bin(b1 ^ b3).count('1') for b1, b3 in zip(ct1, ct3))
    print(f"Bits diferentes generados en Ciphertext (Avalancha Mensaje): {diff_msg} / {total_bits} ({(diff_msg/total_bits)*100:.2f}%)")
    print("\nRespuesta: De igual manera que en ChaCha20, la modificación en un bit del mensaje solo se refleja en un bit de cambio en el criptograma, ya que el flujo pseudoaleatorio (keystream) depende solo de la clave.")
