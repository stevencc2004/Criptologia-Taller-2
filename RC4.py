import time

def rc4(key_indices, msg_indices, n):
    """
    Algoritmo RC4 adaptado para un módulo N.
    Devuelve los índices del keystream y del texto cifrado (o descifrado).
    """
    # KSA (Key-Scheduling Algorithm)
    S = list(range(n))
    j = 0
    for i in range(n):
        j = (j + S[i] + key_indices[i % len(key_indices)]) % n
        S[i], S[j] = S[j], S[i]
        
    # PRGA (Pseudo-Random Generation Algorithm)
    i = 0
    j = 0
    keystream = []
    ciphertext_indices = []
    
    for char_idx in msg_indices:
        i = (i + 1) % n
        j = (j + S[i]) % n
        S[i], S[j] = S[j], S[i]
        # Generar byte del keystream (o caracter en nuestro caso de N bits)
        k = S[(S[i] + S[j]) % n]
        
        keystream.append(k)
        ciphertext_indices.append(char_idx ^ k)
        
    return keystream, ciphertext_indices

def text_to_indices(text, dictionary):
    return [dictionary.index(c) for c in text]

def indices_to_text(indices, dictionary):
    return "".join(dictionary[idx] for idx in indices)

def run_tests():
    print("=======================================")
    print("PARTE 3: ALGORITMO RC4")
    print("=======================================")
    
    # --- PRUEBA 1 ---
    print("\n[+] Prueba 1: Cifrado con D = 32 caracteres (5 bits)")
    D32 = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ12345"
    n32 = len(D32)
    
    msg_str1 = "MENSAJEDEPRUEBARC4PARACRIPTOLOGIA"
    key_str1 = "CLAVE123"
    
    msg_idx = text_to_indices(msg_str1, D32)
    key_idx = text_to_indices(key_str1, D32)
    
    ks, ct_idx = rc4(key_idx, msg_idx, n32)
    ct_str = indices_to_text(ct_idx, D32)
    
    # Imprimir en binario de 5 bits
    print(f"Mensaje Plano:               {msg_str1}")
    print(f"Clave:                       {key_str1}")
    print(f"Texto Cifrado (str):         {ct_str}")
    
    # Formateadores a binario
    print("\nDetalle en binario:")
    for b_m, b_k, b_c, char_c in zip(msg_idx, ks, ct_idx, ct_str):
        print(f"  Mensaje: {b_m:05b} ^ Keystream: {b_k:05b} = Cipher: {b_c:05b} -> {char_c}")
        
    
    ks_bin_total = "".join(f"{b:05b}" for b in ks)
    ones = ks_bin_total.count('1')
    zeros = ks_bin_total.count('0')
    print(f"\nAnalisis de Postulados de Golomb (Keystream):")
    print(f"  Longitud Keystream (bits): {len(ks_bin_total)}")
    print(f"  Cantidad de '1's: {ones}")
    print(f"  Cantidad de '0's: {zeros}")
    print("  Respuesta ¿Cumple Postulados de Golomb?:")
    print("  Para el 1er postulado, debe haber equilibrio aprox equitativo de '1' y '0'. En secuencias cortas, RC4 puede presentar sesgos, pero aquí vemos si la diferencia es mínima. No es estrictamente perfecto, pero tiene gran similitud debido a la naturaleza pseudoaleatoria del RC4. El 2do y 3er postulado requerirían una prueba estadística más larga (ej. de rachas) pero a primera vista RC4 es un buen PRNG que satisface de forma aproximada estos postulados asintóticamente.")

    # --- PRUEBA 2 ---
    print("\n[+] Prueba 2: Cifrado y descifrado con clave propia")
    key_propia = "MIPASS1"
    key_prop_idx = text_to_indices(key_propia, D32)
    
    ks2, ct2_idx = rc4(key_prop_idx, msg_idx, n32)
    ct2_str = indices_to_text(ct2_idx, D32)
    print(f"Mensaje Cifrado con '{key_propia}': {ct2_str}")
    
    # Descifrar CORRECTO
    _, pt_corr_idx = rc4(key_prop_idx, ct2_idx, n32)
    print(f"Descifrado con clave CORRECTA ('{key_propia}'): {indices_to_text(pt_corr_idx, D32)}")
    
    # Descifrar INCORRECTO
    _, pt_incorr_idx = rc4(key_idx, ct2_idx, n32) # key_idx = CLAVE123
    print(f"Descifrado con clave INCORRECTA ('{key_str1}'): {indices_to_text(pt_incorr_idx, D32)}")
    
    print("\nPreguntas para el informe:")
    print("1. ¿Fué posible distinguir de alguna manera el mensaje usando una clave incorrecta?")
    print("   No. El mensaje resultante es texto aparentemente aleatorio, incomprensible.")
    print("2. ¿Sería posible hacer algún ataque estadístico usando una decodificación errónea?")
    print("   Es improbable para un solo mensaje cifrado con RC4 sin reuso de clave. Podría intentarse un ataque de fuerza bruta cruzado con estadísticas del lenguaje si el texto es suficientemente largo, es decir validar si una decodificación con X clave genera trigramas válidos y descartar la clave de lo contrario.")

    # --- PRUEBA 3 FUERZA BRUTA ---
    print("\n[+] Prueba 3: Ataque de Fuerza Bruta (D = 16)")
    D16 = "EAOLSNDRUITCPMYQ"
    n16 = len(D16)
    
    word_str = "SECRETO" # de la lista: S,E,C,R,E,T,O (todos en D16? S=4, E=0, C=11, R=7, E=0, T=10, O=2. Sí están!)
    key_4_str = "LUNA"    # Clave de 4 chars: L(3), U(8), N(5), A(1)
    
    word_idx = text_to_indices(word_str, D16)
    key_4_idx = text_to_indices(key_4_str, D16)
    
    _, ct_fuerza = rc4(key_4_idx, word_idx, n16)
    
    import itertools
    print(f"\nIniciando ataque fuerza bruta para el criptograma de '{word_str}'...")
    start_time = time.time()
    
    # Probar las 16^4 = 65536 posibilidades
    posibilidades = []
    # Usamos itertools para generar las tuplas
    for p in itertools.product(range(n16), repeat=4):
        _, descifrado = rc4(p, ct_fuerza, n16)
        texto = indices_to_text(descifrado, D16)
        posibilidades.append((p, texto))
        
    end_time = time.time()
    duracion = end_time - start_time
    
    total_pos = n16**4
    print("\nRespuestas sobre el Ataque de Fuerza Bruta:")
    print(f"1. ¿Cuántas posibilidades hay de claves?")
    print(f"   Hay N^k = {n16}^4 = {total_pos} combinaciones posibles.")
    print(f"2. ¿Cuánto tiempo se demoró?")
    print(f"   Aproximadamente {duracion:.4f} segundos.")
    print(f"3. Lista parcial de los resultados y sentido:")
    
    # Mostrar la correcta y un par de ejemplos
    idx_correcto = (-1)
    for i, (k, t) in enumerate(posibilidades):
        if t == "SECRETO":
            clave_hallada = indices_to_text(k, D16)
            print(f"   [!] Mensaje original encontrado: {t} usando la Clave: {clave_hallada}")
            
    print(f"4. ¿Dentro de las posibilidades aparecieron varias palabras con sentido?")
    print(f"   Es muy probable dado que son 7 caracteres y hay 65536 posibilidades aleatorias. Pueden surgir seudopalabras, pero con 7 letras es más difícil que en palabras de 4. (Por ejemplo, palabras al azar como 'SUERO' o algo así, si coincidiera).")
    print(f"5. ¿Qué criterio usarían para distinguir el mensaje correcto si salieran varios con sentido?")
    print("   Se usa el Índice de Coincidencia (IC) propio del idioma español, cruzar con un diccionario de palabras de dicho idioma, y modelos n-gramas. Las cadenas con sentido tendrán n-gramas o palabras exactas de español.")
    print(f"6. ¿Qué estrategia usarían para reducir el tiempo de encontrar la clave correcta?")
    print("   Realizar el procesamiento en paralelo (Multihreading/Multiprocessing/GPU computations), u optimizar el código (pasarlo de Python a un lenguaje compilado tipo C, usar pre-cálculo si existieran tablas, o técnicas como MITM dependiendo de la estructura).")

if __name__ == "__main__":
    run_tests()
