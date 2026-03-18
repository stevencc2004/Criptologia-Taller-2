import time

def rc4(key_indices, msg_indices, n):
    """
    Algoritmo RC4.
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
        # Generar byte del keystream 
        k = S[(S[i] + S[j]) % n]
        
        keystream.append(k)
        ciphertext_indices.append(char_idx ^ k)
        
    return keystream, ciphertext_indices

def text_to_indices(text, dictionary):
    return [dictionary.index(c) for c in text]

def indices_to_text(indices, dictionary):
    return "".join(dictionary[idx] for idx in indices)

D32_GLOBAL = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ12345"

def rc4_custom_32(key: str, text: str, show_details: bool = False) -> str:
    """
    Cifra o descifra usando el algoritmo RC4:
    """
    # Validación de la longitud de la clave
    if not (4 <= len(key) <= 16):
        raise ValueError(f"Error: La clave debe tener entre 4 y 16 caracteres (tiene {len(key)}).")
        
    # Validación de los caracteres de la clave
    for c in key:
        if c not in D32_GLOBAL:
            raise ValueError(f"Error: El carácter '{c}' de la clave no pertenece al diccionario.")
            
    # Validación de los caracteres del mensaje/texto
    for c in text:
        if c not in D32_GLOBAL:
            raise ValueError(f"Error: El carácter '{c}' del texto no pertenece al diccionario.")
            
    n = len(D32_GLOBAL)
    key_idx = text_to_indices(key, D32_GLOBAL)
    text_idx = text_to_indices(text, D32_GLOBAL)
    
    ks, result_idx = rc4(key_idx, text_idx, n)
    result_text = indices_to_text(result_idx, D32_GLOBAL)
    
    if show_details:
    
        # 1. Mensaje y clave
        print(f"\n1. Códigos en decimal (índices en el diccionario):")
        print(f"\n   Mensaje '{text}': ")
        print(f"      {text_idx}")
        print(f"\n   Clave   '{key}': ")
        print(f"      {key_idx}")
        

        # 3. tabla de XOR
        print("\n3. Proceso de Codificación (Tabla):")
        print(f"\n   | {'Char':^6} | {'Char(Dec)':^9} | {'Char(Bin)':^10} | {'Key(Dec)':^8} | {'Key(Bin)':^10} | {'XOR(Dec)':^8} | {'XOR(Bin)':^10} | {'Cifrado':^9} |")
        print("   |" + "-"*8 + "+" + "-"*11 + "+" + "-"*12 + "+" + "-"*10 + "+" + "-"*12 + "+" + "-"*10 + "+" + "-"*12 + "+" + "-"*11 + "|")
        for m_idx, k_val, c_idx, char_c, char_m in zip(text_idx, ks, result_idx, result_text, text):
            m_bin = f"{m_idx:05b}"
            k_bin = f"{k_val:05b}"
            c_bin = f"{c_idx:05b}"
            print(f"   | {char_m:^6} | {m_idx:^9} | {m_bin:^10} | {k_val:^8} | {k_bin:^10} | {c_idx:^8} | {c_bin:^10} | {char_c:^9} |")
            
        # 4. Mensaje resultante
        print(f"\n4. Mensaje resultante:")
        print(f"   {result_text}")
        print("\n" + "="*50 + "\n")
    
    return result_text

def run_tests():
    print("          =======================================")
    print("                 PARTE 3: ALGORITMO RC4")
    print("          =======================================")
    
    # --- PRUEBA 1 ---
    print("\n[+] Prueba 1: Cifrado con D = 32 caracteres (5 bits)")
    D32 = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ12345"
    n32 = len(D32)
    
    msg_str1 = "MENSAJEDEPRUEBARC4PARACRIPTOLOGIA"
    key_str1 = "CLAVE123"
    
    # mostrar los detalles al informe
    ct_str = rc4_custom_32(key_str1, msg_str1, show_details=True)
    
    # Re-obtener variables necesarias para el análisis de Golomb
    msg_idx = text_to_indices(msg_str1, D32)
    key_idx = text_to_indices(key_str1, D32)
    ks, ct_idx = rc4(key_idx, msg_idx, n32)
    ks_bin_total = "".join(f"{b:05b}" for b in ks)
    ones = ks_bin_total.count('1')
    zeros = ks_bin_total.count('0')
    print(f"Analisis de Postulados de Golomb (Keystream):")
    print(f"  Longitud Keystream (bits): {len(ks_bin_total)}")
    print(f"  Cantidad de '1's: {ones}")
    print(f"  Cantidad de '0's: {zeros}")
    print("\n" + "="*50 + "\n")

    # --- PRUEBA 2 ---
    print("\n[+] Prueba 2: Cifrado y descifrado con clave propia")
    key_propia = "CLAVEPRUEBA123"
    key_prop_idx = text_to_indices(key_propia, D32)
    
    # mostrar detalles
    print(f"\n Mensaje: '{msg_str1}'\n Clave: '{key_propia}'")
    ct2_str = rc4_custom_32(key_propia, msg_str1, show_details=True)
    print(f"Mensaje Cifrado con '{key_propia}': {ct2_str}")
    print("\n" + "="*50 + "\n")

    # Descifrado CORRECTO 
    print(f"\n Descifrado de: '{ct2_str}'\n con clave CORRECTA: '{key_propia}'")
    pt_corr_str = rc4_custom_32(key_propia, ct2_str, show_details=True)
    print(f"   Descifrado con clave CORRECTA ('{key_propia}'): {pt_corr_str}")
    print("\n" + "="*50 + "\n")

    # Descifrado INCORRECTO 
    print(f"\n Descifrado de: '{ct2_str}'\n con clave INCORRECTA: '{key_str1}'")
    pt_incorr_str = rc4_custom_32(key_str1, ct2_str, show_details=True) 
    print(f"   Descifrado con clave INCORRECTA ('{key_str1}'): {pt_incorr_str}")
    print("\n" + "="*50 + "\n")
    
    # --- PRUEBA 3 FUERZA BRUTA ---
    print("\n[+] Prueba 3: Ataque de Fuerza Bruta (D = 16)")
    D16 = "EAOLSNDRUITCPMYQ"
    n16 = len(D16)
    
    # 1. Mensaje y clave
    word_str = "SECRETO" 
    key_4_str = "LEON"    
    
    word_idx = text_to_indices(word_str, D16)
    key_4_idx = text_to_indices(key_4_str, D16)
    
    # 2. codificación del mensaje
    ks_fuerza, ct_fuerza = rc4(key_4_idx, word_idx, n16)
    ct_fuerza_str = indices_to_text(ct_fuerza, D16)
    
    print(f"\nDesarrollando la codificación del mensaje:")
    print(f"   Mensaje Original : {word_str}")
    print(f"   Clave usada      : {key_4_str}")
    print(f"   Criptograma      : {ct_fuerza_str}")

    print("\n   Proceso de Codificación (Tabla D=16, 4 bits):")
    print(f"\n   | {'Char':^6} | {'Char(Dec)':^9} | {'Char(Bin)':^10} | {'Key(Dec)':^8} | {'Key(Bin)':^10} | {'XOR(Dec)':^8} | {'XOR(Bin)':^10} | {'Cifrado':^9} |")
    print("   |" + "-"*8 + "+" + "-"*11 + "+" + "-"*12 + "+" + "-"*10 + "+" + "-"*12 + "+" + "-"*10 + "+" + "-"*12 + "+" + "-"*11 + "|")
    for m_idx, k_val, c_idx, char_c, char_m in zip(word_idx, ks_fuerza, ct_fuerza, ct_fuerza_str, word_str):
        m_bin = f"{m_idx:04b}"
        k_bin = f"{k_val:04b}"
        c_bin = f"{c_idx:04b}"
        print(f"   | {char_m:^6} | {m_idx:^9} | {m_bin:^10} | {k_val:^8} | {k_bin:^10} | {c_idx:^8} | {c_bin:^10} | {char_c:^9} |")

    # 3. Programa que prueba todas las posibles combinaciones de claves de 4 caracteres
    import itertools
    import time
    
    print(f"\nIniciando ataque de fuerza bruta para el criptograma '{ct_fuerza_str}'...")
    start_time = time.time()
    
    table_filename = "tabla_fuerza_bruta.txt"
    print(f"Podra ver la tabla con todas las combinaciones en el archivo adjunto: {table_filename}")
    
    with open(table_filename, "w", encoding="utf-8") as f:
        f.write(f"{'CLAVE':<10} | {'MENSAJE DECODIFICADO':<25} | {'ESTADO'}\n")
        f.write("-" * 65 + "\n")
        
        for p in itertools.product(range(n16), repeat=4):
            _, descifrado = rc4(p, ct_fuerza, n16)
            texto = indices_to_text(descifrado, D16)
            clave_actual = indices_to_text(p, D16)
            
            estado = ""
            if texto == word_str: # Se identifica el mensaje original para distinguirlo en la tabla
                estado = "<--- MENSAJE CORRECTO ENCONTRADO"
            
            f.write(f"{clave_actual:<10} | {texto:<25} | {estado}\n")

    end_time = time.time()
    duracion = end_time - start_time
    
    total_pos = n16**4
    print(f"\n" + "="*50)
    print(f"RESUMEN DEL ATAQUE DE FUERZA BRUTA:")
    print(f"="*50)
    print(f"1. Total de combinaciones posibles (N^k): {n16}^4 = {total_pos}")
    print(f"2. Tiempo total que demoró en calcular y obtener TODAS las posibilidades: {duracion:.4f} segundos.")
    print(f"3. La tabla completa con las {total_pos} posibilidades se ha guardado en: '{table_filename}'")
    
    print("\nFragmento de la tabla generada en el archivo donde se resalta la clave correcta:\n")
    print(f"{'CLAVE':<10} | {'MENSAJE DECODIFICADO':<25} | {'ESTADO'}")
    print("-" * 65)
    
    # Se muestran las primeras 5 y la correcta como demostracion
    muestra_count = 0
    for p in itertools.product(range(n16), repeat=4):
        _, descifrado = rc4(p, ct_fuerza, n16)
        texto = indices_to_text(descifrado, D16)
        clave_actual = indices_to_text(p, D16)
        
        is_correct = (texto == word_str)
        
        if muestra_count < 5 or is_correct:
            estado = "<--- MENSAJE CORRECTO ENCONTRADO" if is_correct else ""
            print(f"{clave_actual:<10} | {texto:<25} | {estado}")
            if is_correct:
                print("... (otras combinaciones) ...")
        
        muestra_count += 1

if __name__ == "__main__":
    run_tests()

