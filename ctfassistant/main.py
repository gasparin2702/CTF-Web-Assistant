#!/usr/bin/env python3
"""
MÓDULO COMPLETO CTF - Todas las Categorías
Campo de Marte 2025
Incluye: Reversing, Pwn, Crypto, Forensics, Steganography, OSINT, Web, Hardware
"""

import os
import sys
import subprocess
import struct
import string
from pathlib import Path

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

# ═══════════════════════════════════════════════════════════════
# MÓDULO 1: REVERSING
# ═══════════════════════════════════════════════════════════════

def reversing_strings_analysis(binary_path):
    """Análisis de strings en binario"""
    print(f"\n{YELLOW}═══ STRING ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/4] Extrayendo strings...")
    os.system(f"strings {binary_path} > /tmp/strings_output.txt")
    
    print("\n[2/4] Buscando flags...")
    os.system(f"grep -i 'flag\\|password\\|key' /tmp/strings_output.txt")
    
    print("\n[3/4] Buscando URLs y emails...")
    os.system(f"grep -E 'http|@' /tmp/strings_output.txt")
    
    print("\n[4/4] Strings interesantes (más de 20 chars)...")
    os.system(f"strings {binary_path} | awk 'length>20' | head -20")
    
    print(f"\n💾 Output completo: /tmp/strings_output.txt")

def reversing_binary_info(binary_path):
    """Información del binario"""
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
    os.system(f"checksec --file={binary_path} 2>/dev/null || echo 'checksec no disponible'")
    
    print("\n[5/5] Symbols...")
    os.system(f"nm {binary_path} 2>/dev/null | head -20")

def reversing_disassemble(binary_path):
    """Desensamblado básico"""
    print(f"\n{YELLOW}═══ DISASSEMBLY ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/3] Usando objdump...")
    os.system(f"objdump -d {binary_path} > /tmp/disasm.txt 2>/dev/null")
    os.system(f"objdump -d {binary_path} | grep -A 10 '<main>' 2>/dev/null")
    
    print("\n[2/3] Buscando funciones interesantes...")
    os.system(f"objdump -t {binary_path} 2>/dev/null | grep -E 'flag|password|key|secret'")
    
    print("\n[3/3] Secciones del binario...")
    os.system(f"readelf -S {binary_path} 2>/dev/null | head -20")
    
    print(f"\n💾 Desensamblado completo: /tmp/disasm.txt")

def reversing_hex_dump(binary_path):
    """Hex dump y búsqueda de patrones"""
    print(f"\n{YELLOW}═══ HEX DUMP ANALYSIS ═══{RESET}\n")
    
    if not os.path.exists(binary_path):
        print(f"{RED}❌ Archivo no encontrado{RESET}")
        return
    
    print("[1/3] Primeros 256 bytes...")
    os.system(f"xxd {binary_path} | head -16")
    
    print("\n[2/3] Buscando magic bytes conocidos...")
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
        
        for magic, desc in magic_bytes.items():
            if hex_header.startswith(magic):
                print(f"✅ Detectado: {desc}")
    
    print("\n[3/3] Últimos 256 bytes (puede haber data al final)...")
    os.system(f"xxd {binary_path} | tail -16")

def reversing_ltrace_strace(binary_path):
    """Trazado de llamadas"""
    print(f"\n{YELLOW}═══ DYNAMIC ANALYSIS ═══{RESET}\n")
    
    print("[1/2] ltrace (library calls)...")
    print("Ejecutando binario con ltrace...")
    os.system(f"timeout 5 ltrace {binary_path} 2>&1 | head -30")
    
    print("\n[2/2] strace (system calls)...")
    print("Ejecutando binario con strace...")
    os.system(f"timeout 5 strace {binary_path} 2>&1 | head -30")

def reversing_menu():
    """Menú de Reversing"""
    while True:
        print(f"\n{BLUE}{'═'*60}")
        print("REVERSING ENGINEERING")
        print(f"{'═'*60}{RESET}")
        print("1. 📝 String Analysis")
        print("2. 🔍 Binary Info (file, checksec, symbols)")
        print("3. 💻 Disassembly (objdump)")
        print("4. 🔢 Hex Dump Analysis")
        print("5. 🔬 Dynamic Analysis (ltrace/strace)")
        print("6. 🛠️  Abrir en Ghidra")
        print("7. 🛠️  Abrir en radare2")
        print("8. 📦 Análisis Completo (todo lo anterior)")
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
                reversing_strings_analysis(binary)
                reversing_hex_dump(binary)
                reversing_disassemble(binary)
                print(f"\n{GREEN}✅ Análisis completo guardado en /tmp/{RESET}")
        
        elif choice == '6':
            binary = input("Ruta del binario: ").strip()
            print(f"\n{GREEN}[*] Abriendo en Ghidra...{RESET}")
            os.system(f"ghidra {binary} &")
        
        elif choice == '7':
            binary = input("Ruta del binario: ").strip()
            print(f"\n{GREEN}[*] Abriendo en radare2...{RESET}")
            os.system(f"r2 {binary}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 2: PWN / BINARY EXPLOITATION
# ═══════════════════════════════════════════════════════════════

def pwn_checksec(binary_path):
    """Verificar protecciones del binario"""
    print(f"\n{YELLOW}═══ SECURITY CHECKS ═══{RESET}\n")
    os.system(f"checksec --file={binary_path}")

def pwn_buffer_overflow_check(binary_path):
    """Detectar posibles buffer overflows"""
    print(f"\n{YELLOW}═══ BUFFER OVERFLOW DETECTION ═══{RESET}\n")
    
    print("[1/3] Buscando funciones peligrosas...")
    dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf', 'vsprintf']
    
    for func in dangerous_funcs:
        result = subprocess.run(
            f"objdump -d {binary_path} | grep -i {func}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.stdout:
            print(f"⚠️  Encontrado: {func}")
    
    print("\n[2/3] Verificando stack protections...")
    os.system(f"readelf -s {binary_path} | grep STACK")
    
    print("\n[3/3] Generando pattern para testing...")
    print("Pattern cíclico (100 chars):")
    # Generar pattern De Bruijn simple
    pattern = ""
    for i in range(26):
        for j in range(26):
            pattern += chr(65 + i) + chr(97 + j)
            if len(pattern) >= 100:
                break
        if len(pattern) >= 100:
            break
    print(pattern[:100])

def pwn_rop_gadgets(binary_path):
    """Buscar ROP gadgets"""
    print(f"\n{YELLOW}═══ ROP GADGETS ═══{RESET}\n")
    print("Buscando gadgets útiles...")
    os.system(f"ROPgadget --binary {binary_path} 2>/dev/null | head -50")

def pwn_menu():
    """Menú de PWN"""
    while True:
        print(f"\n{BLUE}{'═'*60}")
        print("PWN / BINARY EXPLOITATION")
        print(f"{'═'*60}{RESET}")
        print("1. 🛡️  Check Security (checksec)")
        print("2. 💥 Buffer Overflow Detection")
        print("3. 🔗 ROP Gadgets Search")
        print("4. 📝 Generate Shellcode")
        print("5. 🔢 Generate Cyclic Pattern")
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
        
        elif choice == '4':
            print("\n🔧 Shellcode común:\n")
            print("Linux x86 execve /bin/sh:")
            print("\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e")
            print("\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80")
        
        elif choice == '5':
            length = input("Longitud del pattern (default 100): ").strip() or "100"
            pattern = ""
            for i in range(26):
                for j in range(26):
                    pattern += chr(65 + i) + chr(97 + j)
                    if len(pattern) >= int(length):
                        break
                if len(pattern) >= int(length):
                    break
            print(f"\nPattern: {pattern[:int(length)]}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 3: FORENSICS
# ═══════════════════════════════════════════════════════════════

def forensics_file_analysis(file_path):
    """Análisis forense de archivo"""
    print(f"\n{YELLOW}═══ FILE FORENSICS ═══{RESET}\n")
    
    print("[1/6] File type and magic bytes...")
    os.system(f"file {file_path}")
    os.system(f"xxd {file_path} | head -3")
    
    print("\n[2/6] Metadata (exiftool)...")
    os.system(f"exiftool {file_path} 2>/dev/null || echo 'exiftool no disponible'")
    
    print("\n[3/6] Binwalk (embedded files)...")
    os.system(f"binwalk {file_path}")
    
    print("\n[4/6] Foremost (file carving)...")
    output_dir = "/tmp/foremost_output"
    os.system(f"foremost -o {output_dir} {file_path} 2>/dev/null")
    print(f"Archivos extraídos en: {output_dir}")
    
    print("\n[5/6] Strings analysis...")
    os.system(f"strings {file_path} | grep -i flag")
    
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
                        entropy -= p * (p.bit_length() - 1)
                
                print(f"Entropy: {entropy:.2f} (>7.5 = probablemente encriptado)")
    except:
        print("Error calculando entropy")

def forensics_memory_strings(dump_path):
    """Análisis de memoria dump"""
    print(f"\n{YELLOW}═══ MEMORY DUMP ANALYSIS ═══{RESET}\n")
    
    print("[1/3] Buscando passwords...")
    os.system(f"strings {dump_path} | grep -i 'password\\|passwd\\|pwd' | head -20")
    
    print("\n[2/3] Buscando flags...")
    os.system(f"strings {dump_path} | grep -E 'flag\\{{|FLAG\\{{' | head -20")
    
    print("\n[3/3] Buscando URLs...")
    os.system(f"strings {dump_path} | grep -E 'http://|https://' | head -20")

def forensics_disk_analysis(image_path):
    """Análisis de imagen de disco"""
    print(f"\n{YELLOW}═══ DISK IMAGE ANALYSIS ═══{RESET}\n")
    
    print("[1/3] Mounting image...")
    mount_point = "/tmp/disk_mount"
    os.system(f"mkdir -p {mount_point}")
    os.system(f"sudo mount -o loop {image_path} {mount_point} 2>/dev/null")
    
    print("\n[2/3] Listing files...")
    os.system(f"ls -laR {mount_point} 2>/dev/null | head -50")
    
    print("\n[3/3] Searching for hidden files...")
    os.system(f"find {mount_point} -name '.*' 2>/dev/null")
    
    print(f"\n💾 Image mounted at: {mount_point}")
    print("Recuerda desmontar: sudo umount {mount_point}")

def forensics_menu():
    """Menú de Forensics"""
    while True:
        print(f"\n{BLUE}{'═'*60}")
        print("FORENSICS")
        print(f"{'═'*60}{RESET}")
        print("1. 🔍 File Analysis (completo)")
        print("2. 💾 Memory Dump Analysis")
        print("3. 💿 Disk Image Analysis")
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
            output = input("Directorio output (default /tmp/binwalk): ").strip() or "/tmp/binwalk"
            os.system(f"binwalk -e --directory={output} {file_path}")
            print(f"\n✅ Archivos en: {output}")
        elif choice == '5':
            os.system(f"exiftool {file_path}")
        elif choice == '6':
            output = input("Directorio output (default /tmp/foremost): ").strip() or "/tmp/foremost"
            os.system(f"foremost -o {output} {file_path}")
            print(f"\n✅ Archivos en: {output}")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 4: STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════

def stego_image_analysis(image_path):
    """Análisis de esteganografía en imágenes"""
    print(f"\n{YELLOW}═══ IMAGE STEGANOGRAPHY ═══{RESET}\n")
    
    print("[1/5] Metadata...")
    os.system(f"exiftool {image_path} 2>/dev/null")
    
    print("\n[2/5] Strings...")
    os.system(f"strings {image_path} | grep -i flag")
    
    print("\n[3/5] Binwalk (embedded files)...")
    os.system(f"binwalk {image_path}")
    
    print("\n[4/5] Steghide extract (sin password)...")
    os.system(f"steghide extract -sf {image_path} -p '' 2>/dev/null || echo 'Requiere password'")
    
    print("\n[5/5] zsteg (LSB analysis)...")
    os.system(f"zsteg {image_path} 2>/dev/null | head -20")

def stego_audio_analysis(audio_path):
    """Análisis de audio"""
    print(f"\n{YELLOW}═══ AUDIO STEGANOGRAPHY ═══{RESET}\n")
    
    print("[1/3] Metadata...")
    os.system(f"exiftool {audio_path} 2>/dev/null")
    
    print("\n[2/3] Spectogram analysis...")
    print("Abriendo en Audacity para análisis visual...")
    os.system(f"audacity {audio_path} &")
    
    print("\n[3/3] Strings...")
    os.system(f"strings {audio_path} | grep -i flag")

def stego_menu():
    """Menú de Steganography"""
    while True:
        print(f"\n{BLUE}{'═'*60}")
        print("STEGANOGRAPHY")
        print(f"{'═'*60}{RESET}")
        print("1. 🖼️  Image Analysis")
        print("2. 🎵 Audio Analysis")
        print("3. 📄 Text/Document Analysis")
        print("4. 🔓 Steghide Extract")
        print("5. 🔍 LSB Analysis (zsteg)")
        print("6. 📊 Stegsolve (tool)")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        file_path = input("Ruta del archivo: ").strip()
        
        if choice == '1':
            stego_image_analysis(file_path)
        elif choice == '2':
            stego_audio_analysis(file_path)
        elif choice == '3':
            os.system(f"strings {file_path} | head -50")
        elif choice == '4':
            password = input("Password (Enter si ninguno): ").strip()
            cmd = f"steghide extract -sf {file_path}"
            if password:
                cmd += f" -p {password}"
            os.system(cmd)
        elif choice == '5':
            os.system(f"zsteg {file_path}")
        elif choice == '6':
            os.system(f"stegsolve {file_path} &")

# ═══════════════════════════════════════════════════════════════
# MÓDULO 5: OSINT
# ═══════════════════════════════════════════════════════════════

def osint_whois(domain):
    """WHOIS lookup"""
    print(f"\n{YELLOW}═══ WHOIS LOOKUP ═══{RESET}\n")
    os.system(f"whois {domain}")

def osint_dns(domain):
    """DNS enumeration"""
    print(f"\n{YELLOW}═══ DNS ENUMERATION ═══{RESET}\n")
    
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
    print(f"\n{YELLOW}═══ SUBDOMAIN ENUMERATION ═══{RESET}\n")
    
    print("Usando wordlist offline...")
    wordlist = "~/CTF_OFFLINE_RESOURCES/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
    
    if os.path.exists(os.path.expanduser(wordlist)):
        print(f"Testing common subdomains...")
        os.system(f"cat {wordlist} | head -100 | while read sub; do "
                 f"host $sub.{domain} 2>/dev/null | grep 'has address' && echo $sub.{domain}; done")
    else:
        print("Wordlist no encontrada, probando comunes...")
        common = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api']
        for sub in common:
            os.system(f"host {sub}.{domain} 2>/dev/null | grep 'has address'")

def osint_menu():
    """Menú de OSINT"""
    while True:
        print(f"\n{BLUE}{'═'*60}")
        print("OSINT (Open Source Intelligence)")
        print(f"{'═'*60}{RESET}")
        print("1. 🔍 WHOIS Lookup")
        print("2. 🌐 DNS Enumeration")
        print("3. 📡 Subdomain Enumeration")
        print("4. 📧 Email Harvesting")
        print("5. 🗺️  Geolocation (IP)")
        print("6. 📸 Social Media Search")
        print("9. ← Volver")
        
        choice = input(f"\n{CYAN}Opción: {RESET}").strip()
        
        if choice == '9':
            break
        
        if choice == '1':
            domain = input("Domain: ").strip()
            osint_whois(domain)
        elif choice == '2':
            domain = input("Domain: ").strip()
            osint_dns(domain)
        elif choice == '3':
            domain = input("Domain: ").strip()
            osint_subdomain_enum(domain)
        elif choice == '4':
            domain = input("Domain: ").strip()
            print("\nBuscando emails...")
            os.system(f"theharvester -d {domain} -b google 2>/dev/null || echo 'theHarvester no disponible'")
        elif choice == '5':
            ip = input("IP address: ").strip()
            os.system(f"curl ipinfo.io/{ip} 2>/dev/null")

# ═══════════════════════════════════════════════════════════════
# MENÚ PRINCIPAL
# ═══════════════════════════════════════════════════════════════

def main_menu():
    """Menú principal con todas las categorías"""
    while True:
        print(f"\n{GREEN}{'═'*60}")
        print(" CTF COMPLETE TOOLKIT - Campo de Marte 2025")
        print(f"{'═'*60}{RESET}")
        print(f"{MAGENTA}1. 💻 REVERSING{RESET} - Binary analysis, disassembly")
        print(f"{RED}2. 💥 PWN{RESET} - Binary exploitation, ROP")
        print(f"{CYAN}3. 🔍 FORENSICS{RESET} - File analysis, memory dumps")
        print(f"{YELLOW}4. 🖼️  STEGANOGRAPHY{RESET} - Hidden data in files")
        print(f"{BLUE}5. 🌐 OSINT{RESET} - Open source intelligence")
        print(f"{GREEN}6. 🌐 WEB{RESET} - SQL injection, XSS, etc")
        print(f"{MAGENTA}7. 🔧 HARDWARE{RESET} - ESP32, firmware, etc")
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
        elif choice == '0':
            print(f"\n{GREEN}¡Suerte en Campo de Marte 2025!{RESET}\n")
            break

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Saliendo...{RESET}\n")
        sys.exit(0)
