import socket
import platform
import winreg
import json
import os
from datetime import datetime, timezone
import urllib.request

SERVER_URL = "__SERVER_URL__"
AGENT_SECRET_TOKEN = "__AGENT_TOKEN__"

def clean_string(s):
    if not isinstance(s, str): return s
    return s.encode('utf-8', 'ignore').decode('utf-8')

def get_os_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = "127.0.0.1"
    os_name = platform.system()
    os_version = platform.release()
    asset_type = "workstation"
    if "server" in platform.win32_ver()[0].lower():
        asset_type = "server"
    return {"hostname": hostname, "ip": ip, "os": f"{os_name} {os_version}", "asset_type": asset_type}

def get_installed_software():
    software_list = []
    uninstall_paths = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
    for path in uninstall_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                            if display_name and str(display_name).strip():
                                software_list.append({"name": clean_string(display_name), "version": clean_string(display_version), "vendor": clean_string(publisher)})
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
    return [dict(t) for t in {tuple(d.items()) for d in software_list}]

def send_data_to_server(data):
    print(f"\n--- Enviando datos al servidor en {SERVER_URL} ---")
    try:
        data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Agent-Token': AGENT_SECRET_TOKEN
        }
        req = urllib.request.Request(SERVER_URL, data=data_bytes, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status >= 200 and response.status < 300:
                response_data = json.loads(response.read().decode('utf-8'))
                print("[+] Éxito: El servidor ha recibido los datos.")
                print(f"Respuesta del servidor: {response_data['message']}")
            else:
                print(f"[!] Error: El servidor respondió con el código de estado {response.status}")
    except Exception as e:
        print(f"[!] Error: No se pudo enviar los datos al servidor. {e}")

def main():
    print("--- Iniciando recolección de datos del agente de Windows ---")
    system_info = get_os_info()
    print("Información del sistema recolectada.")
    software_inventory = get_installed_software()
    print(f"Se encontraron {len(software_inventory)} programas instalados.")
    agent_data = {
        "hostname": system_info["hostname"],
        "ip": system_info["ip"],
        "os": system_info["os"],
        "os_version": platform.version(),
        "asset_type": system_info["asset_type"],
        "software": software_inventory,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    send_data_to_server(agent_data)

if __name__ == "__main__":
    main()
