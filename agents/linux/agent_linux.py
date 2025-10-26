import socket
import platform
import json
import subprocess
import os
from datetime import datetime, timezone
import urllib.request

# Lee la URL del servidor desde una variable de entorno, con un valor por defecto.
SERVER_URL = "__SERVER_URL__"
AGENT_SECRET_TOKEN = "__AGENT_TOKEN__"

def get_os_info():
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    os_name = platform.system()
    os_version = platform.release()
    asset_type = "workstation"
    return {"hostname": hostname, "ip": ip, "os": f"{os_name} {os_version}", "asset_type": asset_type}

def get_installed_software_apt():
    software_list = []
    try:
        cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        for line in result.stdout.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) == 3:
                software_list.append({"name": parts[0], "version": parts[1], "vendor": parts[2]})
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"[APT] No se pudo obtener la lista de paquetes: {e}")
    return software_list

def get_installed_software():
    return get_installed_software_apt()

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
    print("--- Iniciando recolección de datos del agente de Linux ---")
    system_info = get_os_info()
    print("Información del sistema recolectada.")
    software_inventory = get_installed_software()
    print(f"Se encontraron {len(software_inventory)} paquetes instalados.")
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
