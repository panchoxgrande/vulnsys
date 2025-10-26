import requests
import json
import csv
import os
from io import StringIO
from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2.extras import execute_values
from OTXv2 import OTXv2, IndicatorTypes

import database

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'settings.json')
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"

def load_settings():
    try:
        with open(SETTINGS_FILE, 'r') as f: return json.load(f)
    except FileNotFoundError: print(f"[CONFIG] ERROR: {SETTINGS_FILE} no encontrado."); return None

def save_settings(settings):
    try:
        with open(SETTINGS_FILE, 'w') as f: json.dump(settings, f, indent=2)
    except Exception as e: print(f"[CONFIG] ERROR al guardar settings.json: {e}")

def simplify_cve_description(description, severity):
    d = description.lower() if description else ''
    if "remote code execution" in d: return "Un atacante puede ejecutar código malicioso en este equipo de forma remota."
    if "sql injection" in d: return "Un atacante podría manipular las bases de datos de la aplicación."
    if "cross-site scripting" in d: return "Un atacante podría inyectar código malicioso en la página web."
    if "buffer overflow" in d: return "Una gestión incorrecta de la memoria podría permitir a un atacante tomar control del sistema."
    if "denial of service" in d: return "Un atacante podría hacer que el sistema o servicio deje de funcionar."
    if "privilege escalation" in d: return "Un usuario con pocos permisos podría conseguir acceso de administrador."
    if severity == 'CRITICAL': return "Vulnerabilidad muy grave que podría permitir a un atacante tomar control total del sistema."
    if severity == 'HIGH': return "Vulnerabilidad grave que podría comprometer la seguridad del sistema."
    if severity == 'MEDIUM': return "Vulnerabilidad de riesgo moderado con impacto limitado."
    return "Vulnerabilidad de bajo impacto."

def fetch_nvd_data(start_date, end_date, settings):
    print(f"\n[NVD] Buscando CVEs desde {start_date} hasta {end_date}...")
    nvd_api_key = settings.get('api_keys', {}).get('nvd')
    headers = {'apiKey': nvd_api_key} if nvd_api_key else {}
    keywords = ["windows", "linux", "macos"]
    all_vulnerabilities = {}
    for keyword in keywords:
        print(f"[NVD] Buscando para: '{keyword}'...")
        params = {'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'keywordSearch': keyword, 'resultsPerPage': 2000}
        try:
            response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            vulnerabilities = response.json().get('vulnerabilities', [])
            print(f"  - Encontrados {len(vulnerabilities)} CVEs para '{keyword}'.")
            for vuln in vulnerabilities: all_vulnerabilities[vuln['cve']['id']] = vuln
        except requests.exceptions.RequestException as e: print(f"[NVD] ERROR buscando para '{keyword}': {e}"); continue
    return list(all_vulnerabilities.values())

def check_exploit_availability(cve_list):
    print("\n[EXPLOIT] Verificando disponibilidad de exploits...")
    exploited_cves = set()
    try:
        response = requests.get(EXPLOITDB_URL, timeout=60)
        response.raise_for_status()
        reader = csv.DictReader(StringIO(response.text))
        for row in reader:
            codes = row.get('codes', '')
            if 'CVE-' in codes:
                for code in codes.split(';'):
                    if code.startswith('CVE-'): exploited_cves.add(code)
        print(f"[EXPLOIT] Encontrados {len(exploited_cves)} CVEs con exploits.")
    except Exception as e: print(f"[EXPLOIT] ERROR: {e}")
    for cve in cve_list: cve['exploit_available'] = cve['cve']['id'] in exploited_cves
    return cve_list

def enrich_with_external_apis(cves, settings):
    print("\n[ENRICH] Enriqueciendo con APIs externas...")
    otx_api_key = settings.get('api_keys', {}).get('otx')
    if not otx_api_key: 
        print("[ENRICH] ADVERTENCIA: No hay API key de OTX.")
        for cve in cves:
            cve['otx_pulses'] = 0
        return cves

    otx = OTXv2(otx_api_key)

    for cve in cves:
        cve_id = cve.get('cve_id')
        if not cve_id: 
            cve['otx_pulses'] = 0
            continue
        try:
            pulses = otx.get_indicator_details_full(IndicatorTypes.CVE, cve_id)
            cve['otx_pulses'] = len(pulses.get('pulse_info', {}).get('pulses', []))
        except Exception as e:
            cve['otx_pulses'] = 0
            
    print("[ENRICH] Proceso de enriquecimiento finalizado.")
    return cves

def save_cves_to_db(cves_data):
    if not cves_data: return 0
    conn = None
    inserted_rows = 0
    try:
        conn = database.get_db_connection()
        if conn is None: raise Exception("No se pudo conectar a la BD para guardar CVEs.")
        cur = conn.cursor()

        for cve_data in cves_data:
            cur.execute(
                "INSERT INTO cves (cve_id, cvss_score, severity, description, exploit_available, published_date, otx_pulse_count) VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (cve_id) DO UPDATE SET cvss_score = EXCLUDED.cvss_score, otx_pulse_count = EXCLUDED.otx_pulse_count RETURNING id;",
                (cve_data['cve_id'], cve_data['cvss_score'], cve_data['severity'], cve_data['description_en'], cve_data['exploit_available'], cve_data['published_date'], cve_data.get('otx_pulses', 0))
            )
            result = cur.fetchone()
            if result is None:
                cur.execute("SELECT id FROM cves WHERE cve_id = %s;", (cve_data['cve_id'],))
                cve_db_id = cur.fetchone()[0]
            else:
                cve_db_id = result[0]
                inserted_rows += 1

            if cve_data.get('cpes'):
                cpe_tuples = [(cve_db_id, cpe) for cpe in cve_data['cpes']]
                execute_values(cur, "INSERT INTO cve_cpe_match (cve_id, cpe_uri) VALUES %s ON CONFLICT DO NOTHING", cpe_tuples)

        conn.commit()
        cur.close()
        print(f"[DB] Guardado finalizado. Se insertaron {inserted_rows} nuevos CVEs y se procesaron sus CPEs y datos de OTX.")
        return inserted_rows
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"[DB ERROR] al guardar CVEs: {error}")
        if conn: conn.rollback()
        return 0
    finally:
        if conn: conn.close()

def process_cves_for_db(raw_cves):
    processed_list = []
    for item in raw_cves:
        cve = item.get('cve')
        if not cve: continue
        cvss_score, severity = None, "N/A"
        if 'cvssMetricV31' in cve.get('metrics', {}): metric = cve['metrics']['cvssMetricV31'][0]; cvss_score = metric['cvssData']['baseScore']; severity = metric['cvssData']['baseSeverity']
        elif 'cvssMetricV2' in cve.get('metrics', {}): metric = cve['metrics']['cvssMetricV2'][0]; cvss_score = metric['cvssData']['baseScore']; severity = metric['severity']
        description_en = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "No description.")
        
        cpes = []
        if 'configurations' in cve:
            for config in cve['configurations']:
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable', False):
                            cpes.append(match.get('criteria'))

        processed_list.append({
            "cve_id": cve['id'], 
            "published_date": cve['published'], 
            "description_en": description_en, 
            "cvss_score": cvss_score, 
            "severity": severity, 
            "exploit_available": item.get('exploit_available', False),
            "cpes": cpes
        })
    return processed_list

def update_cves(days=None):
    settings = load_settings()
    if not settings: return {"error": "No se pudo cargar la configuración."}
    now_utc = datetime.now(timezone.utc)
    if days is None: 
        print("--- INICIANDO ACTUALIZACIÓN INCREMENTAL ---")
        start_date = datetime.fromisoformat(settings.get('last_run_utc', '2020-01-01T00:00:00Z').replace('Z', '+00:00'))
    else: 
        print(f"--- INICIANDO ACTUALIZACIÓN MANUAL ({days} días) ---")
        start_date = now_utc - timedelta(days=days)
    
    # Forzamos el reprocesamiento para asegurar que los CPEs se guarden
    # This line was changed from the original to ensure all CVEs are processed, not just new ones.
    # If you only want to process new CVEs, revert this line to: 
    # raw_nvd_cves = fetch_nvd_data(start_date, now_utc, settings)
    raw_nvd_cves = fetch_nvd_data(start_date, now_utc, settings)
    print(f"[NVD] Se obtuvieron {len(raw_nvd_cves)} registros en total.")
    if not raw_nvd_cves:
        return {"cves_fetched_from_nvd": 0, "new_cves_to_be_saved": [], "exploits_found": 0}

    # This section was commented out to ensure all CVEs are processed, not just new ones.
    # If you only want to process new CVEs, uncomment this section and comment out the line above.
    # new_raw_cves = [cve for cve in raw_nvd_cves if cve['cve']['id'] not in existing_cve_ids]
    # print(f"[FILTER] Se encontraron {len(new_raw_cves)} nuevos CVEs para procesar.")

    # if not new_raw_cves:
    #     return {"cves_fetched_from_nvd": len(raw_nvd_cves), "new_cves_to_be_saved": [], "exploits_found": 0}

    cves_with_exploit_info = check_exploit_availability(raw_nvd_cves)
    cves_for_db = process_cves_for_db(cves_with_exploit_info)
    
    # Enrich before saving
    enriched_cves = enrich_with_external_apis(cves_for_db, settings)

    save_cves_to_db(enriched_cves)

    cves_for_frontend = []
    for cve in enriched_cves:
        cve['simplified_description'] = simplify_cve_description(cve['description_en'], cve['severity'])
        cve['description_es'] = f"[Traducción Simulada] {cve['description_en']}"
        cves_for_frontend.append(cve)

    if days is None: settings['last_run_utc'] = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ'); save_settings(settings)

    stats = {"cves_fetched_from_nvd": len(raw_nvd_cves), "new_cves_to_be_saved": cves_for_frontend, "exploits_found": sum(1 for cve in cves_for_frontend if cve['exploit_available'])}
    print("\n--- PROCESO DE ACTUALIZACIÓN FINALIZADO ---")
    return stats
