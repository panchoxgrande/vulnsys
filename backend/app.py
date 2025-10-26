import json
import os
import traceback
import requests
import io
import time
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import psycopg2
from psycopg2.extras import execute_values

# Módulos locales
from modules.cve_collector import cve_collector
from modules.risk_engine import risk_engine
import database

# --- App Setup ---
app = Flask(__name__)
CORS(app)

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
AGENT_SECRET_TOKEN = os.getenv("AGENT_SECRET_TOKEN", "default-secret-for-dev")

# --- Lógica de Utilidad ---
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

def translate_to_spanish(text):
    if not text: return "No hay descripción disponible."
    return f"[Traducción Simulada] {text}"

# --- Rutas de API ---

@app.route('/api/generate_agent', methods=['GET'])
def generate_agent():
    os_type = request.args.get('os', 'windows')
    server_ip = request.args.get('server_ip', '127.0.0.1')
    server_url = f"http://{server_ip}:5000/api/ingest"
    if os_type not in ['windows', 'linux']: return jsonify({"error": "OS no soportado"}), 400
    template_path = os.path.join(os.path.dirname(__file__), '..', 'agents', os_type, f'agent_{os_type}.py')
    try:
        with open(template_path, 'r', encoding='utf-8') as f: template_content = f.read()
        script_content = template_content.replace('__SERVER_URL__', server_url).replace('__AGENT_TOKEN__', AGENT_SECRET_TOKEN)
        return send_file(io.BytesIO(script_content.encode('utf-8')), as_attachment=True, download_name=f'agent_{os_type}.py', mimetype='text/x-python')
    except Exception as e:
        print(f"[AGENT GEN ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        with open(SETTINGS_FILE, 'r') as f: return jsonify(json.load(f))
    except Exception as e: return jsonify({"error": f"Error al leer la configuración: {str(e)}"}), 500

@app.route('/api/settings', methods=['POST'])
def save_settings():
    try:
        new_settings = request.get_json()
        with open(SETTINGS_FILE, 'w') as f: json.dump(new_settings, f, indent=2)
        return jsonify({"message": "Configuración guardada con éxito."})
    except Exception as e: return jsonify({"error": f"Error al guardar la configuración: {str(e)}"}), 500

@app.route('/api/update_cves', methods=['GET'])
def api_update_cves():
    try:
        days = request.args.get('days', default=7, type=int)
        stats = cve_collector.update_cves(days=days)
        return jsonify(stats), 200
    except Exception as e: print(f"[CVE Collector] ERROR: {e}"); return jsonify({"error": str(e)}), 500

@app.route('/api/assets', methods=['GET'])
def get_assets():
    conn = None
    try:
        conn = database.get_db_connection()
        if conn is None: return jsonify([]), 500
        cur = conn.cursor()
        cur.execute("SELECT a.id, a.hostname, a.os_type, a.ip, c.name as client_name, COUNT(v.id) as vulnerability_count FROM assets a JOIN clients c ON a.client_id = c.id LEFT JOIN vulnerabilities v ON a.id = v.asset_id GROUP BY a.id, c.name ORDER BY vulnerability_count DESC, a.hostname;")
        assets = [dict(zip([desc[0] for desc in cur.description], row)) for row in cur.fetchall()]
        cur.close()
        return jsonify(assets)
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"[GET ASSETS ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(error)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities_for_asset():
    asset_id = request.args.get('asset_id', type=int)
    if not asset_id: return jsonify({"error": "asset_id es requerido"}), 400
    conn = None
    try:
        start_time = time.time()
        conn = database.get_db_connection()
        if conn is None: return jsonify([]), 500
        cur = conn.cursor()
        cur.execute("SELECT v.risk_score, c.cve_id, c.cvss_score, c.severity, c.description, c.exploit_available, c.otx_pulse_count FROM vulnerabilities v JOIN cves c ON v.cve_id = c.id WHERE v.asset_id = %s ORDER BY v.risk_score DESC;", (asset_id,))
        vulns_from_db = [dict(zip([desc[0] for desc in cur.description], row)) for row in cur.fetchall()]
        db_time = time.time() - start_time
        print(f"[PERF] DB query for asset {asset_id} took {db_time:.2f} seconds, fetched {len(vulns_from_db)} vulnerabilities.")

        vulns_for_frontend = []
        for vuln in vulns_from_db:
            vuln['description_en'] = vuln['description']
            vuln['description_es'] = translate_to_spanish(vuln['description'])
            vuln['simplified_description'] = simplify_cve_description(vuln['description'], vuln['severity'])
            vulns_for_frontend.append(vuln)
        cur.close()

        return jsonify(vulns_for_frontend)
    except Exception as e:
        print(f"[GET VULNS ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/cves', methods=['GET'])
def get_all_cves():
    conn = None
    try:
        start_time = time.time()
        conn = database.get_db_connection()
        if conn is None: return jsonify([]), 500
        cur = conn.cursor()
        cur.execute("SELECT *, otx_pulse_count FROM cves ORDER BY cvss_score DESC NULLS LAST;")
        cves_from_db = [dict(zip([desc[0] for desc in cur.description], row)) for row in cur.fetchall()]
        db_time = time.time() - start_time
        print(f"[PERF] DB query took {db_time:.2f} seconds, fetched {len(cves_from_db)} CVEs.")

        cves_for_frontend = []
        for cve in cves_from_db:
            cve['description_en'] = cve['description']
            cve['description_es'] = translate_to_spanish(cve['description'])
            cve['simplified_description'] = simplify_cve_description(cve['description'], cve['severity'])
            cve['risk_score'] = None
            cves_for_frontend.append(cve)
        cur.close()

        return jsonify(cves_for_frontend)
    except Exception as e:
        print(f"[GET ALL CVES ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/ingest', methods=['POST'])
def ingest_data():
    received_token = request.headers.get('X-Agent-Token')
    if not received_token or received_token != AGENT_SECRET_TOKEN: return jsonify({"error": "No autorizado"}), 401
    agent_data = request.get_json()
    if not agent_data or 'hostname' not in agent_data: return jsonify({"error": "Datos inválidos"}), 400
    conn = None
    try:
        conn = database.get_db_connection()
        if conn is None: return jsonify({"error": "No se pudo establecer conexión con la base de datos."} ), 500
        cur = conn.cursor()
        cur.execute("INSERT INTO clients (name) VALUES (%s) ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id;", ('Default Client',))
        client_id = cur.fetchone()[0]
        asset_info = (client_id, agent_data['hostname'], agent_data['ip'], agent_data['os'], agent_data['asset_type'])
        cur.execute("INSERT INTO assets (client_id, hostname, ip, os_type, asset_type, criticality_weight) VALUES (%s, %s, %s, %s, %s, 1.0) ON CONFLICT (client_id, hostname) DO UPDATE SET ip = EXCLUDED.ip, os_type = EXCLUDED.os_type RETURNING id;", asset_info)
        asset_id = cur.fetchone()[0]
        cur.execute("DELETE FROM software_inventory WHERE asset_id = %s;", (asset_id,))
        software_list = agent_data.get('software', [])
        if software_list:
            software_tuples = [(asset_id, s['name'], s.get('version'), s.get('vendor')) for s in software_list]
            execute_values(cur, "INSERT INTO software_inventory (asset_id, software_name, version, vendor) VALUES %s", software_tuples)
        conn.commit()
        cur.close()
        hostname = agent_data.get('hostname')
        print(f"\n[DB] Base de datos actualizada para el agente: {hostname}")
        message = "Inventario de " + hostname + " guardado en la base de datos."
        return jsonify({"message": message}), 200
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"[INGEST ERROR]\n{traceback.format_exc()}")
        if conn: conn.rollback()
        return jsonify({"error": str(error)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/correlate', methods=['POST'])
def run_correlation():
    try:
        result = risk_engine.correlate_vulnerabilities()
        return jsonify(result)
    except Exception as e:
        print(f"[CORRELATION ERROR]\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)