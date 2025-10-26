import psycopg2
import database # Nuestro módulo de conexión
import requests
from cpe import CPE

# --- Lógica de Enriquecimiento --- #

def enrich_with_external_apis(cves, settings):
    """Enriquece los datos de CVE con información de AlienVault."""
    print("\n[ENRICH] Enriqueciendo datos con APIs externas (OTX)... ")
    otx_api_key = settings.get('api_keys', {}).get('otx')
    if not otx_api_key:
        print("[ENRICH] ADVERTENCIA: No hay API key de OTX en la configuración.")
        return cves

    # El campo cve_id puede tener nombres diferentes dependiendo de la fuente
    for cve in cves:
        cve_id = cve.get('cve_id')
        if not cve_id: continue
        
        try:
            headers = {'X-OTX-API-KEY': otx_api_key}
            # Usamos la URL base de OTX definida en el colector
            response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                cve['otx_pulses'] = response.json().get('pulse_info', {}).get('count', 0)
            else:
                cve['otx_pulses'] = 0
        except requests.exceptions.RequestException:
            cve['otx_pulses'] = 0
    return cves

# --- Motor de Correlación --- #

def correlate_vulnerabilities():
    """
    Motor principal de correlación. Compara el inventario de software de los activos
    contra la base de datos de CVEs para encontrar vulnerabilidades usando CPE matching.
    """
    conn = None
    new_vulnerabilities_found = 0
    try:
        conn = database.get_db_connection()
        if conn is None: raise Exception("No se pudo conectar a la base de datos.")
        
        cur = conn.cursor()

        print("\n[Risk Engine] Iniciando correlación con CPE...")
        print("[Risk Engine] 1. Leyendo inventario de software y CPEs de la base de datos...")

        cur.execute("SELECT sw.id, sw.software_name, sw.vendor, sw.version, a.id as asset_id, a.asset_type FROM software_inventory sw JOIN assets a ON sw.asset_id = a.id;")
        inventory = cur.fetchall()
        
        cur.execute("SELECT c.id, c.cvss_score, c.exploit_available, cpe.cpe_uri FROM cves c JOIN cve_cpe_match cpe ON c.id = cpe.cve_id;")
        cve_cpes = cur.fetchall()

        print(f"[Risk Engine] 2. Procesando {len(inventory)} programas contra {len(cve_cpes)} CPEs de CVEs...")

        vulnerabilities_to_insert = set()
        processed_count = 0

        for sw_id, sw_name, sw_vendor, sw_version, asset_id, asset_type in inventory:
            processed_count += 1
            if processed_count % 100 == 0:
                print(f"  - Progreso: {processed_count}/{len(inventory)} programas analizados...")

            if not sw_name or not sw_vendor:
                continue

            try:
                # Crear un CPE para el software del inventario
                # Asegurarse de que los valores no sean None
                sw_vendor_str = sw_vendor or ''
                sw_name_str = sw_name or ''
                sw_version_str = sw_version or ''
                source_cpe_str = f"cpe:2.3:a:{sw_vendor_str.lower()}:{sw_name_str.lower()}:{sw_version_str.lower()}"
                source_cpe = CPE(source_cpe_str)
            except Exception as e:
                # print(f"[CPE WARNING] No se pudo crear CPE para '{sw_name}': {e}")
                continue

            for cve_db_id, cvss, exploit, cpe_uri in cve_cpes:
                try:
                    target_cpe = CPE(cpe_uri)
                    # Comparar si el CPE del inventario matchea con el CPE de la vulnerabilidad
                    if source_cpe.matches(target_cpe):
                        asset_multiplier = 2.0 if asset_type == 'server' else 1.0
                        exploit_factor = 1.5 if exploit else 1.0
                        risk_score = (float(cvss) * 10) * asset_multiplier * exploit_factor
                        # Usamos un set para evitar duplicados de (asset, cve)
                        vulnerabilities_to_insert.add((asset_id, cve_db_id, 'open', risk_score))
                        break # Pasar al siguiente software una vez que se encuentra una coincidencia de CVE

                except Exception as e:
                    # Omitir CPEs malformados en la base de datos
                    # print(f"[CPE WARNING] Omitiendo CPE malformado de la BD: '{cpe_uri}': {e}")
                    continue

        print(f"[Risk Engine] 3. Se encontraron {len(vulnerabilities_to_insert)} posibles vulnerabilidades.")

        if vulnerabilities_to_insert:
            print("[Risk Engine] 4. Guardando nuevos hallazgos en la base de datos...")
            sql_insert = "INSERT INTO vulnerabilities (asset_id, cve_id, status, risk_score, detected_date) VALUES (%s, %s, %s, %s, NOW()) ON CONFLICT (asset_id, cve_id) DO NOTHING;"
            for vuln in list(vulnerabilities_to_insert):
                cur.execute(sql_insert, vuln)
                if cur.rowcount > 0: new_vulnerabilities_found += 1

        conn.commit()
        cur.close()

        print(f"[Risk Engine] Proceso finalizado. Se añadieron {new_vulnerabilities_found} nuevas vulnerabilidades.")
        return {"new_vulnerabilities_found": new_vulnerabilities_found, "potential_vulnerabilities": len(vulnerabilities_to_insert)}

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"[Risk Engine ERROR] {error}")
        if conn: conn.rollback()
        return {"error": str(error)}
    finally:
        if conn: conn.close()
