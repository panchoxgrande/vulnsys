-- Esquema de Base de Datos para el Sistema de Gestión de Vulnerabilidades

-- Tabla de Clientes
CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    industry VARCHAR(255),
    criticality_level VARCHAR(50) -- e.g., 'High', 'Medium', 'Low'
);

-- Tabla de Activos
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    ip VARCHAR(45), -- Supports IPv4 and IPv6
    os_type TEXT,
    asset_type VARCHAR(50) NOT NULL, -- 'server' or 'workstation'
    criticality_weight DECIMAL(3, 1) NOT NULL, -- Multiplier for risk calculation
    UNIQUE(client_id, hostname)
);

-- Tabla de Inventario de Software
CREATE TABLE software_inventory (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_name TEXT NOT NULL,
    version VARCHAR(100),
    vendor VARCHAR(255),
    UNIQUE(asset_id, software_name, version)
);

-- Tabla de CVEs (Common Vulnerabilities and Exposures)
CREATE TABLE cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL UNIQUE,
    cvss_score DECIMAL(3, 1),
    severity VARCHAR(50), -- e.g., 'Critical', 'High', 'Medium', 'Low', 'None'
    description TEXT,
    exploit_available BOOLEAN DEFAULT FALSE,
    published_date TIMESTAMP WITH TIME ZONE,
    otx_pulse_count INTEGER DEFAULT 0
);

-- Nueva tabla para almacenar los CPEs de cada CVE
CREATE TABLE cve_cpe_match (
    id SERIAL PRIMARY KEY,
    cve_id INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cpe_uri TEXT NOT NULL,
    UNIQUE(cve_id, cpe_uri)
);

-- Tabla de Vulnerabilidades detectadas en Activos
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'open', -- e.g., 'open', 'closed', 'in_progress', 'accepted'
    detected_date TIMESTAMP WITH TIME ZONE NOT NULL,
    risk_score DECIMAL(10, 2),
    UNIQUE(asset_id, cve_id)
);

-- Tabla de Matriz de Riesgo (agregado por cliente y activo)
CREATE TABLE risk_matrix (
    id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    total_risk_score DECIMAL(10, 2),
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    last_update TIMESTAMP WITH TIME ZONE,
    UNIQUE(client_id, asset_id)
);

-- Crear índices para mejorar el rendimiento de las búsquedas
CREATE INDEX idx_assets_client_id ON assets(client_id);
CREATE INDEX idx_software_inventory_asset_id ON software_inventory(asset_id);
CREATE INDEX idx_vulnerabilities_asset_id ON vulnerabilities(asset_id);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_risk_matrix_client_id ON risk_matrix(client_id);
CREATE INDEX idx_risk_matrix_asset_id ON risk_matrix(asset_id);
CREATE INDEX idx_cve_cpe_match_cve_id ON cve_cpe_match(cve_id);
