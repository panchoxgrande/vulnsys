# VulnSys - Sistema de Gestión de Vulnerabilidades

VulnSys es una herramienta de gestión de vulnerabilidades de código abierto diseñada para ayudar a los equipos de seguridad a identificar, correlacionar y gestionar las vulnerabilidades en su infraestructura de TI.

## Características Principales

- **Base de Datos de CVEs Centralizada:** Descarga y actualiza automáticamente las vulnerabilidades desde el National Vulnerability Database (NVD).
- **Enriquecimiento de Datos:** Enriquece los datos de CVEs con información de exploits públicos de Exploit-DB y pulsos de inteligencia de amenazas de AlienVault OTX.
- **Agentes de Recolección:** Genera agentes ligeros para Windows y Linux que recolectan información del sistema y del software instalado.
- **Motor de Correlación Inteligente:** Utiliza CPE (Common Platform Enumeration) matching para correlacionar de forma precisa el software de tus equipos con las vulnerabilidades conocidas.
- **Cálculo de Riesgo:** Asigna un `risk_score` a cada vulnerabilidad para ayudar a priorizar los esfuerzos de remediación.
- **Dashboard Interactivo:** Una interfaz web para visualizar los equipos, sus vulnerabilidades y gestionar el sistema.
- **Temas Personalizables:** Soporta temas claro, oscuro y "hacker" para una mejor experiencia de usuario.
- **Despliegue Sencillo con Docker:** Todo el sistema (backend, base de datos y frontend) está containerizado para un despliegue rápido y consistente.

## Tech Stack

- **Backend:** Python, Flask
- **Base de Datos:** PostgreSQL
- **Frontend:** HTML, CSS, JavaScript, Bootstrap
- **Containerización:** Docker, Docker Compose

## Despliegue del Proyecto desde GitHub

Sigue estos pasos para desplegar la aplicación en tu propio entorno utilizando Docker.

### 1. Prerrequisitos

Asegúrate de tener instalado el siguiente software en tu sistema:

- **Para Windows:**
  - [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
  - [Git for Windows](https://git-scm.com/download/win)

- **Para Ubuntu:**
  - [Docker Engine](https://docs.docker.com/engine/install/ubuntu/)
  - [Docker Compose](https://docs.docker.com/compose/install/)
  - `git` (`sudo apt-get install git`)

### 2. Montaje Inicial de la Aplicación

**Paso 1: Clonar el Repositorio**
```bash
git clone https://github.com/panchoxgrande/vulnsys.git
```

**Paso 2: Navegar al Directorio del Proyecto**
```bash
cd vulnsys
```

**Paso 3: Construir y Levantar los Contenedores**
Desde la raíz del proyecto, ejecuta:
```bash
docker-compose up --build
```
Este comando construirá la imagen de la aplicación y levantará todos los servicios. La primera vez puede tardar unos minutos.

**Paso 4: Acceder a la Aplicación**
Una vez que los contenedores estén en funcionamiento, podrás acceder a:
- **Frontend:** `http://localhost:8080`
- **Backend API:** `http://localhost:5000`

**Paso 5: Configuración Inicial de la Base de Datos (Solo la primera vez)**
La primera vez que levantes el entorno, la base de datos estará vacía. Necesitas inicializarla:

1.  **Aplica el esquema de la base de datos:** Conéctate a la base de datos PostgreSQL con las siguientes credenciales:
    - **Host:** `localhost`
    - **Puerto:** `5432`
    - **Base de datos:** `vulnerability_manager`
    - **Usuario:** `postgres`
    - **Contraseña:** `Chino01*`
    
    Una vez conectado, ejecuta el contenido del archivo `backend/schema.sql` para crear todas las tablas.

2.  **Puebla la base de datos de CVEs:**
    - Abre el frontend en `http://localhost:8080`.
    - Usa el botón **"Buscar nuevas vulnerabilidades (CVEs)"** para iniciar la primera carga de datos. Este proceso puede tardar varios minutos.

### 3. Actualización del Sistema

Para actualizar la aplicación con los últimos cambios del repositorio de Git:

**Paso 1: Obtener los Últimos Cambios**
```bash
git pull
```

**Paso 2: Reconstruir y Reiniciar los Contenedores**
```bash
docker-compose up --build -d
```

## Estructura del Proyecto

```
.
├── agents/             # Plantillas para los agentes de recolección
├── backend/            # Código fuente de la aplicación Flask (API)
├── frontend/           # Archivos estáticos de la interfaz web
├── .gitignore          # Archivos ignorados por Git
├── Dockerfile          # Define la imagen Docker para el backend
├── docker-compose.yml  # Orquesta los servicios de la aplicación
└── README.md           # Este archivo
```
