<p align="center">
  <img src="docs/screenshots/banner.png" alt="Hollownet banner">
</p>

<p align="center">
  Honeypot SSH de código abierto con inteligencia de amenazas en tiempo real y detección de anomalías por ML.<br>
  <strong>capture · analyze · detect</strong>
</p>

<p align="center">
  Desarrollado por <a href="https://kelink.dev">Kelink</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python 3.12">
  <img src="https://img.shields.io/badge/fastapi-0.111-green" alt="FastAPI">
  <img src="https://img.shields.io/badge/license-MIT-black" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-49%20passing-brightgreen" alt="49 tests passing">
  <img src="https://img.shields.io/badge/cowrie-2.9.0-orange" alt="Cowrie 2.9.0">
</p>

---

## ¿Qué es Hollownet?

Hollownet es una plataforma de honeypot SSH diseñada para capturar, analizar y clasificar ataques reales contra sistemas expuestos a internet. Cada intento de conexión es registrado, enriquecido con inteligencia de IPs, visualizado en un dashboard en tiempo real, y analizado por un pipeline de ML que detecta comportamiento anómalo.

El sistema corre completamente self-hosted en Docker Compose — sin dependencias en cloud, sin costos de infraestructura.

---

## Arquitectura

```text
Internet
    │
    ▼
Cloudflare Tunnel          ← IP real nunca expuesta
    │
    ▼
Cowrie SSH Honeypot        ← simula un servidor SSH real (puerto 2222)
    │  JSON logs
    ▼
Collector (FastAPI)        ← parsea, enriquece y persiste eventos
    │
    ├── GeoIP + AbuseIPDB  ← país, ciudad, ASN, abuse score
    │
    ├── PostgreSQL          ← almacenamiento de eventos e inteligencia de IPs
    │
    ├── Telegram Bot        ← alertas en tiempo real (brute force + login exitoso)
    │
    └── Grafana Dashboard   ← visualización en tiempo real
              │
              ▼
         ML Pipeline        ← Isolation Forest, anomaly scoring diario
```

---

## Screenshots

### Dashboard en tiempo real

![Dashboard](docs/screenshots/dashboard.png)

### Alertas Telegram

![Alertas](docs/screenshots/telegram-alerts.png)

---

## Stack

| Componente | Tecnología |
|------------|------------|
| Honeypot | Cowrie 2.9.0 |
| Collector | FastAPI + Python 3.12 |
| Base de datos | PostgreSQL 16 |
| Enriquecimiento | ip-api.com + AbuseIPDB |
| Dashboard | Grafana OSS 11.0.0 |
| Alertas | Telegram Bot API |
| ML | scikit-learn (Isolation Forest) |
| Exposición | Cloudflare Tunnel |
| Orquestación | Docker Compose |

---

## Funcionalidades

### Captura de eventos SSH

Cowrie simula un servidor SSH completo. Acepta cualquier credencial, registra sesiones, comandos ejecutados, y archivos descargados. Los logs JSON son procesados por el Collector cada 30 segundos.

Eventos capturados:
- `cowrie.login.failed` — intento de login fallido
- `cowrie.login.success` — login exitoso (credencial aceptada por el honeypot)
- `cowrie.command.input` — comando ejecutado dentro del honeypot
- `cowrie.session.file_download` — archivo descargado por el atacante

### Enriquecimiento de IPs

Cada IP atacante es enriquecida automáticamente con:
- País, ciudad, ASN via ip-api.com
- Abuse score (0-100) via AbuseIPDB
- Caché en PostgreSQL con TTL de 24hs para no exceder rate limits

### Alertas en tiempo real

El Collector evalúa cada evento y dispara alertas via Telegram:

**Brute force detectado** — 5 o más intentos de login desde la misma IP en 60 segundos:
```
🚨 Brute force detectado
IP: 185.220.101.45
País: Germany (87/100)
Intentos: 7 en 60s
```

**Login exitoso** — cualquier credencial aceptada por el honeypot:
```
⚠️ Login exitoso en honeypot
IP: 185.220.101.45
País: Germany (87/100)
Usuario: root
Password: 123456
```

Las alertas de brute force tienen un cooldown configurable de 5 minutos por IP para evitar spam en ataques sostenidos.

### Dashboard Grafana

Panels en tiempo real actualizados cada 30 segundos:
- Total de eventos y eventos en las últimas 24hs
- IPs únicas y top país atacante
- Timeline de eventos por hora
- Top 10 IPs atacantes
- Top 10 credenciales probadas
- Tabla de eventos recientes

### ML Pipeline — Detección de anomalías

Un pipeline de Isolation Forest analiza los eventos acumulados diariamente y asigna un anomaly score (0-100) a cada evento. Score 100 = comportamiento más anómalo.

Features utilizados:
- Hora del día y día de la semana
- Intentos por IP en 24hs
- Cantidad de credenciales únicas probadas por IP
- Duración de sesión
- Presencia de comandos ejecutados
- Login exitoso

El pipeline corre como container Docker con un systemd timer a las 8AM y envía un reporte diario por Telegram:

```
📊 Hollownet — Reporte diario

Eventos analizados: 1,432
IPs únicas: 87
Anomalías detectadas (score > 70): 23

🔴 Top 3 eventos más anómalos:
• IP: 45.33.32.156 | Score: 98.5 | 2026-04-08 03:14:22
• IP: 192.241.235.82 | Score: 94.1 | 2026-04-08 11:07:55
• IP: 185.220.101.45 | Score: 91.3 | 2026-04-08 22:43:10

🔑 Credencial más usada: root:123456
🌍 País más activo: China (342 eventos)
```

---

## Instalación

### Requisitos

- Docker y Docker Compose
- Python 3.12 (solo para desarrollo)
- Una cuenta Cloudflare con dominio propio (para exposición a internet)

### 1. Clonar el repositorio

```bash
git clone https://github.com/trykelink/hollownet.git
cd hollownet
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
```

Editar `.env` con los valores reales:

```env
POSTGRES_PASSWORD=tu_password_segura
DATABASE_URL=postgresql+asyncpg://hollownet:tu_password_segura@postgres:5432/hollownet
ABUSEIPDB_API_KEY=tu_api_key
TELEGRAM_BOT_TOKEN=tu_bot_token
TELEGRAM_CHAT_ID=tu_chat_id
GRAFANA_PASSWORD=tu_password_grafana
COWRIE_LOG_PATH=/cowrie/cowrie-git/var/log/cowrie/cowrie.json
ALERT_COOLDOWN_SECONDS=300
LOG_LEVEL=INFO
```

### 3. Levantar el stack

```bash
docker compose up -d
```

Esto levanta Cowrie, PostgreSQL, el Collector y Grafana. El honeypot empieza a escuchar en el puerto 2222.

### 4. Verificar que todo corre

```bash
docker ps
docker logs hollownet-collector --tail 20
```

### 5. Acceder al dashboard

El dashboard de Grafana está disponible en `http://localhost:3000` (o via SSH tunnel si accedés desde otra máquina). Login: `admin` / tu `GRAFANA_PASSWORD`.

---

## Exposición a internet con Cloudflare Tunnel

Para que el honeypot reciba tráfico real es necesario exponerlo via Cloudflare Tunnel. Esto mantiene tu IP real oculta.

```bash
# Instalar cloudflared
# https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

# Autenticar con tu cuenta Cloudflare
cloudflared tunnel login

# Crear el tunnel
cloudflared tunnel create hollownet

# Configurar el tunnel
cat > ~/.cloudflared/config.yml << EOF
tunnel: <TUNNEL_ID>
credentials-file: /home/<usuario>/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: honeypot.tu-dominio.com
    service: ssh://localhost:2222
  - service: http_status:404
EOF

# Crear el registro DNS
cloudflared tunnel route dns hollownet honeypot.tu-dominio.com

# Instalar como servicio systemd
sudo cp ~/.cloudflared/config.yml /etc/cloudflared/
sudo cp ~/.cloudflared/<TUNNEL_ID>.json /etc/cloudflared/
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

---

## ML Pipeline — Uso manual

```bash
# Correr el pipeline una vez
docker compose --profile ml up ml

# Ver logs del pipeline
docker logs hollownet-ml
```

### Scheduler automático (systemd timer)

```bash
# Crear el service
sudo nano /etc/systemd/system/hollownet-ml.service
```

```ini
[Unit]
Description=Hollownet ML Pipeline
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/ruta/a/hollownet
ExecStart=/usr/bin/docker compose --profile ml up ml
RemainAfterExit=no
```

```bash
# Crear el timer
sudo nano /etc/systemd/system/hollownet-ml.timer
```

```ini
[Unit]
Description=Hollownet ML Pipeline — cada 24hs

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hollownet-ml.timer
sudo systemctl start hollownet-ml.timer
```

---

## Comandos útiles

```bash
# Ver estado del stack
docker ps

# Logs de cada servicio
docker logs hollownet-cowrie --tail 30
docker logs hollownet-collector --tail 30
docker logs hollownet-db --tail 30

# Verificar eventos en PostgreSQL
docker exec hollownet-db psql -U hollownet -d hollownet \
  -c "SELECT COUNT(*) FROM events;"

docker exec hollownet-db psql -U hollownet -d hollownet \
  -c "SELECT src_ip, COUNT(*) as attempts FROM events GROUP BY src_ip ORDER BY attempts DESC LIMIT 10;"

# Rebuildar después de cambios
docker compose up -d --build

# Acceder a Grafana via SSH tunnel (desde otra máquina)
ssh -L 3000:localhost:3000 -N -f usuario@ip-del-servidor
# Luego abrir http://localhost:3000
```

---

## Estructura del proyecto

```text
hollownet/
├── docker-compose.yml
├── .env.example
├── cowrie/
│   └── config/                    # Configuración de Cowrie
├── collector/
│   ├── app/
│   │   ├── main.py                # FastAPI + CollectorService
│   │   ├── parser.py              # Parser de logs JSON de Cowrie
│   │   ├── enricher.py            # GeoIP + AbuseIPDB
│   │   ├── database.py            # SQLAlchemy async
│   │   ├── models.py              # Modelos de DB
│   │   └── notifier.py            # Telegram alerts
│   ├── tests/                     # 31 tests
│   ├── Dockerfile
│   ├── requirements.txt
│   └── requirements-dev.txt
├── ml/
│   ├── train.py                   # Script principal del pipeline
│   ├── features.py                # Feature extraction
│   ├── model.py                   # Isolation Forest wrapper
│   ├── database.py                # Acceso a PostgreSQL (psycopg2)
│   ├── notifier.py                # Reporte Telegram
│   ├── tests/                     # 18 tests
│   ├── Dockerfile
│   └── requirements.txt
├── grafana/
│   └── provisioning/              # Datasource y dashboard automáticos
├── docs/
│   └── screenshots/               # Banner, dashboard, alertas
├── AGENTS.md                      # Instrucciones para agentes de código
├── PROGRESS.md                    # Log de cambios
└── REVIEWER.md                    # Checklist de code review
```

---

## Schema de base de datos

### Tabla `events`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | UUID PK | Identificador interno |
| `event_id` | VARCHAR UNIQUE | UUID de Cowrie o hash del payload |
| `session` | VARCHAR | Session ID de Cowrie |
| `src_ip` | VARCHAR | IP del atacante |
| `timestamp` | TIMESTAMPTZ | Timestamp del evento |
| `protocol` | VARCHAR | `ssh` / `telnet` |
| `username` | VARCHAR | nullable |
| `password` | VARCHAR | nullable |
| `command` | TEXT | nullable |
| `raw` | JSONB | Evento completo de Cowrie |

### Tabla `ip_intel`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `ip` | VARCHAR PK | IP del atacante |
| `country` | VARCHAR | País |
| `city` | VARCHAR | Ciudad |
| `asn` | VARCHAR | ASN |
| `abuse_score` | INTEGER | 0-100 (AbuseIPDB) |
| `is_tor` | BOOLEAN | Nodo Tor |
| `updated_at` | TIMESTAMPTZ | Última actualización |

### Tabla `anomaly_scores`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `event_id` | VARCHAR PK | Referencia a `events.event_id` |
| `score` | FLOAT | 0-100 (100 = más anómalo) |
| `scored_at` | TIMESTAMPTZ | Timestamp del scoring |

---

## Tests

```bash
# Collector (31 tests)
cd collector
pip install -r requirements-dev.txt
pytest tests/ -v

# ML pipeline (18 tests)
cd ml
pip install -r requirements.txt
pytest tests/ -v
```

---

## Decisiones de diseño

**¿Por qué Cloudflare Tunnel y no exposición directa?**
El honeypot nunca expone la IP real del servidor. Todo el tráfico pasa por Cloudflare, lo que protege la infraestructura del operador de ataques dirigidos al servidor host.

**¿Por qué Isolation Forest?**
Es un algoritmo no supervisado — no requiere datos etiquetados. Dado que un honeypot nuevo no tiene ataques conocidos clasificados, el modelo aprende qué es "normal" y marca lo que se desvía. Ideal para la fase de arranque del proyecto.

**¿Por qué las credenciales no se redactan?**
Los intentos de credenciales son el dato más valioso de un honeypot SSH. Redactarlos eliminaría la capacidad de detectar ataques coordinados con diccionarios compartidos y de entrenar el modelo ML con patrones reales.

**¿Por qué PostgreSQL y no una base de datos de series temporales?**
PostgreSQL con índices en `timestamp` y `src_ip` es suficiente para el volumen de un honeypot personal o de investigación. Grafana se conecta nativamente. La migración a TimescaleDB es trivial si el volumen lo requiere.

---

## Roadmap

| Fase | Estado | Descripción |
|------|--------|-------------|
| 1 — Honeypot | ✅ | Cowrie + Cloudflare Tunnel |
| 2 — Collector | ✅ | FastAPI + PostgreSQL + enriquecimiento de IPs |
| 3 — Alertas | ✅ | Telegram Bot con cooldown configurable |
| 4 — Dashboard | ✅ | Grafana con provisioning automático |
| 5 — ML | ✅ | Isolation Forest + reporte diario |
| 6 — Panel de anomalías | 📋 | Anomaly scores en Grafana |
| 7 — Exportación | 📋 | Export de datasets para investigación |
| 8 — Multi-protocolo | 📋 | Soporte Telnet y HTTP honeypot |

---

## Licencia

MIT. Libre para usar, modificar y self-hostear.

---

<p align="center">
  Desarrollado por <a href="https://kelink.dev">Kelink</a> &nbsp;·&nbsp;
  <a href="https://kelink.dev">kelink.dev</a>
</p>