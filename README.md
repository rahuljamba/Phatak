# Phatak Punjab 🚊 • Live Railway Level Crossing Intelligence Backend

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Uvicorn](https://img.shields.io/badge/Uvicorn-0.34.0-2b5b84.svg?style=flat)](https://www.uvicorn.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python)](https://python.org)
[![Render](https://img.shields.io/badge/Render-Deploy%20Ready-46E3B7.svg?style=flat&logo=render)](https://render.com)

Real-time railway level crossing intelligence and persistent WebSocket streaming backend for **Punjab, India**. Tracking **1,828+ level crossings** and **1,005+ railway track segments** across all **23 Punjab districts**.

---

## ⚡ Zero Push Notifications Philosophy

Phatak Punjab intentionally omits background push notification systems (APNs/FCM). Instead:
* **Persistent Bi-directional WebSockets (`/ws/phatak`)**: Delivers sub-second telemetry as trains enter block sections.
* **Battery & Foreground Friendly**: Connects dynamically when commuters or drivers are on the road.
* **Instant Gate Drops**: Drivers receive approaching alerts before warning sirens finish sounding.

---

## 🚀 Quick Start (Local Development)

### 1. Clone & Setup
```bash
git clone https://github.com/rahuljamba/Phatak.git
cd Phatak

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run with Uvicorn
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

* 🌐 **Landing Page**: [http://localhost:8000/](http://localhost:8000/)
* 🔍 **Health Probe**: [http://localhost:8000/health](http://localhost:8000/health)
* 📡 **API Specification**: [http://localhost:8000/apis](http://localhost:8000/apis)
* ⚡ **WebSocket Stream**: `ws://localhost:8000/ws/phatak`
* 📖 **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 📡 Endpoints Overview

| Method | Endpoint | Protocol | Description |
|---|---|---|---|
| `GET` | `/` | HTTP | Modern dark-themed dashboard & live crossing preview |
| `GET` | `/health` | HTTP | Service health status & metrics probe |
| `GET` | `/apis` | HTTP | Complete WebSocket-first API specification (JSON) |
| `WS` | `/ws/phatak` | WebSocket | Live Punjab crossing telemetry stream & subscriptions |
| `GET` | `/docs` | HTTP | Interactive Swagger UI API documentation |

---

## ☁️ Deployment on Render

This project includes a native `render.yaml` configuration.

1. Connect your GitHub repository to [Render.com](https://render.com).
2. Choose **Blueprint** deployment or deploy using the Web Service config:
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   * **Health Check Path**: `/health`

---

## 🚂 Punjab Coverage Metrics

* **Total Level Crossings**: 1,828+
* **Total Track Segments**: 1,005+
* **Covered Districts**: 23 (Amritsar, Gurdaspur, Ludhiana, Fazilka, Sangrur, Jalandhar, Bathinda, Pathankot, Patiala, SAS Nagar Mohali, etc.)
* **Tracked Stations**: DHW (Dhariwal), ABS (Abohar), DUI (Dhuri), LDH (Ludhiana), ASR (Amritsar), SASN (Mohali), and 330+ more.
