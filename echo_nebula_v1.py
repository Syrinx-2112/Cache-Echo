#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECHO-NEBULA v1.0 — Cartographie ludique des infrastructures Cloud / DevOps / IA
================================================================================
Dérivé de ECHO-UNIFIED v4.1, spécialisé dans la DÉCOUVERTE et la CLASSIFICATION
d'hôtes exposant des briques d'infrastructure Cloud-native, DevOps et IA
(agents, serveurs de modèles, bases vectorielles, protocoles type MCP...).

CONTRAINTE MAJEURE DE CONCEPTION (héritée, non négociable) :
La découverte d'hôtes/services n'est réalisée QUE via Shodan InternetDB,
un service public, gratuit, SANS clé API :
    GET https://internetdb.shodan.io/<ip>
C'est également le SEUL service web contacté par tout le programme.
InternetDB est une base de CACHE PASSIVE : interroger InternetDB ne touche
JAMAIS la cible elle-même — seulement le « souvenir » qu'en garde Shodan.

CE QUE CE PROGRAMME AJOUTE PAR RAPPORT À ECHO-UNIFIED :
- Un moteur de signatures (ports, CPE, indices de hostname) spécialisé dans
  l'identification de briques Cloud/DevOps/IA : Docker, Kubernetes, Jenkins,
  GitLab, Grafana, Prometheus, Vault, Consul, Kafka, RabbitMQ, PostgreSQL,
  Redis, Ollama, Qdrant, Milvus, Jupyter, n8N, etc.
- Un score « Stack » (0-100) et des niveaux thématiques en phases de lune/
  nébuleuse (🌑→✨🌌), pour rendre l'exploration plus lisible et plus fun.
- Des badges ludiques (🐳 🚀 🤖 ☁️ ...) et un « Rapport Constellation » qui
  résume, à la fin d'un scan, la diversité des briques rencontrées.
- Chaque correspondance est étiquetée par sa CONFIANCE : « strong » (port ou
  CPE explicite du service) ou « heuristic » (port ambigu partagé par
  plusieurs logiciels, ou simple indice dans un hostname) — pour rester
  honnête sur ce qui est certain et ce qui ne l'est pas.

CE QUE CE PROGRAMME N'INCLUT PAS (identique à ECHO-UNIFIED) :
- l'enrichissement WHOIS / DNS inverse, la géolocalisation, AbuseIPDB
- l'API Shodan payante, Censys, FOFA, ZoomEye
- tout sondage actif (JSON-RPC MCP, ping, port-scan...) de la cible elle-même

Usage :
    python3 echo_nebula_v1.py --gui
    python3 echo_nebula_v1.py -t 8.8.8.8
    python3 echo_nebula_v1.py -c 203.0.113.0/24 -w 4 -r 1.0 -o rapport.json
    python3 echo_nebula_v1.py -f cibles.txt --fmt csv -o rapport.csv

Rappel légal/éthique : n'interrogez que des cibles (IP, plages, comptes
cloud) que vous êtes autorisé à examiner. InternetDB ne « scanne » rien en
direct, mais l'usage des informations retournées (ports, CVE, empreintes de
services) reste soumis au droit applicable et aux conditions d'utilisation
de vos fournisseurs cloud.
"""
from __future__ import annotations
import argparse
import csv
import dataclasses
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    HAS_TK = True
except ImportError:
    HAS_TK = False

# ==============================================================================
# LOGGING
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] echo-nebula: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("echo-nebula")

# ==============================================================================
# CONSTANTES GÉNÉRALES / IDENTITÉ VISUELLE
# ==============================================================================
class Corpus:
    VERSION = "1.0"
    TOOL_NAME = "ECHO-NEBULA"
    TAGLINE = "Cartographie Cloud · DevOps · IA — via Shodan InternetDB uniquement"
    CLIENT_UA = f"echo-nebula/{VERSION} (+internetdb-only)"

    # Palette "Nébuleuse" : bleu nuit profond + accents cyan/violet, un clin
    # d'œil assumé au thème "Cloud" (la nébuleuse est, littéralement, un nuage).
    NEBULA = {
        'bg':         '#0B0E2A',
        'bg_dark':    '#05061A',
        'fg':         '#7CFFCB',
        'fg_cyan':    '#5AD7FF',
        'fg_yellow':  '#FFD166',
        'fg_red':     '#FF6B6B',
        'fg_orange':  '#FFA552',
        'fg_magenta': '#C77DFF',
        'fg_white':   '#F5F5FF',
        'fg_grey':    '#8890B5',
        'grid':       '#2C2F55',
        'border':     '#7A5CFF',
    }

    # Seul point d'accès web du programme entier.
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

    CSV_HEADERS = [
        "ip", "timestamp", "status", "hostnames", "ports", "cpes", "tags",
        "vulns_count", "vulns",
        "categories", "stack_score", "stack_level", "matches_count", "badges",
        "from_cache", "latency_ms",
    ]

# ==============================================================================
# CIBLES : validation IP + expansion CIDR / fichier (inchangé vs ECHO-UNIFIED)
# ==============================================================================
class TargetError(ValueError):
    pass

def classify_ip(ip_obj: ipaddress.IPv4Address) -> str:
    if ip_obj.is_loopback: return "loopback"
    if ip_obj.is_multicast: return "multicast"
    if ip_obj.is_link_local: return "link-local"
    if ip_obj.is_private: return "private"
    if ip_obj.is_reserved: return "reserved"
    if ip_obj.is_unspecified: return "unspecified"
    return "public"

def expand_targets(single: Optional[str] = None,
                   file_path: Optional[str] = None,
                   cidr: Optional[str] = None,
                   max_cidr_hosts: int = 4096) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Construit la liste finale d'IPs à interroger, en excluant les IPs
    non publiques (InternetDB n'a de sens que pour des IPs publiques)."""
    raw: List[str] = []
    rejected: List[Tuple[str, str]] = []

    if single:
        raw.append(single.strip())
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise TargetError(f"Fichier introuvable : {file_path}")
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw.append(line)
    if cidr:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise TargetError(f"CIDR invalide « {cidr} » : {e}")
        if network.version != 4:
            raise TargetError("Seul IPv4 est pris en charge pour le CIDR.")
        host_count = network.num_addresses
        if host_count > max_cidr_hosts:
            raise TargetError(
                f"Plage trop large ({host_count} adresses > {max_cidr_hosts}). "
                f"Réduisez le CIDR ou augmentez --max-cidr-hosts en connaissance "
                f"de cause (InternetDB est un service public à usage raisonnable, "
                f"et scanner en masse l'espace d'adressage d'un fournisseur cloud "
                f"peut violer ses conditions d'utilisation)."
            )
        raw.extend(str(ip) for ip in network.hosts())
        if network.num_addresses <= 2:
            raw.append(str(network.network_address))

    validated: List[str] = []
    seen = set()
    for item in raw:
        if item in seen:
            continue
        seen.add(item)
        try:
            ip_obj = ipaddress.ip_address(item)
        except ValueError:
            rejected.append((item, "Pas une adresse IPv4/IPv6 valide"))
            continue
        if ip_obj.version != 4:
            rejected.append((item, "IPv6 non pris en charge par InternetDB v4"))
            continue
        klass = classify_ip(ip_obj)
        if klass != "public":
            rejected.append((item, f"Non publique ({klass})"))
            continue
        validated.append(str(ip_obj))

    return validated, rejected

# ==============================================================================
# CACHE PERSISTANT SQLITE (local, aucun réseau) — inchangé vs ECHO-UNIFIED
# ==============================================================================
class CacheManager:
    """Cache disque des réponses InternetDB, avec TTL. Évite de re-solliciter
    le service public pour une même cible pendant la durée de vie configurée."""
    def __init__(self, path: str = "~/.cache/echo-nebula/cache.db", ttl: int = 3600):
        self.db_path = Path(path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS internetdb_cache ("
            " ip TEXT PRIMARY KEY, data TEXT NOT NULL, ts REAL NOT NULL, status TEXT NOT NULL)"
        )
        self._conn.commit()

    def get(self, ip: str) -> Optional[Tuple[dict, str]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT data, ts, status FROM internetdb_cache WHERE ip = ?", (ip,)
            )
            row = cur.fetchone()
            if not row:
                return None
            data_raw, ts, status = row
            if (time.time() - ts) > self.ttl:
                return None
            try:
                return json.loads(data_raw), status
            except json.JSONDecodeError:
                return None

    def set(self, ip: str, data: dict, status: str):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO internetdb_cache (ip, data, ts, status) VALUES (?, ?, ?, ?)",
                (ip, json.dumps(data), time.time(), status),
            )
            self._conn.commit()

    def purge_expired(self):
        cutoff = time.time() - self.ttl
        with self._lock:
            self._conn.execute("DELETE FROM internetdb_cache WHERE ts < ?", (cutoff,))
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

# ==============================================================================
# CLIENT INTERNETDB — SEUL POINT DE CONTACT RÉSEAU DE TOUT LE PROGRAMME
# (inchangé vs ECHO-UNIFIED, hormis le User-Agent)
# ==============================================================================
class InternetDBClient:
    """Interroge exclusivement https://internetdb.shodan.io/<ip>.
    Aucune clé API. Aucun autre hôte n'est jamais contacté par cette classe,
    ni par le reste du programme. Rate-limiting local et cache disque pour
    rester un usage raisonnable d'un service public gratuit."""
    def __init__(self, cache: Optional[CacheManager] = None,
                 timeout: float = 10.0, max_retries: int = 2,
                 min_interval: float = 1.0):
        self.cache = cache
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_interval = min_interval
        self._rate_lock = threading.Lock()
        self._last_call = 0.0

    def _throttle(self):
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_call
            wait = self.min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def lookup(self, ip: str, use_cache: bool = True) -> Tuple[dict, str, bool, float]:
        """Retourne (data, status, from_cache, latency_ms).
        status ∈ {"found", "not_found", "error", "invalid"}"""
        if use_cache and self.cache:
            cached = self.cache.get(ip)
            if cached is not None:
                data, status = cached
                return data, status, True, 0.0

        url = Corpus.INTERNETDB_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": Corpus.CLIENT_UA,
                                                   "Accept": "application/json"})
        last_exc: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            self._throttle()
            t0 = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    latency_ms = (time.monotonic() - t0) * 1000
                    try:
                        data = json.loads(body)
                    except json.JSONDecodeError as e:
                        last_exc = e
                        logger.warning(f"JSON invalide pour {ip} (tentative {attempt+1}) : {e}")
                        time.sleep(min(2 ** attempt, 4))
                        continue

                    if self.cache:
                        self.cache.set(ip, data, "found")
                    return data, "found", False, latency_ms

            except urllib.error.HTTPError as e:
                latency_ms = (time.monotonic() - t0) * 1000
                if e.code == 404:
                    data = {"detail": "not indexed by InternetDB"}
                    if self.cache:
                        self.cache.set(ip, data, "not_found")
                    return data, "not_found", False, latency_ms
                if e.code == 429 or 500 <= e.code < 600:
                    last_exc = e
                    time.sleep(min(2 ** attempt, 4))
                    continue
                return {"error": str(e)}, "error", False, latency_ms

            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_exc = e
                time.sleep(min(2 ** attempt, 4))
                continue

        return {"error": str(last_exc) if last_exc else "unknown"}, "error", False, 0.0

# ==============================================================================
# MOTEUR DE SIGNATURES — CŒUR DE LA SPÉCIALISATION CLOUD / DEVOPS / IA
# ==============================================================================
# Toutes les correspondances sont calculées uniquement à partir des champs
# renvoyés par InternetDB (ports, cpes, hostnames) : aucun sondage actif.
#
# Chaque signature porte une "confidence" :
#   - "strong"    : port peu ambigu, ou CPE explicite du logiciel.
#   - "heuristic" : port partagé par plusieurs logiciels courants, ou simple
#                   indice textuel dans un hostname (peut être un faux ami).
class StackSignatures:

    CATEGORIES: Dict[str, Dict[str, str]] = {
        "containers":    {"label": "Conteneurs & Orchestration",   "emoji": "🐳"},
        "cicd":          {"label": "CI/CD",                         "emoji": "🚀"},
        "observability": {"label": "Observabilité",                 "emoji": "📊"},
        "secrets_net":   {"label": "Secrets, Config & Réseau",      "emoji": "🔐"},
        "data":          {"label": "Data & Message Brokers",        "emoji": "🗄️"},
        "ai_agents":     {"label": "IA, Agents & MCP",              "emoji": "🤖"},
        "iac_cloud":     {"label": "Cloud & IaC",                   "emoji": "☁️"},
        "gateway":       {"label": "API Gateway & Proxy",           "emoji": "🌐"},
    }

    # port -> (nom, catégorie, description, confiance)
    PORT_SIGNATURES: Dict[int, Tuple[str, str, str, str]] = {
        # --- Conteneurs & Orchestration --------------------------------------
        2375:  ("Docker Engine API (non-TLS)", "containers", "API Docker exposée en clair — souvent un accès quasi total au démon.", "strong"),
        2376:  ("Docker Engine API (TLS)", "containers", "API Docker exposée, a priori avec TLS.", "strong"),
        2377:  ("Docker Swarm", "containers", "Port de gestion de cluster Docker Swarm.", "strong"),
        4243:  ("Docker Engine API (legacy)", "containers", "Ancien port historique de l'API Docker.", "heuristic"),
        6443:  ("Kubernetes API Server", "containers", "Cœur du control-plane Kubernetes.", "strong"),
        16443: ("K3s API Server", "containers", "Control-plane K3s (Kubernetes allégé).", "strong"),
        10250: ("Kubelet API", "containers", "API du kubelet — historiquement souvent mal protégée.", "strong"),
        10255: ("Kubelet (lecture seule, obsolète)", "containers", "Ancien endpoint kubelet en lecture seule.", "strong"),
        2379:  ("etcd (client)", "containers", "Datastore clé/valeur de Kubernetes — peut contenir des secrets.", "strong"),
        2380:  ("etcd (peer)", "containers", "Communication inter-nœuds etcd.", "strong"),
        4646:  ("Nomad", "containers", "API de l'orchestrateur HashiCorp Nomad.", "strong"),
        4647:  ("Nomad RPC", "containers", "Canal RPC interne Nomad.", "heuristic"),
        9001:  ("Portainer / MinIO Console", "containers", "UI d'admin conteneurs (Portainer) ou console objet MinIO — à vérifier.", "heuristic"),

        # --- CI/CD -------------------------------------------------------------
        50000: ("Jenkins (agents JNLP)", "cicd", "Canal de communication avec les agents Jenkins.", "strong"),
        8111:  ("TeamCity", "cicd", "Serveur d'intégration continue JetBrains.", "strong"),
        9418:  ("Git (protocole natif)", "cicd", "Dépôt Git exposé en protocole natif, souvent non authentifié.", "strong"),

        # --- Observabilité -------------------------------------------------------
        9093:  ("Alertmanager", "observability", "Gestion des alertes de l'écosystème Prometheus.", "strong"),
        9100:  ("Node Exporter", "observability", "Exporteur de métriques système pour Prometheus.", "strong"),
        5601:  ("Kibana", "observability", "Interface de visualisation de la stack Elastic.", "strong"),
        3100:  ("Loki", "observability", "Agrégateur de logs Grafana Loki.", "strong"),
        16686: ("Jaeger UI", "observability", "Interface de traçage distribué Jaeger.", "strong"),
        14268: ("Jaeger Collector", "observability", "Collecteur de traces Jaeger.", "strong"),
        9411:  ("Zipkin", "observability", "Traçage distribué Zipkin.", "strong"),
        2003:  ("Graphite (Carbon)", "observability", "Réception de métriques au format Graphite.", "strong"),
        10050: ("Zabbix Agent", "observability", "Agent de supervision Zabbix.", "strong"),
        10051: ("Zabbix Server", "observability", "Serveur de supervision Zabbix.", "strong"),
        8086:  ("InfluxDB", "observability", "Base de données de séries temporelles.", "strong"),
        9090:  ("Prometheus / Envoy Admin", "observability", "Serveur de métriques Prometheus, ou panneau d'admin du proxy Envoy.", "heuristic"),

        # --- Secrets, Config & Réseau --------------------------------------------
        8500:  ("Consul", "secrets_net", "Service discovery / configuration distribuée HashiCorp Consul.", "strong"),
        8502:  ("Consul (gRPC)", "secrets_net", "Canal gRPC de Consul.", "strong"),
        8200:  ("Vault", "secrets_net", "Gestion de secrets HashiCorp Vault.", "strong"),

        # --- API Gateway & Proxy ----------------------------------------------
        2019:  ("Caddy Admin API", "gateway", "API d'administration du serveur web Caddy.", "strong"),
        9901:  ("Envoy Admin", "gateway", "Panneau d'admin du proxy Envoy.", "strong"),
        8001:  ("Kong Admin API", "gateway", "API d'administration de l'API Gateway Kong.", "strong"),

        # --- Data & Message Brokers ---------------------------------------------
        27017: ("MongoDB", "data", "Base de données documentaire.", "strong"),
        5432:  ("PostgreSQL", "data", "Base de données relationnelle — souvent équipée de pgvector pour l'IA.", "strong"),
        3306:  ("MySQL / MariaDB", "data", "Base de données relationnelle.", "strong"),
        6379:  ("Redis", "data", "Cache / broker en mémoire, aussi utilisé comme vector store léger.", "strong"),
        9042:  ("Cassandra", "data", "Base de données distribuée à grande échelle.", "strong"),
        11211: ("Memcached", "data", "Cache mémoire distribué.", "strong"),
        5672:  ("RabbitMQ", "data", "Broker de messages AMQP.", "strong"),
        15672: ("RabbitMQ Management", "data", "Interface d'administration RabbitMQ.", "strong"),
        9092:  ("Kafka", "data", "Plateforme de streaming d'événements.", "strong"),
        2181:  ("ZooKeeper", "data", "Coordination distribuée, souvent devant un cluster Kafka.", "strong"),
        8983:  ("Apache Solr", "data", "Moteur de recherche/indexation.", "strong"),
        5984:  ("CouchDB", "data", "Base de données documentaire.", "strong"),
        8161:  ("ActiveMQ Console", "data", "Interface d'administration ActiveMQ.", "strong"),
        61616: ("ActiveMQ", "data", "Broker de messages JMS.", "strong"),
        1883:  ("MQTT", "data", "Broker de messages IoT publish/subscribe.", "strong"),
        8883:  ("MQTT (TLS)", "data", "Broker MQTT chiffré.", "strong"),
        9200:  ("Elasticsearch", "data", "Moteur de recherche/indexation — parfois utilisé comme vector store.", "strong"),
        9300:  ("Elasticsearch (transport)", "data", "Communication inter-nœuds Elasticsearch.", "strong"),

        # --- IA, Agents & MCP ---------------------------------------------------
        11434: ("Ollama", "ai_agents", "Serveur de modèles de langage auto-hébergés — très répandu chez les agents locaux.", "strong"),
        1234:  ("LM Studio", "ai_agents", "Serveur local de modèles de langage.", "strong"),
        7860:  ("Gradio / text-generation-webui", "ai_agents", "Interface web typique des démos et agents IA.", "strong"),
        5678:  ("n8n", "ai_agents", "Plateforme d'automatisation de workflows, très utilisée pour orchestrer des agents.", "strong"),
        8888:  ("Jupyter Notebook/Lab", "ai_agents", "Environnement de notebook — souvent le labo d'un agent en construction.", "strong"),
        6333:  ("Qdrant", "ai_agents", "Base de données vectorielle pour recherche sémantique / RAG.", "strong"),
        6334:  ("Qdrant (gRPC)", "ai_agents", "Canal gRPC de Qdrant.", "strong"),
        19530: ("Milvus", "ai_agents", "Base de données vectorielle à grande échelle.", "strong"),
        19121: ("Milvus (web)", "ai_agents", "Interface web de Milvus.", "strong"),
        8501:  ("Streamlit / TensorFlow Serving", "ai_agents", "Interface de démo ML (Streamlit) ou service de modèles TensorFlow.", "heuristic"),
        8000:  ("ChromaDB / vLLM / Triton / app générique", "ai_agents", "Port très utilisé par des outils IA (ChromaDB, vLLM, Triton...) mais aussi par des frameworks web génériques.", "heuristic"),
        3000:  ("Grafana / app IA (LangFuse, OpenWebUI...)", "observability", "Port par défaut de Grafana, mais aussi de nombreuses apps Node/IA (LangFuse, OpenWebUI, Flowise...).", "heuristic"),
        8080:  ("Jenkins / Kong / Nexus / app générique", "cicd", "Port ultra-partagé : Jenkins, proxy Kong, Nexus, ou simple appli web.", "heuristic"),

        # --- Cloud & IaC ---------------------------------------------------------
        8140:  ("Puppet Master", "iac_cloud", "Serveur de configuration Puppet.", "strong"),
        8006:  ("Proxmox VE", "iac_cloud", "Hyperviseur de virtualisation Proxmox.", "strong"),
        4505:  ("SaltStack (publish)", "iac_cloud", "Canal de publication SaltStack.", "strong"),
        4506:  ("SaltStack (return)", "iac_cloud", "Canal de retour SaltStack.", "strong"),
    }

    # Sous-chaîne (minuscules) trouvée dans un CPE -> (nom, catégorie)
    CPE_KEYWORDS: List[Tuple[str, str, str]] = [
        ("docker",              "Docker",                    "containers"),
        ("kubernetes",          "Kubernetes",                "containers"),
        ("hashicorp:nomad",     "Nomad",                     "containers"),
        ("jenkins",             "Jenkins",                   "cicd"),
        ("gitlab",              "GitLab",                    "cicd"),
        ("sonatype:nexus",      "Sonatype Nexus",            "cicd"),
        ("sonarqube",           "SonarQube",                 "cicd"),
        ("grafana",             "Grafana",                   "observability"),
        ("prometheus",          "Prometheus",                "observability"),
        ("elasticsearch",       "Elasticsearch",             "data"),
        ("elastic",             "Elastic Stack",             "data"),
        ("redis",               "Redis",                     "data"),
        ("postgresql",          "PostgreSQL",                "data"),
        ("mongodb",             "MongoDB",                   "data"),
        ("mysql",               "MySQL",                     "data"),
        ("rabbitmq",            "RabbitMQ",                  "data"),
        ("kafka",               "Kafka",                     "data"),
        ("nginx",                "Nginx",                     "gateway"),
        ("traefik",             "Traefik",                   "gateway"),
        ("envoy",               "Envoy",                     "gateway"),
        ("kong",                "Kong Gateway",              "gateway"),
        ("hashicorp:consul",    "Consul",                    "secrets_net"),
        ("hashicorp:vault",     "Vault",                     "secrets_net"),
        ("hashicorp:terraform", "Terraform",                 "iac_cloud"),
        ("portainer",           "Portainer",                 "containers"),
        ("harbor",              "Harbor (registre de conteneurs)", "containers"),
        ("airflow",             "Apache Airflow",            "iac_cloud"),
        ("jupyter",             "Jupyter",                   "ai_agents"),
    ]

    # Sous-chaîne (minuscules) trouvée dans un hostname -> (libellé, catégorie)
    # Toujours en confiance "heuristic" : un hostname est choisi par un humain,
    # ce n'est jamais une preuve technique.
    HOSTNAME_HINTS: List[Tuple[str, str, str]] = [
        ("k8s",         "Indice de hostname Kubernetes",   "containers"),
        ("kube",        "Indice de hostname Kubernetes",   "containers"),
        ("docker",      "Indice de hostname Docker",       "containers"),
        ("jenkins",     "Indice de hostname Jenkins",      "cicd"),
        ("gitlab",      "Indice de hostname GitLab",       "cicd"),
        ("grafana",     "Indice de hostname Grafana",      "observability"),
        ("prometheus",  "Indice de hostname Prometheus",   "observability"),
        ("ollama",      "Indice de hostname Ollama",       "ai_agents"),
        ("openwebui",   "Indice de hostname OpenWebUI",    "ai_agents"),
        ("n8n",         "Indice de hostname n8n",          "ai_agents"),
        ("mcp",         "Indice de hostname contenant « mcp »", "ai_agents"),
        ("agent",       "Indice de hostname contenant « agent »", "ai_agents"),
        ("vault",       "Indice de hostname Vault",        "secrets_net"),
        ("consul",      "Indice de hostname Consul",       "secrets_net"),
        ("airflow",     "Indice de hostname Airflow",      "iac_cloud"),
        ("terraform",   "Indice de hostname Terraform",    "iac_cloud"),
    ]

    NODEPORT_RANGE = range(30000, 32768)

    # Messages "fun" affichés une seule fois par scan, à la première rencontre
    # d'une catégorie — pour rythmer l'exploration.
    DISCOVERY_MSG: Dict[str, str] = {
        "containers":    "🐳 Une baleine passe au loin : conteneurs & orchestration en vue.",
        "cicd":          "🚀 Une fusée s'allume : pipeline CI/CD détecté.",
        "observability": "📡 Un radar se met à biper : télémétrie repérée.",
        "secrets_net":   "🔐 Un coffre scintille dans la brume réseau.",
        "data":          "🗄️ Un gisement de données affleure.",
        "ai_agents":     "🤖 Un agent IA ouvre l'œil quelque part.",
        "iac_cloud":     "☁️ Les nuages s'organisent en infrastructure.",
        "gateway":       "🌐 Une porte d'entrée API s'illumine.",
    }

    BADGE_MAP: Dict[str, str] = {
        "containers":    "🐳 Capitaine Conteneurs",
        "cicd":          "🚀 Voyageur CI/CD",
        "observability": "📊 Cartographe de Télémétrie",
        "secrets_net":   "🔐 Chercheur de Coffres",
        "data":          "🗄️ Prospecteur de Data",
        "ai_agents":     "🤖 Chuchoteur d'Agents IA",
        "iac_cloud":     "☁️ Architecte du Nuage",
        "gateway":       "🌐 Gardien de Passerelle",
    }

    @classmethod
    def detect(cls, status: str, data: dict) -> List[Dict[str, str]]:
        """Calcule la liste des correspondances Cloud/DevOps/IA, uniquement à
        partir des champs renvoyés par InternetDB. Aucun réseau ici."""
        matches: List[Dict[str, str]] = []
        if status != "found":
            return matches

        ports = data.get("ports") or []
        cpes = data.get("cpes") or []
        hostnames = data.get("hostnames") or []

        for p in ports:
            if p in cls.PORT_SIGNATURES:
                name, cat, desc, conf = cls.PORT_SIGNATURES[p]
                matches.append({"kind": "port", "key": str(p), "name": name,
                                "category": cat, "desc": desc, "confidence": conf})
            elif p in cls.NODEPORT_RANGE:
                matches.append({"kind": "port", "key": str(p),
                                "name": "Plage NodePort Kubernetes",
                                "category": "containers",
                                "desc": "Port dans la plage NodePort par défaut de Kubernetes (30000-32767).",
                                "confidence": "heuristic"})

        for cpe in cpes:
            low = cpe.lower()
            for kw, name, cat in cls.CPE_KEYWORDS:
                if kw in low:
                    matches.append({"kind": "cpe", "key": cpe, "name": name,
                                    "category": cat, "desc": f"Identifié via CPE : {cpe}",
                                    "confidence": "strong"})

        for h in hostnames:
            low = h.lower()
            for kw, label, cat in cls.HOSTNAME_HINTS:
                if kw in low:
                    matches.append({"kind": "hostname", "key": h, "name": label,
                                    "category": cat,
                                    "desc": f"Indice faible dans le hostname « {h} » — à confirmer.",
                                    "confidence": "heuristic"})

        return matches


# ==============================================================================
# ANALYSE "STACK" — score ludique, niveaux "phases de nébuleuse", badges
# (remplace le calcul Δ / Ports Fantômes d'ECHO-UNIFIED par quelque chose de
# transparent : le score ne reflète QUE la diversité/qualité des signatures
# réellement trouvées, sans bruit aléatoire.)
# ==============================================================================
class StackAnalyzer:

    LEVELS: List[Tuple[int, str]] = [
        (0,   "🌑 Silence Radio"),
        (20,  "🌒 Premier Signal"),
        (40,  "🌓 Stack en Formation"),
        (60,  "🌔 Belle Constellation"),
        (80,  "🌕 Pleine Nébuleuse"),
        (101, "✨🌌 Nova Stack"),
    ]

    @staticmethod
    def score(matches: List[Dict[str, str]]) -> int:
        if not matches:
            return 0
        cats_strong = {m["category"] for m in matches if m["confidence"] == "strong"}
        cats_all = {m["category"] for m in matches}
        n_strong = len(cats_strong)
        n_weak_only = len(cats_all - cats_strong)
        breadth_bonus = min(len(matches), 10) * 1.5
        raw = n_strong * 15 + n_weak_only * 6 + breadth_bonus
        return int(min(100, round(raw)))

    @classmethod
    def level(cls, score: int) -> str:
        label = cls.LEVELS[0][1]
        for threshold, text in cls.LEVELS:
            if score >= threshold:
                label = text
        return label

    @staticmethod
    def categories(matches: List[Dict[str, str]]) -> List[str]:
        return sorted({m["category"] for m in matches})

    @classmethod
    def badges(cls, matches: List[Dict[str, str]]) -> List[str]:
        cats = cls.categories(matches)
        out = [StackSignatures.BADGE_MAP[c] for c in cats if c in StackSignatures.BADGE_MAP]
        if len(cats) >= 5:
            out.append("🌌 Stack Complète — Full Nebula")
        return out

    @staticmethod
    def color_tk(score: int) -> str:
        C = Corpus.NEBULA
        if score == 0: return C['fg_grey']
        if score < 20: return C['fg']
        if score < 40: return C['fg_cyan']
        if score < 60: return C['fg_yellow']
        if score < 80: return C['fg_orange']
        return C['fg_magenta']

# ==============================================================================
# RÉSULTAT DE SCAN
# ==============================================================================
@dataclasses.dataclass
class ScanResult:
    ip: str
    timestamp: str
    status: str
    data: dict
    matches: List[Dict[str, str]]
    categories: List[str]
    stack_score: int
    stack_level: str
    badges: List[str]
    from_cache: bool
    latency_ms: float

    @property
    def hostnames(self) -> List[str]:
        return self.data.get("hostnames") or []

    @property
    def ports(self) -> List[int]:
        return self.data.get("ports") or []

    @property
    def cpes(self) -> List[str]:
        return self.data.get("cpes") or []

    @property
    def tags(self) -> List[str]:
        return self.data.get("tags") or []

    @property
    def vulns(self) -> List[str]:
        return self.data.get("vulns") or []

    def category_labels(self) -> List[str]:
        out = []
        for c in self.categories:
            meta = StackSignatures.CATEGORIES.get(c)
            if meta:
                out.append(f"{meta['emoji']} {meta['label']}")
        return out

    def to_dict(self) -> Dict:
        return dataclasses.asdict(self)

    def to_csv_row(self) -> List:
        return [
            self.ip, self.timestamp, self.status,
            ";".join(self.hostnames), ";".join(str(p) for p in self.ports),
            ";".join(self.cpes), ";".join(self.tags),
            len(self.vulns), ";".join(self.vulns),
            ";".join(self.category_labels()), self.stack_score, self.stack_level,
            len(self.matches), ";".join(self.badges),
            self.from_cache, round(self.latency_ms, 1),
        ]

# ==============================================================================
# SCANNER — ORCHESTRATEUR (threads + rate-limit + cache)
# ==============================================================================
class EchoScanner:
    """Orchestre la résolution des cibles via InternetDB uniquement, puis fait
    passer chaque réponse dans le moteur de signatures Cloud/DevOps/IA.
    Callbacks (on_log, on_result, on_progress) pour intégration GUI/CLI."""
    def __init__(self, workers: int = 4, rate: float = 1.0,
                 timeout: float = 10.0, cache_ttl: int = 3600,
                 no_cache: bool = False,
                 score_threshold: int = 50,
                 cache_path: str = "~/.cache/echo-nebula/cache.db"):
        self.workers = max(1, workers)
        self.rate = max(0.0, rate)
        self.timeout = timeout
        self.score_threshold = score_threshold
        self.cache = None if no_cache else CacheManager(cache_path, ttl=cache_ttl)

        if self.cache is not None:
            self.cache.purge_expired()

        self.client = InternetDBClient(cache=self.cache, timeout=timeout,
                                       min_interval=self.rate)
        self.on_log = lambda msg, tag="info": None
        self.on_result = lambda result: None
        self.on_progress = lambda done, total: None
        self._cancel_event = threading.Event()
        self._results: List[ScanResult] = []
        self._seen_categories: Set[str] = set()

    def cancel(self):
        self._cancel_event.set()

    def reset_cancel(self):
        self._cancel_event.clear()

    def _cancel_pending(self, futures: Dict[Future, str]):
        for fut in futures:
            if not fut.done() and not fut.running():
                fut.cancel()

    def _process_one(self, ip: str) -> Optional[ScanResult]:
        if self._cancel_event.is_set():
            return None
        data, status, from_cache, latency_ms = self.client.lookup(ip)
        matches = StackSignatures.detect(status, data)
        score = StackAnalyzer.score(matches)
        level = StackAnalyzer.level(score)
        cats = StackAnalyzer.categories(matches)
        badges = StackAnalyzer.badges(matches)
        return ScanResult(
            ip=ip,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            status=status,
            data=data,
            matches=matches,
            categories=cats,
            stack_score=score,
            stack_level=level,
            badges=badges,
            from_cache=from_cache,
            latency_ms=latency_ms,
        )

    def scan(self, targets: List[str]) -> List[ScanResult]:
        self.reset_cancel()
        self._results = []
        self._seen_categories = set()
        total = len(targets)
        done = 0
        if total == 0:
            self.on_log("Aucune cible valide à interroger.", "warning")
            return []

        self.on_log(f"Démarrage : {total} cible(s), {self.workers} worker(s), "
                    f"délai={self.rate}s, cache={'off' if self.cache is None else 'on'}", "info")

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._process_one, ip): ip for ip in targets}
            try:
                for fut in as_completed(futures):
                    if self._cancel_event.is_set():
                        self._cancel_pending(futures)
                        self.on_log(f"Scan annulé : {done}/{total} traités.", "warning")
                        break

                    ip = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as e:
                        if fut.cancelled():
                            continue
                        self.on_log(f"Erreur inattendue sur {ip} : {e}", "error")
                        result = None

                    done += 1
                    self.on_progress(done, total)
                    if result is None:
                        continue

                    self._results.append(result)
                    self.on_result(result)

                    tag = "success" if result.stack_score < 20 else (
                        "warning" if result.stack_score < 60 else "delta")
                    cache_flag = " [cache]" if result.from_cache else ""

                    if result.status == "found":
                        cats_str = " ".join(StackSignatures.CATEGORIES[c]["emoji"] for c in result.categories) or "—"
                        self.on_log(
                            f"{result.ip:<15} score={result.stack_score:<4} {result.stack_level:<22} "
                            f"cat={cats_str:<12} ports={len(result.ports):<3} vulns={len(result.vulns)}{cache_flag}",
                            tag,
                        )
                        for c in result.categories:
                            if c not in self._seen_categories:
                                self._seen_categories.add(c)
                                self.on_log(f"  {StackSignatures.DISCOVERY_MSG.get(c, '')}", "delta")
                    elif result.status == "not_found":
                        self.on_log(f"{result.ip:<15} non indexée par InternetDB{cache_flag}", "info")
                    else:
                        self.on_log(f"{result.ip:<15} ERREUR : {result.data.get('error', '?')}", "error")

                    if result.stack_score >= self.score_threshold:
                        self.on_log(f"  🏆 STACK NOTABLE (score≥{self.score_threshold}) sur {result.ip} "
                                    f"— {result.stack_level}", "delta")

            except KeyboardInterrupt:
                self._cancel_event.set()
                self._cancel_pending(futures)
                self.on_log(f"Scan annulé (KeyboardInterrupt) : {done}/{total} traités.", "warning")

        self.on_log(f"Terminé : {len(self._results)}/{total} résultats.", "info")
        if self.cache:
            self.cache.purge_expired()
        return self._results

    def close(self):
        if self.cache:
            self.cache.close()

# ==============================================================================
# RAPPORT CONSTELLATION — synthèse ludique en fin de scan
# ==============================================================================
def constellation_report(results: List[ScanResult]) -> str:
    """Construit un résumé texte (barres unicode) de la diversité des briques
    Cloud/DevOps/IA rencontrées sur l'ensemble du scan."""
    found = [r for r in results if r.status == "found"]
    if not found:
        return "🌑 Aucune donnée exploitable pour un rapport constellation."

    counts: Dict[str, int] = {c: 0 for c in StackSignatures.CATEGORIES}
    for r in found:
        for c in r.categories:
            counts[c] += 1

    max_count = max(counts.values()) if counts else 0
    lines = ["", "═" * 60, f" 🌌 RAPPORT CONSTELLATION — {len(found)} hôte(s) indexé(s) ", "═" * 60]
    if max_count == 0:
        lines.append("Aucune brique Cloud/DevOps/IA reconnue sur ce lot d'hôtes.")
    else:
        bar_width = 24
        for cat, meta in StackSignatures.CATEGORIES.items():
            n = counts[cat]
            filled = round((n / max_count) * bar_width) if max_count else 0
            bar = "█" * filled + "░" * (bar_width - filled)
            lines.append(f" {meta['emoji']} {meta['label']:<28} {bar} {n}")

    all_badges: Dict[str, int] = {}
    for r in found:
        for b in r.badges:
            all_badges[b] = all_badges.get(b, 0) + 1
    if all_badges:
        lines.append("")
        lines.append(" Badges débloqués sur ce lot :")
        for b, n in sorted(all_badges.items(), key=lambda kv: -kv[1]):
            lines.append(f"   {b}  (x{n})")

    top = sorted(found, key=lambda r: -r.stack_score)[:5]
    if top and top[0].stack_score > 0:
        lines.append("")
        lines.append(" Top hôtes par richesse de stack :")
        for r in top:
            if r.stack_score == 0:
                continue
            lines.append(f"   {r.ip:<16} {r.stack_score:>3}  {r.stack_level}")

    lines.append("═" * 60)
    return "\n".join(lines)

# ==============================================================================
# EXPORT
# ==============================================================================
def export_results(results: List[ScanResult], path: str, fmt: str = "json"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    fmt = fmt.lower()
    if fmt == "json":
        payload = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tool": f"{Corpus.TOOL_NAME} v{Corpus.VERSION}",
                "source": "https://internetdb.shodan.io",
                "count": len(results),
            },
            "results": [r.to_dict() for r in results],
        }
        Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "ndjson":
        with open(path, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(Corpus.CSV_HEADERS)
            for r in results:
                writer.writerow(r.to_csv_row())
    else:
        raise ValueError(f"Format d'export inconnu : {fmt}")

# ==============================================================================
# GUI TKINTER — panneau de contrôle / terminal / tableau / détails
# ==============================================================================
if HAS_TK:
    class DetailsPanel(tk.Frame):
        """Panneau de détails d'une cible sélectionnée dans le tableau."""
        def __init__(self, parent, **kwargs):
            super().__init__(parent, bg=Corpus.NEBULA['bg'], **kwargs)
            C = Corpus.NEBULA
            self._text = scrolledtext.ScrolledText(
                self, wrap=tk.WORD, font=("Courier New", 9),
                bg=C['bg_dark'], fg=C['fg'], insertbackground=C['fg_white'],
                relief=tk.SUNKEN, state=tk.DISABLED,
            )
            self._text.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            for tag, fg in [("h", C['fg_yellow']), ("v", C['fg_cyan']),
                            ("warn", C['fg_red']), ("strong", C['fg']),
                            ("weak", C['fg_grey']), ("badge", C['fg_magenta'])]:
                self._text.tag_configure(tag, foreground=fg)

        def show(self, result: ScanResult):
            self._text.configure(state=tk.NORMAL)
            self._text.delete("1.0", tk.END)
            def line(label, value, tag="v"):
                self._text.insert(tk.END, f"{label:<16}: ", "h")
                self._text.insert(tk.END, f"{value}\n", tag)

            line("IP", result.ip)
            line("Statut", result.status)
            line("Horodatage", result.timestamp)
            line("Source", "InternetDB (cache Shodan)" + (" [depuis cache local]" if result.from_cache else ""))
            line("Latence", f"{result.latency_ms:.1f} ms")
            self._text.insert(tk.END, "\n")
            line("Score Stack", f"{result.stack_score}/100  —  {result.stack_level}",
                 "warn" if result.stack_score >= 60 else "v")

            if result.badges:
                self._text.insert(tk.END, "Badges          : ", "h")
                self._text.insert(tk.END, "  ".join(result.badges) + "\n", "badge")
            self._text.insert(tk.END, "\n")

            if result.status == "found":
                line("Ports ouverts", ", ".join(str(p) for p in result.ports) or "—")
                line("Hostnames", ", ".join(result.hostnames) or "—")
                line("CPEs", ", ".join(result.cpes) or "—")
                line("Tags", ", ".join(result.tags) or "—")
                self._text.insert(tk.END, "\n")
                if result.vulns:
                    self._text.insert(tk.END, f"CVE ({len(result.vulns)}) :\n", "warn")
                    for v in result.vulns:
                        self._text.insert(tk.END, f"   · {v}\n", "warn")
                else:
                    line("CVE", "aucune")

                if result.matches:
                    self._text.insert(tk.END, f"\nBriques identifiées ({len(result.matches)}) :\n", "h")
                    by_cat: Dict[str, List[Dict[str, str]]] = {}
                    for m in result.matches:
                        by_cat.setdefault(m["category"], []).append(m)
                    for cat, ms in by_cat.items():
                        meta = StackSignatures.CATEGORIES[cat]
                        self._text.insert(tk.END, f"\n {meta['emoji']} {meta['label']}\n", "h")
                        for m in ms:
                            mark = "✓" if m["confidence"] == "strong" else "~"
                            tag = "strong" if m["confidence"] == "strong" else "weak"
                            self._text.insert(
                                tk.END,
                                f"   {mark} [{m['kind']}:{m['key']}] {m['name']}\n"
                                f"       {m['desc']}\n",
                                tag,
                            )
                else:
                    self._text.insert(tk.END, "\nAucune brique Cloud/DevOps/IA reconnue sur cet hôte.\n", "weak")
            elif result.status == "not_found":
                self._text.insert(tk.END, "\nCette IP n'est pas indexée par InternetDB "
                                  "(aucune donnée récente en cache Shodan).\n", "v")
            else:
                self._text.insert(tk.END, f"\nErreur : {result.data.get('error', '?')}\n", "warn")

            self._text.insert(tk.END, "\n--- JSON brut InternetDB ---\n", "h")
            self._text.insert(tk.END, json.dumps(result.data, indent=2, ensure_ascii=False), "v")
            self._text.configure(state=tk.DISABLED)

        def clear(self):
            self._text.configure(state=tk.NORMAL)
            self._text.delete("1.0", tk.END)
            self._text.configure(state=tk.DISABLED)

    class EchoUnifiedGUI:
        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title(f"{Corpus.TOOL_NAME} v{Corpus.VERSION} — {Corpus.TAGLINE}")
            self.root.geometry("1400x860")
            self.root.configure(bg=Corpus.NEBULA['bg'])
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
            self.scanner: Optional[EchoScanner] = None
            self._scan_thread: Optional[threading.Thread] = None
            self._results: List[ScanResult] = []
            self._results_by_ip: Dict[str, ScanResult] = {}
            self._build_ui()

        def _build_ui(self):
            C = Corpus.NEBULA
            hdr = tk.Frame(self.root, bg=C['bg'])
            hdr.pack(fill=tk.X, padx=8, pady=(6, 0))
            logo = (
                f" 🌌 {Corpus.TOOL_NAME} v{Corpus.VERSION} ══ {Corpus.TAGLINE}\n"
                " Seule source réseau : https://internetdb.shodan.io (aucun sondage actif de la cible)"
            )
            tk.Label(hdr, text=logo, fg=C['fg_cyan'], bg=C['bg'],
                     font=("Courier New", 9, "bold"), justify=tk.LEFT).pack(anchor=tk.W)

            ctrl = tk.LabelFrame(self.root, text=" [ CONTRÔLE ] ", bg=C['bg'], fg=C['fg_white'],
                                 font=("Courier New", 9, "bold"))
            ctrl.pack(fill=tk.X, padx=8, pady=4)
            self._build_controls(ctrl)

            prog_frame = tk.Frame(self.root, bg=C['bg'])
            prog_frame.pack(fill=tk.X, padx=8, pady=2)
            self._progress_var = tk.DoubleVar(value=0.0)
            self._progress_label = tk.Label(prog_frame, text="IDLE", bg=C['bg'], fg=C['fg_grey'],
                                            font=("Courier", 8))
            self._progress_label.pack(side=tk.LEFT, padx=4)
            self._progress_bar = ttk.Progressbar(prog_frame, variable=self._progress_var,
                                                 maximum=100, length=320)
            self._progress_bar.pack(side=tk.LEFT, padx=4)

            main = tk.Frame(self.root, bg=C['bg'])
            main.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

            term_frame = tk.LabelFrame(main, text=" [ TERMINAL ] ", bg=C['bg'], fg=C['fg_white'],
                                       font=("Courier New", 8, "bold"))
            term_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self._terminal = scrolledtext.ScrolledText(
                term_frame, wrap=tk.WORD, font=("Courier New", 9),
                bg=C['bg_dark'], fg=C['fg'], insertbackground=C['fg_white'], relief=tk.SUNKEN,
            )
            self._terminal.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            for tag, fg in [("info", C['fg_cyan']), ("success", C['fg']),
                            ("warning", C['fg_yellow']), ("error", C['fg_red']),
                            ("delta", C['fg_magenta'])]:
                self._terminal.tag_configure(tag, foreground=fg)

            table_frame = tk.LabelFrame(main, text=" [ RÉSULTATS ] ", bg=C['bg'], fg=C['fg_white'],
                                        font=("Courier New", 8, "bold"))
            table_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            columns = ("ip", "status", "ports", "vulns", "categories", "score", "level")
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
            style.configure("Echo.Treeview", background=C['bg_dark'], fieldbackground=C['bg_dark'],
                            foreground=C['fg'], font=("Courier New", 9))
            style.configure("Echo.Treeview.Heading", background=C['bg'], foreground=C['fg_yellow'],
                            font=("Courier New", 9, "bold"))
            self._tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                      style="Echo.Treeview", height=18)
            headers = {"ip": "IP", "status": "Statut", "ports": "Ports", "vulns": "CVE",
                       "categories": "Catégories", "score": "Score", "level": "Niveau"}
            widths = {"ip": 110, "status": 65, "ports": 50, "vulns": 40,
                      "categories": 110, "score": 50, "level": 150}
            for col in columns:
                self._tree.heading(col, text=headers[col])
                self._tree.column(col, width=widths[col], anchor=tk.CENTER)
            self._tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=(3, 0))
            self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

            self._tree.tag_configure("ok", foreground=C['fg_grey'])
            self._tree.tag_configure("warn", foreground=C['fg_yellow'])
            self._tree.tag_configure("critical", foreground=C['fg_magenta'])

            det_frame = tk.LabelFrame(main, text=" [ DÉTAILS ] ", bg=C['bg'], fg=C['fg_white'],
                                      font=("Courier New", 8, "bold"))
            det_frame.pack_propagate(False)
            det_frame.configure(width=400)
            det_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 0))
            self._details = DetailsPanel(det_frame)
            self._details.pack(fill=tk.BOTH, expand=True)

            self._status = tk.Label(
                self.root,
                text=f"READY.  {Corpus.TOOL_NAME} v{Corpus.VERSION}  |  source unique : internetdb.shodan.io",
                bg=C['bg_dark'], fg=C['fg'], font=("Courier", 8), anchor=tk.W,
            )
            self._status.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=2)

        def _build_controls(self, parent):
            C = Corpus.NEBULA
            def lbl(text, row, col):
                tk.Label(parent, text=text, bg=C['bg'], fg=C['fg_yellow'],
                         font=("Courier", 9)).grid(row=row, column=col, sticky=tk.W, padx=6, pady=2)

            lbl("Mode cible :", 0, 0)
            self._mode_var = tk.StringVar(value="ip")
            mode_frame = tk.Frame(parent, bg=C['bg'])
            mode_frame.grid(row=0, column=1, sticky=tk.W)
            for text, val in [("IP unique", "ip"), ("Fichier", "file"), ("CIDR", "cidr")]:
                tk.Radiobutton(mode_frame, text=text, variable=self._mode_var, value=val,
                               bg=C['bg'], fg=C['fg'], selectcolor=C['bg_dark'],
                               font=("Courier", 9)).pack(side=tk.LEFT, padx=2)

            lbl("Cible :", 1, 0)
            self._target_entry = tk.Entry(parent, width=34, bg=C['bg_dark'], fg=C['fg_cyan'],
                                          font=("Courier", 9))
            self._target_entry.grid(row=1, column=1, sticky=tk.W, padx=4, pady=2)
            self._target_entry.insert(0, "8.8.8.8")
            tk.Button(parent, text="[ Parcourir ]", command=self._pick_file,
                      bg=C['fg_orange'], fg="#000000", font=("Courier", 8, "bold"),
                      relief=tk.FLAT).grid(row=1, column=2, sticky=tk.W, padx=4)

            lbl("Workers :", 2, 0)
            self._workers_var = tk.StringVar(value="4")
            tk.Spinbox(parent, from_=1, to=20, width=5, textvariable=self._workers_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)).grid(row=2, column=1, sticky=tk.W, padx=4)

            lbl("Délai (s/req) :", 2, 2)
            self._rate_var = tk.StringVar(value="1.0")
            tk.Spinbox(parent, from_=0.0, to=10.0, increment=0.1, width=5, textvariable=self._rate_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)).grid(row=2, column=3, sticky=tk.W, padx=4)

            lbl("Cache TTL(s):", 3, 0)
            self._ttl_var = tk.StringVar(value="3600")
            tk.Spinbox(parent, from_=0, to=86400, increment=60, width=7, textvariable=self._ttl_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)).grid(row=3, column=1, sticky=tk.W, padx=4)
            self._no_cache_var = tk.BooleanVar(value=False)
            tk.Checkbutton(parent, text="Désactiver cache", variable=self._no_cache_var,
                           bg=C['bg'], fg=C['fg'], selectcolor=C['bg_dark'],
                           font=("Courier", 9)).grid(row=3, column=2, sticky=tk.W, padx=6)

            lbl("Seuil score 🏆:", 3, 3)
            self._score_var = tk.StringVar(value="50")
            tk.Spinbox(parent, from_=0, to=100, increment=5, width=5, textvariable=self._score_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)).grid(row=3, column=4, sticky=tk.W, padx=4)

            btn_frame = tk.Frame(parent, bg=C['bg'])
            btn_frame.grid(row=4, column=0, columnspan=6, pady=6)
            for text, cmd, bg, fg in [
                ("[ SCAN ]", self._start_scan, "#00AA55", "#000000"),
                ("[ ANNULER ]", self._cancel_scan, "#AA3355", "#FFFFFF"),
                ("[ CLEAR ]", self._clear, "#555555", "#FFFFFF"),
                ("[ 🌌 CONSTELLATION ]", self._show_constellation, C['border'], "#FFFFFF"),
                ("[ EXPORT JSON ]", lambda: self._export("json"), "#2C2F70", "#FFFFFF"),
                ("[ EXPORT NDJSON ]", lambda: self._export("ndjson"), "#2C2F70", "#FFFFFF"),
                ("[ EXPORT CSV ]", lambda: self._export("csv"), "#215522", "#FFFFFF"),
            ]:
                tk.Button(btn_frame, text=text, command=cmd, bg=bg, fg=fg,
                          font=("Courier", 9, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)

        def _pick_file(self):
            path = filedialog.askopenfilename(title="Fichier de cibles (une IP par ligne)")
            if path:
                self._mode_var.set("file")
                self._target_entry.delete(0, tk.END)
                self._target_entry.insert(0, path)

        def _gui_log(self, msg: str, tag: str = "info"):
            def _do():
                self._terminal.insert(tk.END, msg + "\n", tag)
                self._terminal.see(tk.END)
            self.root.after(0, _do)

        def _gui_on_result(self, result: ScanResult):
            self._results.append(result)
            self._results_by_ip[result.ip] = result
            def _do():
                if result.stack_score < 20:
                    tag = "ok"
                elif result.stack_score < 60:
                    tag = "warn"
                else:
                    tag = "critical"
                cats_str = " ".join(StackSignatures.CATEGORIES[c]["emoji"] for c in result.categories)
                self._tree.insert("", tk.END, iid=result.ip, values=(
                    result.ip, result.status, len(result.ports), len(result.vulns),
                    cats_str, result.stack_score, result.stack_level,
                ), tags=(tag,))
            self.root.after(0, _do)

        def _gui_progress(self, done: int, total: int):
            pct = done / total * 100 if total else 0
            def _do():
                self._progress_var.set(pct)
                self._progress_label.configure(text=f"{done}/{total}  {pct:.0f}%")
                self._status.configure(text=f"Scan en cours : {done}/{total} ({pct:.0f}%)")
            self.root.after(0, _do)

        def _on_row_select(self, _event=None):
            sel = self._tree.selection()
            if not sel:
                return
            ip = sel[0]
            result = self._results_by_ip.get(ip)
            if result:
                self._details.show(result)

        def _gather_targets(self) -> Tuple[List[str], List[Tuple[str, str]]]:
            mode = self._mode_var.get()
            value = self._target_entry.get().strip()
            if not value:
                raise TargetError("Aucune cible saisie.")
            if mode == "ip":
                return expand_targets(single=value)
            if mode == "file":
                return expand_targets(file_path=value)
            if mode == "cidr":
                return expand_targets(cidr=value)
            raise TargetError("Mode de cible inconnu.")

        def _start_scan(self):
            if self._scan_thread and self._scan_thread.is_alive():
                messagebox.showwarning("En cours", "Un scan est déjà en cours.")
                return
            try:
                targets, rejected = self._gather_targets()
            except TargetError as e:
                messagebox.showerror("Cible invalide", str(e))
                return

            if rejected:
                msg = f"{len(rejected)} cible(s) rejetée(s) :\n" + "\n".join(f"- {v} : {r}" for v, r in rejected)
                messagebox.showwarning("Cibles rejetées", msg)

            if not targets:
                messagebox.showinfo("Aucune cible", "Aucune cible valide à interroger.")
                return

            try:
                workers = int(self._workers_var.get())
                rate = float(self._rate_var.get())
                ttl = int(self._ttl_var.get())
                score_threshold = int(self._score_var.get())
            except ValueError:
                messagebox.showerror("Paramètre invalide", "Vérifiez workers/délai/TTL/seuil score.")
                return

            self.scanner = EchoScanner(
                workers=workers, rate=rate, cache_ttl=ttl,
                no_cache=self._no_cache_var.get(), score_threshold=score_threshold,
            )
            self.scanner.on_log = self._gui_log
            self.scanner.on_result = self._gui_on_result
            self.scanner.on_progress = self._gui_progress
            self._results = []
            self._results_by_ip = {}
            for item in self._tree.get_children():
                self._tree.delete(item)
            self._details.clear()

            def run():
                try:
                    self.scanner.scan(targets)
                finally:
                    self.scanner.close()

            self._scan_thread = threading.Thread(target=run, daemon=True)
            self._scan_thread.start()

        def _cancel_scan(self):
            if self.scanner:
                self.scanner.cancel()
                self._gui_log("Annulation demandée…", "warning")

        def _clear(self):
            self._terminal.delete("1.0", tk.END)
            for item in self._tree.get_children():
                self._tree.delete(item)
            self._results = []
            self._results_by_ip = {}
            self._details.clear()
            self._progress_var.set(0)
            self._progress_label.configure(text="IDLE")

        def _show_constellation(self):
            if not self._results:
                messagebox.showinfo("Constellation", "Aucun résultat pour l'instant.")
                return
            report = constellation_report(self._results)
            self._gui_log(report, "delta")

        def _export(self, fmt: str):
            if not self._results:
                messagebox.showinfo("Export", "Aucun résultat à exporter.")
                return
            ext = {"json": ".json", "ndjson": ".ndjson", "csv": ".csv"}[fmt]
            path = filedialog.asksaveasfilename(defaultextension=ext,
                                                filetypes=[(fmt.upper(), f"*{ext}")])
            if not path:
                return
            try:
                export_results(self._results, path, fmt)
                self._gui_log(f"Export {fmt.upper()} → {path}", "success")
            except Exception as e:
                messagebox.showerror("Erreur export", str(e))

        def _on_close(self):
            if self.scanner:
                self.scanner.cancel()
            self.root.destroy()

# ==============================================================================
# CLI
# ==============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="echo_nebula_v1.py",
        description=f"{Corpus.TOOL_NAME} v{Corpus.VERSION} — {Corpus.TAGLINE}. "
                    f"Découvre et classe des briques Cloud/DevOps/IA (Docker, Kubernetes, "
                    f"Jenkins, Grafana, Vault, Kafka, Ollama, Qdrant...) exposées par des "
                    f"hôtes publics, via Shodan InternetDB uniquement (sans clé API). "
                    f"Cibles (une seule option à la fois) : -t, -f, -c",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {Corpus.VERSION}")
    p.add_argument("--gui", action="store_true", help="Lance l'interface graphique")

    tgt = p.add_mutually_exclusive_group(required=False)
    tgt.add_argument("-t", "--target", help="IP unique")
    tgt.add_argument("-f", "--file", help="Fichier de cibles (une IP par ligne, # = commentaire)")
    tgt.add_argument("-c", "--cidr", help="Plage réseau, ex : 203.0.113.0/24")

    p.add_argument("--max-cidr-hosts", type=int, default=4096,
                   help="Garde-fou taille CIDR [défaut: 4096]")

    perf = p.add_argument_group("Performance")
    perf.add_argument("-w", "--workers", type=int, default=4, help="Workers parallèles [défaut: 4]")
    perf.add_argument("-r", "--rate", type=float, default=1.0,
                      help="Délai minimal entre requêtes InternetDB, en secondes [défaut: 1.0]")
    perf.add_argument("--timeout", type=float, default=10.0, help="Timeout requête [défaut: 10s]")
    perf.add_argument("--cache-ttl", type=int, default=3600, help="TTL du cache local [défaut: 3600s]")
    perf.add_argument("--no-cache", action="store_true", help="Désactiver le cache disque")

    stack = p.add_argument_group("Stack / thème")
    stack.add_argument("-d", "--score-threshold", type=int, default=50,
                       help="Seuil de score Stack déclenchant une alerte 🏆 dans les logs [défaut: 50]")
    stack.add_argument("--no-constellation", action="store_true",
                       help="Ne pas afficher le rapport constellation en fin de scan CLI")

    out = p.add_argument_group("Sortie")
    out.add_argument("-o", "--output", help="Fichier de rapport")
    out.add_argument("--fmt", choices=["json", "ndjson", "csv"], default="json",
                     help="Format d'export [défaut: json]")
    out.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    out.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux")
    return p

def cli_log(msg: str, tag: str = "info"):
    prefix = {"info": "[*]", "success": "[+]", "warning": "[!]",
              "error": "[x]", "delta": "[✨]"}.get(tag, "[*]")
    print(f"{prefix} {msg}")

def main():
    args = build_parser().parse_args()
    if args.quiet:
        logging.getLogger("echo-nebula").setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger("echo-nebula").setLevel(logging.DEBUG)

    no_target_given = not (args.target or args.file or args.cidr)
    if args.gui or no_target_given:
        if not HAS_TK:
            print("tkinter n'est pas disponible dans cet environnement Python. "
                  "Installez-le (ex : `sudo apt install python3-tk`) ou utilisez le "
                  "mode CLI avec -t/-f/-c.", file=sys.stderr)
            sys.exit(1)
        root = tk.Tk()
        EchoUnifiedGUI(root)
        root.mainloop()
        sys.exit(0)

    try:
        targets, rejected = expand_targets(single=args.target, file_path=args.file, cidr=args.cidr,
                                           max_cidr_hosts=args.max_cidr_hosts)
    except TargetError as e:
        print(f"Erreur de cible : {e}", file=sys.stderr)
        sys.exit(1)

    if rejected:
        print(f"[!] {len(rejected)} cible(s) rejetée(s) :", file=sys.stderr)
        for val, reason in rejected:
            print(f"    - {val} : {reason}", file=sys.stderr)

    if not targets:
        print("Aucune cible valide à interroger.", file=sys.stderr)
        sys.exit(1)

    scanner = EchoScanner(
        workers=args.workers, rate=args.rate, timeout=args.timeout,
        cache_ttl=args.cache_ttl, no_cache=args.no_cache,
        score_threshold=args.score_threshold,
    )
    if not args.quiet:
        scanner.on_log = cli_log

    try:
        results = scanner.scan(targets)
    finally:
        scanner.close()

    if not args.quiet and not args.no_constellation:
        print(constellation_report(results))

    if args.output:
        export_results(results, args.output, args.fmt)
        if not args.quiet:
            print(f"[✓] Export {args.fmt.upper()} → {args.output}")
    else:
        payload = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tool": f"{Corpus.TOOL_NAME} v{Corpus.VERSION}",
                "source": "https://internetdb.shodan.io",
                "count": len(results),
            },
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    if len(results) == 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
