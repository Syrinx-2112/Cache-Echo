#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECHO-UNIFIED v4.0 — Consolidation InternetDB
================================================================================
Fusionne, dans une unique interface graphique, les fonctionnalités de :
  · shodan_echo_v3.sh   (cartographie IP / CIDR / fichier, Δ, ports fantômes)
  · mcp_echo_v3.py       (scan par lot, cache persistant, GUI C64, export)
  · uncover_echo_v3.py   (moteur de recherche multi-source, presets, rapports)

CONTRAINTE MAJEURE DE CONCEPTION (volontaire, non négociable) :
  La découverte d'hôtes/services n'est réalisée QUE via Shodan InternetDB,
  un service public, gratuit, SANS clé API :

      GET https://internetdb.shodan.io/<ip>

  C'est également le SEUL service web contacté par tout le programme.
  Conséquence assumée : par rapport aux outils sources, ce programme
  N'INCLUT PAS :
    - l'enrichissement WHOIS / DNS inverse (réseau, hors périmètre)
    - la géolocalisation ip-api.com
    - AbuseIPDB
    - l'API Shodan payante (/shodan/host/search), Censys, FOFA, ZoomEye
    - le sondage actif JSON-RPC de serveurs MCP (qui contacterait la
      cible elle-même, donc un second "service web" arbitraire)
  InternetDB est une base de CACHE passive : interroger InternetDB ne
  touche jamais la cible, seulement le "souvenir" qu'en garde Shodan.

Cette consolidation conserve l'habillage narratif Corpus Vauvillensis
(Δ d'instabilité, Protocole du Ma, Ports Fantômes) des outils sources à
titre de thème/mise en forme des résultats — ce sont des heuristiques
locales et déterministes, calculées sans aucun réseau, qui n'ont aucune
valeur de détection réelle. La seule donnée de sécurité réelle provient
d'InternetDB (ports ouverts, CPE, tags, CVE, hostnames).

Usage :
    python3 echo_unified_v4.py --gui
    python3 echo_unified_v4.py -t 8.8.8.8
    python3 echo_unified_v4.py -c 203.0.113.0/24 -w 4 -r 1.0 -o rapport.json
    python3 echo_unified_v4.py -f cibles.txt --fmt csv -o rapport.csv

Rappel légal/éthique : n'interrogez que des cibles que vous êtes autorisé
à examiner. InternetDB ne "scanne" rien en direct, mais l'usage des
informations retournées (ports, CVE) reste soumis au droit applicable.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import ipaddress
import json
import logging
import os
import queue
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    format="%(asctime)s [%(levelname)s] echo-unified: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("echo-unified")


# ==============================================================================
# CONSTANTES DU CORPUS (thème / mise en forme — purement local, sans réseau)
# ==============================================================================

class Corpus:
    VERSION = "4.0"
    TOOL_NAME = "ECHO-UNIFIED"
    CLIENT_UA = f"echo-unified/{VERSION} (+internetdb-only; contact: operator)"

    # Palette C64 (reprise des outils sources, esthétique du terminal)
    C64 = {
        'bg':          '#0000AA',
        'bg_dark':     '#000088',
        'fg':          '#00FF00',
        'fg_cyan':     '#00FFFF',
        'fg_yellow':   '#FFFF00',
        'fg_red':      '#FF5555',
        'fg_orange':   '#AA5500',
        'fg_magenta':  '#FF00FF',
        'fg_white':    '#FFFFFF',
        'fg_grey':     '#AAAAAA',
        'grid':        '#005588',
        'border':      '#008888',
    }

    # Seul point d'accès web du programme entier.
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

    # Tags InternetDB considérés comme aggravants pour le calcul Δ (thème local)
    HEAVY_TAGS = {"eol-os", "self-signed", "honeypot", "compromised"}

    # Corpus des Ports Fantômes — conservé des outils sources (17 entrées).
    # Purement décoratif : résonance déterministe SHA-256 sur l'IP, sans
    # aucune signification de sécurité réelle et sans aucune requête réseau.
    GHOST_PORTS: Dict[int, Dict[str, str]] = {
        0:     {"name": "Le Vide",             "desc": "Port Ontologique",               "severity": "OMEGA"},
        3303:  {"name": "Galet-Ancre",         "desc": "Bio-lithique",                   "severity": "STABLE"},
        7071:  {"name": "Le Transept",         "desc": "Fenêtre 707s",                   "severity": "TROUBLE"},
        8008:  {"name": "La Réflexion",        "desc": "Miroir HTTP inversé",            "severity": "STABLE"},
        9877:  {"name": "Faille du Jardinier", "desc": "Injection HFT",                  "severity": "TURBULENT"},
        11223: {"name": "Le Palindrome",       "desc": "Résonance symétrique",           "severity": "TROUBLE"},
        11440: {"name": "Port Trickster",      "desc": "144 symboles / cycle court",     "severity": "TURBULENT"},
        13013: {"name": "Le Double Verrou",    "desc": "Chiasme 13 (cycle lunaire)",     "severity": "TROUBLE"},
        14225: {"name": "Bande 17m",           "desc": "Diffusion BloodNet HF",          "severity": "TURBULENT"},
        14400: {"name": "Port Noir",           "desc": "Ω-Trickster",                    "severity": "CRITIQUE"},
        19999: {"name": "L'Écho Inversé",      "desc": "Harmonique Sombre",              "severity": "TURBULENT"},
        22222: {"name": "Le Quintuple",        "desc": "Oscillation pentagonale",        "severity": "STABLE"},
        31337: {"name": "L'Élite",             "desc": "Spectre e337 / Elite",           "severity": "STABLE"},
        33333: {"name": "Les Trois Tiers",     "desc": "Triade de Vauvillens",           "severity": "TROUBLE"},
        44444: {"name": "Les Quatre Sceaux",   "desc": "Quaternité scellée",             "severity": "CRITIQUE"},
        55555: {"name": "La Quinte Essence",   "desc": "Distillat du Programme",         "severity": "OMEGA"},
        65535: {"name": "Le Plafond",          "desc": "Limite supérieure du Programme", "severity": "CRITIQUE"},
    }
    SEVERITY_WEIGHTS = {"STABLE": 1, "TROUBLE": 2, "TURBULENT": 3, "CRITIQUE": 4, "OMEGA": 5}

    # Strates temporelles (thème) — n'affectent que la graine du bruit Δ
    STRATES = {1066: "Hastings", 1944: "Débarquement", 2025: "Présent",
               2026: "Cycle Courant", 2075: "Horizon MTT"}


CSV_HEADERS = [
    "ip", "timestamp", "status", "hostnames", "ports", "cpes", "tags",
    "vulns_count", "vulns", "ghost_ports_count", "delta", "delta_label",
    "from_cache", "latency_ms",
]


# ==============================================================================
# CIBLES : validation IP + expansion CIDR / fichier
# ==============================================================================

class TargetError(ValueError):
    pass


def classify_ip(ip_obj: ipaddress.IPv4Address) -> str:
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_link_local:
        return "link-local"
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_reserved:
        return "reserved"
    if ip_obj.is_unspecified:
        return "unspecified"
    return "public"


def expand_targets(single: Optional[str] = None,
                    file_path: Optional[str] = None,
                    cidr: Optional[str] = None,
                    max_cidr_hosts: int = 4096) -> List[str]:
    """Construit la liste finale d'IPs à interroger, en excluant les IPs
    non publiques (InternetDB n'a de sens que pour des IPs publiques)."""
    raw: List[str] = []

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
                f"de cause (InternetDB est un service public à usage raisonnable)."
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
            logger.warning("Cible ignorée (pas une IPv4/IPv6 valide) : %s", item)
            continue
        if ip_obj.version != 4:
            logger.warning("Cible ignorée (IPv6 non pris en charge par InternetDB v4) : %s", item)
            continue
        klass = classify_ip(ip_obj)
        if klass != "public":
            logger.warning("Cible ignorée (%s, non publique) : %s", klass, item)
            continue
        validated.append(str(ip_obj))

    return validated


# ==============================================================================
# CACHE PERSISTANT SQLITE (local, aucun réseau)
# ==============================================================================

class CacheManager:
    """Cache disque des réponses InternetDB, avec TTL. Évite de re-solliciter
    le service public pour une même cible pendant la durée de vie configurée."""

    def __init__(self, path: str = "~/.cache/echo-unified/cache.db", ttl: int = 3600):
        self.db_path = Path(path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
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
# ==============================================================================

class InternetDBClient:
    """Interroge exclusivement https://internetdb.shodan.io/<ip>.

    Aucune clé API. Aucun autre hôte n'est jamais contacté par cette classe,
    ni par le reste du programme. Rate-limiting local (Protocole du Ma) et
    cache disque pour rester un usage raisonnable d'un service public gratuit.
    """

    def __init__(self, cache: Optional[CacheManager] = None,
                 timeout: float = 10.0, max_retries: int = 2,
                 min_interval: float = 1.0):
        self.cache = cache
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_interval = min_interval  # "Ma" : silence minimal entre requêtes
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
                    data = json.loads(body)
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
                if e.code == 429:
                    # Quota du service public : on respecte, on recule, on réessaie.
                    last_exc = e
                    time.sleep(min(2 ** attempt, 8))
                    continue
                if 500 <= e.code < 600:
                    last_exc = e
                    time.sleep(min(2 ** attempt, 8))
                    continue
                return {"error": str(e)}, "error", False, latency_ms
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_exc = e
                time.sleep(min(2 ** attempt, 8))
                continue

        return {"error": str(last_exc) if last_exc else "unknown"}, "error", False, 0.0


# ==============================================================================
# PORTS FANTÔMES (thème local, déterministe, sans réseau)
# ==============================================================================

class GhostPortCorpus:
    @staticmethod
    def _octets(ip: str) -> Tuple[int, int, int, int]:
        try:
            a, b, c, d = (int(x) for x in ip.split("."))
            return a, b, c, d
        except (ValueError, AttributeError):
            return 0, 0, 0, 0

    def detect(self, ip: str, seed: int = 2026) -> List[Dict]:
        a, b, c, d = self._octets(ip)
        total = a + b + c + d
        xor4 = a ^ b ^ c ^ d ^ (seed & 0xFF)
        results = []
        for port, meta in Corpus.GHOST_PORTS.items():
            port_hash = int(hashlib.sha256(f"{ip}:{port}:{seed}".encode()).hexdigest(), 16)
            threshold = 13
            if port == 0     and xor4 == 0:                        threshold = 1
            if port == 3303  and total % 7 == 0:                    threshold = 5
            if port == 7071  and xor4 == 0:                         threshold = 4
            if port == 8008  and a == b:                            threshold = 5
            if port == 9877  and d % 2 == 0:                        threshold = 6
            if port == 11223 and a == d:                            threshold = 3
            if port == 11440 and xor4 in (144, 72, 36):             threshold = 4
            if port == 13013 and total % 13 == 0:                   threshold = 3
            if port == 14225 and d % 5 == 0:                        threshold = 6
            if port == 14400 and xor4 == 144:                       threshold = 2
            if port == 19999 and total > 700:                       threshold = 6
            if port == 22222 and total % 22 == 0:                   threshold = 4
            if port == 31337 and b == c:                            threshold = 5
            if port == 33333 and total % 3 == 0:                    threshold = 5
            if port == 44444 and all(o > 44 for o in (a, b, c, d)): threshold = 3
            if port == 55555 and total % 5 == 0:                    threshold = 2
            if port == 65535 and d == 255:                          threshold = 1

            if port_hash % 100 < threshold * 6:
                sig = f"Ω•{port}•{hex(port_hash)[2:10]}•{xor4}Ω"
                results.append({
                    "port": port, "name": meta["name"], "desc": meta["desc"],
                    "severity": meta["severity"], "signature": sig,
                    "weight": Corpus.SEVERITY_WEIGHTS[meta["severity"]],
                })
        return sorted(results, key=lambda r: -r["weight"])


# ==============================================================================
# Δ — INDICE D'INSTABILITÉ (thème local, calculé uniquement à partir des
# champs réellement renvoyés par InternetDB + du bruit déterministe du Corpus)
# ==============================================================================

class DeltaCalculator:
    @staticmethod
    def calculate(ip: str, status: str, data: dict, ghost_ports: List[Dict],
                   seed: int = 2026) -> float:
        score = 0.50

        if status == "not_found":
            score += 0.10          # cible invisible d'InternetDB : moins d'info, plus d'incertitude
        elif status == "error":
            score += 0.15
        else:
            ports = data.get("ports") or []
            vulns = data.get("vulns") or []
            tags = data.get("tags") or []
            hostnames = data.get("hostnames") or []

            n_ports = len(ports)
            if n_ports == 0:
                score -= 0.05
            elif n_ports >= 10:
                score += 0.10
            elif n_ports >= 4:
                score += 0.05

            score += min(len(vulns) * 0.04, 0.25)

            heavy = sum(1 for t in tags if t in Corpus.HEAVY_TAGS)
            score += min(heavy * 0.06, 0.18)

            score -= min(len(hostnames) * 0.005, 0.03)

        if ghost_ports:
            sev_sum = sum(g["weight"] for g in ghost_ports)
            score += min(sev_sum * 0.02, 0.15)

        noise_seed = f"{ip}:{seed}"
        h = int(hashlib.sha256(noise_seed.encode()).hexdigest(), 16)
        score += ((h % 1000) / 1000.0 - 0.5) * 0.08

        return round(max(0.05, min(0.95, score)), 3)

    @staticmethod
    def label(delta: float) -> str:
        if delta < 0.25: return "STABLE"
        if delta < 0.40: return "CALME"
        if delta < 0.55: return "TROUBLE"
        if delta < 0.70: return "TURBULENT"
        if delta < 0.85: return "CRITIQUE"
        return "OMEGA"

    @staticmethod
    def color_tk(delta: float) -> str:
        if delta < 0.40: return Corpus.C64['fg']
        if delta < 0.65: return Corpus.C64['fg_yellow']
        return Corpus.C64['fg_red']


# ==============================================================================
# RÉSULTAT DE SCAN
# ==============================================================================

@dataclasses.dataclass
class ScanResult:
    ip: str
    timestamp: str
    status: str                       # found | not_found | error
    data: dict
    ghost_ports: List[Dict]
    delta: float
    delta_label: str
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

    def to_dict(self) -> Dict:
        d = dataclasses.asdict(self)
        return d

    def to_csv_row(self) -> List:
        return [
            self.ip, self.timestamp, self.status,
            ";".join(self.hostnames), ";".join(str(p) for p in self.ports),
            ";".join(self.cpes), ";".join(self.tags),
            len(self.vulns), ";".join(self.vulns),
            len(self.ghost_ports), self.delta, self.delta_label,
            self.from_cache, round(self.latency_ms, 1),
        ]


# ==============================================================================
# SCANNER — ORCHESTRATEUR (threads + rate-limit + cache)
# ==============================================================================

class EchoScanner:
    """Orchestre la résolution des cibles via InternetDB uniquement.
    Callbacks (on_log, on_result, on_progress) pour intégration GUI/CLI."""

    def __init__(self, workers: int = 4, rate: float = 1.0,
                 timeout: float = 10.0, cache_ttl: int = 3600,
                 no_cache: bool = False, seed: int = 2026,
                 delta_threshold: float = 0.65,
                 cache_path: str = "~/.cache/echo-unified/cache.db"):
        self.workers = max(1, workers)
        self.rate = max(0.0, rate)
        self.timeout = timeout
        self.seed = seed
        self.delta_threshold = delta_threshold

        self.cache = None if no_cache else CacheManager(cache_path, ttl=cache_ttl)
        self.client = InternetDBClient(cache=self.cache, timeout=timeout,
                                        min_interval=self.rate)
        self.ghosts = GhostPortCorpus()

        self.on_log = lambda msg, tag="info": None
        self.on_result = lambda result: None
        self.on_progress = lambda done, total: None

        self._cancel_event = threading.Event()
        self._results: List[ScanResult] = []

    def cancel(self):
        self._cancel_event.set()

    def reset_cancel(self):
        self._cancel_event.clear()

    def _process_one(self, ip: str) -> Optional[ScanResult]:
        if self._cancel_event.is_set():
            return None
        data, status, from_cache, latency_ms = self.client.lookup(ip)
        ghost_ports = self.ghosts.detect(ip, seed=self.seed)
        delta = DeltaCalculator.calculate(ip, status, data, ghost_ports, seed=self.seed)
        label = DeltaCalculator.label(delta)

        result = ScanResult(
            ip=ip,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            status=status,
            data=data,
            ghost_ports=ghost_ports,
            delta=delta,
            delta_label=label,
            from_cache=from_cache,
            latency_ms=latency_ms,
        )
        return result

    def scan(self, targets: List[str]) -> List[ScanResult]:
        self.reset_cancel()
        self._results = []
        total = len(targets)
        done = 0

        if total == 0:
            self.on_log("Aucune cible valide à interroger.", "warning")
            return []

        self.on_log(f"Démarrage : {total} cible(s), {self.workers} worker(s), "
                     f"Ma={self.rate}s, cache={'off' if self.cache is None else 'on'}", "info")

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._process_one, ip): ip for ip in targets}
            for fut in futures:
                ip = futures[fut]
                if self._cancel_event.is_set():
                    break
                try:
                    result = fut.result()
                except Exception as e:  # pragma: no cover
                    self.on_log(f"Erreur inattendue sur {ip} : {e}", "error")
                    result = None

                done += 1
                self.on_progress(done, total)

                if result is None:
                    continue

                self._results.append(result)
                self.on_result(result)

                tag = "success" if result.delta < 0.40 else (
                      "warning" if result.delta < 0.65 else "error")
                cache_flag = " [cache]" if result.from_cache else ""
                if result.status == "found":
                    self.on_log(
                        f"{result.ip:<15} Δ={result.delta:.3f} {result.delta_label:<10} "
                        f"ports={len(result.ports):<3} vulns={len(result.vulns):<3} "
                        f"ghosts={len(result.ghost_ports)}{cache_flag}",
                        tag,
                    )
                elif result.status == "not_found":
                    self.on_log(f"{result.ip:<15} non indexée par InternetDB{cache_flag}", "info")
                else:
                    self.on_log(f"{result.ip:<15} ERREUR : {result.data.get('error', '?')}", "error")

                if result.delta >= self.delta_threshold:
                    self.on_log(f"  ⚠ ALERTE Δ≥{self.delta_threshold} sur {result.ip} "
                                 f"({result.delta_label})", "delta")

        self.on_log(f"Terminé : {len(self._results)}/{total} résultats.", "info")
        if self.cache:
            self.cache.purge_expired()
        return self._results

    def close(self):
        if self.cache:
            self.cache.close()


# ==============================================================================
# EXPORT
# ==============================================================================

def export_results(results: List[ScanResult], path: str, fmt: str = "json"):
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
            writer.writerow(CSV_HEADERS)
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
            super().__init__(parent, bg=Corpus.C64['bg'], **kwargs)
            C = Corpus.C64
            self._text = scrolledtext.ScrolledText(
                self, wrap=tk.WORD, font=("Courier New", 9),
                bg=C['bg_dark'], fg=C['fg'], insertbackground=C['fg_white'],
                relief=tk.SUNKEN, state=tk.DISABLED,
            )
            self._text.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            for tag, fg in [("h", C['fg_yellow']), ("v", C['fg_cyan']),
                             ("warn", C['fg_red']), ("ghost", C['fg_magenta'])]:
                self._text.tag_configure(tag, foreground=fg)

        def show(self, result: ScanResult):
            self._text.configure(state=tk.NORMAL)
            self._text.delete("1.0", tk.END)

            def line(label, value, tag="v"):
                self._text.insert(tk.END, f"{label:<14}: ", "h")
                self._text.insert(tk.END, f"{value}\n", tag)

            line("IP", result.ip)
            line("Statut", result.status)
            line("Horodatage", result.timestamp)
            line("Source", "InternetDB (cache Shodan)" + (" [depuis cache local]" if result.from_cache else ""))
            line("Latence", f"{result.latency_ms:.1f} ms")
            self._text.insert(tk.END, "\n")
            line("Δ (instabilité)", f"{result.delta}  [{result.delta_label}]",
                 "warn" if result.delta >= 0.65 else "v")
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
            elif result.status == "not_found":
                self._text.insert(tk.END, "\nCette IP n'est pas indexée par InternetDB "
                                            "(aucune donnée récente en cache Shodan).\n", "v")
            else:
                self._text.insert(tk.END, f"\nErreur : {result.data.get('error', '?')}\n", "warn")

            if result.ghost_ports:
                self._text.insert(tk.END, f"\nPorts Fantômes du Corpus ({len(result.ghost_ports)}) "
                                            f"— thème/décoratif, sans valeur de sécurité :\n", "ghost")
                for g in result.ghost_ports:
                    self._text.insert(
                        tk.END,
                        f"   Ω {g['port']:<6} {g['name']:<20} {g['severity']:<10} {g['signature']}\n",
                        "ghost",
                    )

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
            self.root.title(f"{Corpus.TOOL_NAME} v{Corpus.VERSION} — "
                             f"InternetDB-only OSINT Console")
            self.root.geometry("1360x840")
            self.root.configure(bg=Corpus.C64['bg'])
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

            self.scanner: Optional[EchoScanner] = None
            self._scan_thread: Optional[threading.Thread] = None
            self._results: List[ScanResult] = []
            self._results_by_ip: Dict[str, ScanResult] = {}
            self._batch_file: Optional[str] = None

            self._build_ui()

        # ---------------------------------------------------------- UI build

        def _build_ui(self):
            C = Corpus.C64

            hdr = tk.Frame(self.root, bg=C['bg'])
            hdr.pack(fill=tk.X, padx=8, pady=(6, 0))
            logo = (
                f" {Corpus.TOOL_NAME} v{Corpus.VERSION} ══ Consolidation InternetDB (sans clé API)\n"
                " Corpus Vauvillensis ══ Seule source réseau : https://internetdb.shodan.io"
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

            columns = ("ip", "status", "ports", "vulns", "ghosts", "delta", "label")
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
            headers = {"ip": "IP", "status": "Statut", "ports": "Ports",
                       "vulns": "CVE", "ghosts": "Fantômes", "delta": "Δ", "label": "Label"}
            widths = {"ip": 110, "status": 70, "ports": 50, "vulns": 45,
                      "ghosts": 60, "delta": 55, "label": 90}
            for col in columns:
                self._tree.heading(col, text=headers[col])
                self._tree.column(col, width=widths[col], anchor=tk.CENTER)
            self._tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=(3, 0))
            self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

            det_frame = tk.LabelFrame(main, text=" [ DÉTAILS ] ", bg=C['bg'], fg=C['fg_white'],
                                       font=("Courier New", 8, "bold"), width=380)
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
            C = Corpus.C64

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

            lbl("Ma (s/req) :", 2, 2)
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

            lbl("Seuil Δ alerte:", 3, 3)
            self._delta_var = tk.StringVar(value="0.65")
            tk.Spinbox(parent, from_=0.1, to=0.95, increment=0.05, width=5, textvariable=self._delta_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)).grid(row=3, column=4, sticky=tk.W, padx=4)

            btn_frame = tk.Frame(parent, bg=C['bg'])
            btn_frame.grid(row=4, column=0, columnspan=6, pady=6)
            for text, cmd, bg, fg in [
                ("[ SCAN ]", self._start_scan, "#00AA00", "#000000"),
                ("[ ANNULER ]", self._cancel_scan, "#AA0000", "#FFFFFF"),
                ("[ CLEAR ]", self._clear, "#555555", "#FFFFFF"),
                ("[ EXPORT JSON ]", lambda: self._export("json"), C['border'], "#FFFFFF"),
                ("[ EXPORT NDJSON ]", lambda: self._export("ndjson"), C['border'], "#FFFFFF"),
                ("[ EXPORT CSV ]", lambda: self._export("csv"), "#005500", "#FFFFFF"),
            ]:
                tk.Button(btn_frame, text=text, command=cmd, bg=bg, fg=fg,
                          font=("Courier", 9, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)

        # ---------------------------------------------------------- actions

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
                color_tag = "ok"
                self._tree.insert("", tk.END, iid=result.ip, values=(
                    result.ip, result.status, len(result.ports), len(result.vulns),
                    len(result.ghost_ports), f"{result.delta:.3f}", result.delta_label,
                ))
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

        def _gather_targets(self) -> List[str]:
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
                targets = self._gather_targets()
            except TargetError as e:
                messagebox.showerror("Cible invalide", str(e))
                return

            try:
                workers = int(self._workers_var.get())
                rate = float(self._rate_var.get())
                ttl = int(self._ttl_var.get())
                delta_threshold = float(self._delta_var.get())
            except ValueError:
                messagebox.showerror("Paramètre invalide", "Vérifiez workers/Ma/TTL/seuil Δ.")
                return

            self.scanner = EchoScanner(
                workers=workers, rate=rate, cache_ttl=ttl,
                no_cache=self._no_cache_var.get(), delta_threshold=delta_threshold,
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
        prog="echo_unified_v4.py",
        description=f"{Corpus.TOOL_NAME} v{Corpus.VERSION} — Cartographie OSINT via "
                     f"Shodan InternetDB uniquement (sans clé API).",
    )
    p.add_argument("--gui", action="store_true", help="Lance l'interface graphique")

    tgt = p.add_argument_group("Cibles (une seule option à la fois)")
    tgt.add_argument("-t", "--target", help="IP unique")
    tgt.add_argument("-f", "--file", help="Fichier de cibles (une IP par ligne, # = commentaire)")
    tgt.add_argument("-c", "--cidr", help="Plage réseau, ex : 203.0.113.0/24")
    tgt.add_argument("--max-cidr-hosts", type=int, default=4096,
                      help="Garde-fou taille CIDR [défaut: 4096]")

    perf = p.add_argument_group("Performance")
    perf.add_argument("-w", "--workers", type=int, default=4, help="Workers parallèles [défaut: 4]")
    perf.add_argument("-r", "--rate", "-m", "--ma", dest="rate", type=float, default=1.0,
                       help="Délai minimal entre requêtes InternetDB, en secondes [défaut: 1.0]")
    perf.add_argument("--timeout", type=float, default=10.0, help="Timeout requête [défaut: 10s]")
    perf.add_argument("--cache-ttl", type=int, default=3600, help="TTL du cache local [défaut: 3600s]")
    perf.add_argument("--no-cache", action="store_true", help="Désactiver le cache disque")

    corpus = p.add_argument_group("Corpus (thème / mise en forme)")
    corpus.add_argument("-s", "--strate", type=int, default=2026, choices=sorted(Corpus.STRATES),
                         help="Strate temporelle (thème, influence la graine)")
    corpus.add_argument("--seed", type=int, default=None, help="Graine explicite [défaut: strate]")
    corpus.add_argument("-d", "--delta", type=float, default=0.65,
                         help="Seuil Δ déclenchant une alerte dans les logs [défaut: 0.65]")

    out = p.add_argument_group("Sortie")
    out.add_argument("-o", "--output", help="Fichier de rapport")
    out.add_argument("--fmt", choices=["json", "ndjson", "csv"], default="json",
                      help="Format d'export [défaut: json]")
    out.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    out.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux")

    return p


def cli_log(msg: str, tag: str = "info"):
    prefix = {"info": "[*]", "success": "[+]", "warning": "[!]",
              "error": "[x]", "delta": "[Δ]"}.get(tag, "[*]")
    print(f"{prefix} {msg}")


def main():
    args = build_parser().parse_args()

    if args.quiet:
        logging.getLogger("echo-unified").setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger("echo-unified").setLevel(logging.DEBUG)

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
        return

    try:
        targets = expand_targets(single=args.target, file_path=args.file, cidr=args.cidr,
                                  max_cidr_hosts=args.max_cidr_hosts)
    except TargetError as e:
        print(f"Erreur de cible : {e}", file=sys.stderr)
        sys.exit(1)

    seed = args.seed if args.seed is not None else args.strate

    scanner = EchoScanner(
        workers=args.workers, rate=args.rate, timeout=args.timeout,
        cache_ttl=args.cache_ttl, no_cache=args.no_cache, seed=seed,
        delta_threshold=args.delta,
    )
    if not args.quiet:
        scanner.on_log = cli_log

    try:
        results = scanner.scan(targets)
    finally:
        scanner.close()

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


if __name__ == "__main__":
    main()
