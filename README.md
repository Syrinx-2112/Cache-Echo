# Cache-Echo

Dépôt regroupant deux variantes d'un même outil de **cartographie passive d'infrastructures**, toutes deux bâties sur une contrainte de conception volontaire et non négociable :

> **La découverte d'hôtes/services n'est réalisée QUE via Shodan InternetDB, un service public, gratuit, SANS clé API :**
> ```
> GET https://internetdb.shodan.io/<ip>
> ```
> **C'est le seul service web jamais contacté par les deux programmes.** InternetDB est une base de cache passive : l'interroger ne touche jamais la cible elle-même — seulement le « souvenir » qu'en garde Shodan.

| Fichier | Rôle |
|---|---|
| [`echo_unified_v41b.py`](./echo_unified_v41b.py) | Outil de base — consolidation générique (Δ d'instabilité, Ports Fantômes, thème « Corpus Vauvillensis ») |
| [`echo_nebula_v1.py`](./echo_nebula_v1.py) | Dérivé spécialisé — cartographie Cloud / DevOps / IA (Docker, Kubernetes, Jenkins, Vault, Ollama, Qdrant...) |
| [`rapport_echo_nebula.md`](./rapport_echo_nebula.md) | Rapport technique détaillé (architecture, configuration, points d'extension) sur `echo_nebula_v1.py` |

---

## Les deux outils en un coup d'œil

### `echo_unified_v41b.py` — ECHO-UNIFIED v4.1

Fusionne, dans une unique interface Tkinter, les fonctionnalités de `shodan_echo_v3.sh` (cartographie IP/CIDR/fichier, Δ, ports fantômes) et `uncover_echo_v3.py` (moteur de recherche multi-source, presets, rapports).

Le résultat de chaque cible est habillé par le thème narratif **Corpus Vauvillensis** :
- un **Δ (indice d'instabilité)**, score continu 0–1 calculé localement (empreinte SHA-256 déterministe sur l'IP + quelques heuristiques sur les champs InternetDB) ;
- des **Ports Fantômes**, 17 « signatures » thématiques (`Le Vide`, `Port Noir`, `L'Élite`...) déclenchées elles aussi par un calcul déterministe sans réseau ;
- une palette visuelle façon terminal C64.

**Important** : Δ et Ports Fantômes sont un habillage/thème de mise en forme, calculés 100 % localement (aucune requête réseau), **sans valeur de détection de sécurité réelle**. La seule donnée de sécurité réelle du programme provient des champs bruts renvoyés par InternetDB (`ports`, `cpes`, `hostnames`, `tags`, `vulns`).

### `echo_nebula_v1.py` — ECHO-NEBULA v1.0

Dérivé d'ECHO-UNIFIED v4.1, qui **reprend telle quelle** l'infrastructure réseau/cache/CLI/GUI (client InternetDB, cache SQLite, orchestrateur multi-thread, exports) et **remplace** le thème Δ/Ports Fantômes par un moteur d'identification orienté Cloud-native/DevOps/IA :

- un **moteur de signatures** (ports, CPE, indices de hostname) reconnaissant ~25 briques courantes : Docker, Kubernetes, Jenkins, GitLab, Grafana, Prometheus, Vault, Consul, Kafka, RabbitMQ, PostgreSQL, Redis, Ollama, Qdrant, Milvus, Jupyter, n8n, etc., réparties en 8 catégories thématiques (conteneurs, CI/CD, observabilité, secrets/réseau, data, IA/agents, cloud/IaC, gateway) ;
- chaque correspondance porte une **confiance explicite** — `strong` (port univoque ou CPE explicite) ou `heuristic` (port ambigu, simple indice de hostname) — pour rester honnête sur ce qui est certain ;
- un **Stack Score** (0–100) et des niveaux thématiques en phases de nébuleuse (`🌑 Silence Radio` → `✨🌌 Nova Stack`), calculés uniquement à partir de la diversité et de la fiabilité des signatures réellement trouvées (pas de bruit aléatoire, contrairement au Δ d'ECHO-UNIFIED) ;
- un **Rapport Constellation** en fin de scan, résumant la diversité des briques rencontrées sur l'ensemble du lot de cibles.

👉 Pour une analyse complète de son architecture (pipeline de scan, modèle de scoring, tous les paramètres CLI/GUI, points d'extension pour faire évoluer le moteur de signatures), voir **[`rapport_echo_nebula.md`](./rapport_echo_nebula.md)**.

### Comparatif rapide

| | `echo_unified_v41b.py` | `echo_nebula_v1.py` |
|---|---|---|
| Version | 4.1 | 1.0 |
| Thème résultat | Δ / Ports Fantômes / Corpus Vauvillensis | Stack Score / catégories Cloud-DevOps-IA / badges |
| Analyse | heuristique déterministe générique (SHA-256 sur l'IP) | moteur de signatures ports/CPE/hostname dédié Cloud-native |
| Confiance des correspondances | non distinguée | `strong` / `heuristic` explicite |
| Palette GUI | C64 (bleu/vert terminal) | Nébuleuse (bleu nuit/cyan/violet) |
| Source réseau | InternetDB uniquement | InternetDB uniquement |
| Cache / rate-limit / CLI / GUI | ✅ | ✅ (héritée sans changement) |

---

## Ce qui a été volontairement retiré (commun aux deux outils)

| Fonctionnalité source | Outil d'origine | Statut ici |
|---|---|---|
| `nrich` / InternetDB | `shodan_echo_v3.sh` | ✅ conservé (réécrit en Python pur, sans binaire externe) |
| WHOIS + DNS inverse | `shodan_echo_v3.sh` | ❌ retiré (2ᵉ service réseau) |
| GéoIP ip-api.com | `shodan_echo_v3.sh` | ❌ retiré |
| AbuseIPDB | `shodan_echo_v3.sh` | ❌ retiré (clé API + 2ᵉ service) |
| Handshake JSON-RPC actif MCP | `mcp_echo_v3.py` | ❌ retiré (contacterait la cible elle-même) |
| API Shodan payante / Censys / FOFA / ZoomEye | `uncover_echo_v3.py` | ❌ retiré |
| Cache, GUI, export, thème de résultats | tous | ✅ conservés (calculs 100 % locaux) |

---

## Installation

Aucune dépendance externe obligatoire pour les deux outils : uniquement la bibliothèque standard Python 3 (`urllib`, `sqlite3`, `ipaddress`, `argparse`, `threading`) + `tkinter` pour la GUI.

```bash
# Sur la plupart des distributions, tkinter doit être installé séparément :
sudo apt install python3-tk   # Debian/Ubuntu
```

---

## Usage

### `echo_nebula_v1.py` (recommandé pour une lecture orientée Cloud/DevOps/IA)

```bash
# Interface graphique (par défaut si aucune cible n'est fournie)
python3 echo_nebula_v1.py --gui

# IP unique
python3 echo_nebula_v1.py -t 8.8.8.8

# Fichier de cibles
python3 echo_nebula_v1.py -f cibles.txt -o rapport.json

# Plage CIDR (garde-fou par défaut : 4096 adresses max)
python3 echo_nebula_v1.py -c 203.0.113.0/24 -w 4 -r 1.0 --fmt ndjson -o rapport.ndjson
```

#### Options principales

```
Cibles (une seule à la fois) :
  -t, --target <IP>          IP unique
  -f, --file <fichier>       Liste d'IPs (une par ligne, # = commentaire)
  -c, --cidr <CIDR>          Plage réseau
      --max-cidr-hosts <N>   Garde-fou taille CIDR [4096]

Performance :
  -w, --workers <N>          Workers parallèles [4]
  -r, --rate <sec>           Délai minimal entre requêtes InternetDB [1.0s]
      --timeout <sec>        Timeout requête [10s]
      --cache-ttl <sec>      TTL du cache local SQLite [3600s]
      --no-cache             Désactiver le cache

Stack / thème :
  -d, --score-threshold <N>  Seuil de Stack Score déclenchant une alerte 🏆 [50]
      --no-constellation     Ne pas afficher le rapport constellation en fin de scan CLI

Sortie :
  -o, --output <fichier>     Fichier de rapport
      --fmt json|ndjson|csv  Format d'export [json]
  -v, --verbose / -q, --quiet
```

### `echo_unified_v41b.py` (version d'origine, thème Δ/Ports Fantômes)

```bash
python3 echo_unified_v41b.py --gui
python3 echo_unified_v41b.py -t 8.8.8.8
python3 echo_unified_v41b.py -c 203.0.113.0/24 -w 4 -r 1.0 -o rapport.json
python3 echo_unified_v41b.py -f cibles.txt --fmt csv -o rapport.csv
```

#### Options principales

```
Cibles :
  -t, --target <IP>          IP unique
  -f, --file <fichier>       Liste d'IPs (une par ligne, # = commentaire)
  -c, --cidr <CIDR>          Plage réseau
      --max-cidr-hosts <N>   Garde-fou taille CIDR [4096]

Performance :
  -w, --workers <N>          Workers parallèles [4]
  -r, --rate <sec>           « Ma » — délai minimal entre requêtes InternetDB [1.0s]
      --cache-ttl <sec>      TTL du cache local SQLite [3600s]
      --no-cache             Désactiver le cache

Corpus (thème) :
  -d, --delta <float>        Seuil Δ déclenchant une alerte dans les logs [0.65]

Sortie :
  -o, --output <fichier>     Fichier de rapport
      --fmt json|ndjson|csv
```

---

## Pourquoi le cache + le délai inter-requêtes ?

InternetDB est un service public **gratuit**, sans authentification. Le cache disque (SQLite, TTL configurable) et le délai minimal entre requêtes (`--rate`, 1 s par défaut) ne sont pas là pour « échapper à une surveillance » — ce sont de bonnes pratiques d'usage raisonnable d'un service partagé, gratuit et non garanti. Les deux outils partagent la même implémentation (`InternetDBClient`, `CacheManager`) et le même comportement à ce sujet.

---

## Avertissement

InternetDB ne « scanne » jamais la cible en direct : il restitue une image mise en cache par Shodan. Cela reste toutefois une activité de reconnaissance — n'interrogez que des cibles (IP, plages, comptes cloud) que vous êtes autorisé à examiner, et respectez le droit applicable ainsi que les conditions d'utilisation de vos fournisseurs cloud pour tout usage des informations retournées (ports exposés, CVE, empreintes de services).
