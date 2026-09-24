# ECHO-UNIFIED v4.0

Consolidation, dans une unique GUI Tkinter, des fonctionnalités de `shodan_echo_v3.sh`,
`mcp_echo_v3.py` et `uncover_echo_v3.py` — avec une contrainte de conception volontaire :

> **La découverte d'hôtes/services n'est réalisée QUE via Shodan InternetDB, sans clé API,
> et c'est le seul service web contacté par tout le programme.**

```
GET https://internetdb.shodan.io/<ip>
```

## Ce qui a été volontairement retiré par rapport aux outils sources

| Fonctionnalité source | Outil d'origine | Statut ici |
|---|---|---|
| `nrich` / InternetDB | shodan_echo_v3.sh | ✅ conservé (réécrit en Python pur, sans binaire externe) |
| WHOIS + DNS inverse | shodan_echo_v3.sh | ❌ retiré (2ᵉ service réseau) |
| GéoIP ip-api.com | shodan_echo_v3.sh | ❌ retiré |
| AbuseIPDB | shodan_echo_v3.sh | ❌ retiré (clé API + 2ᵉ service) |
| Handshake JSON-RPC actif MCP | mcp_echo_v3.py | ❌ retiré (contacterait la cible elle-même) |
| API Shodan payante / Censys / FOFA / ZoomEye | uncover_echo_v3.py | ❌ retiré |
| Δ, Ports Fantômes, thème C64, cache, GUI, export | tous | ✅ conservés (calculs 100% locaux) |

## Installation

Aucune dépendance externe obligatoire : uniquement la bibliothèque standard Python 3
(`urllib`, `sqlite3`, `ipaddress`, `argparse`) + `tkinter` pour la GUI.

```bash
# Sur la plupart des distributions, tkinter doit être installé séparément :
sudo apt install python3-tk   # Debian/Ubuntu
```

## Usage

```bash
# Interface graphique (par défaut si aucune cible n'est fournie)
python3 echo_unified_v4.py --gui

# IP unique
python3 echo_unified_v4.py -t 8.8.8.8

# Fichier de cibles
python3 echo_unified_v4.py -f cibles.txt -o rapport.json

# Plage CIDR (garde-fou par défaut : 4096 adresses max)
python3 echo_unified_v4.py -c 203.0.113.0/24 -w 4 -r 1.0 --fmt ndjson -o rapport.ndjson
```

### Options principales

```
Cibles :
  -t, --target <IP>        IP unique
  -f, --file <fichier>     Liste d'IPs (une par ligne, # = commentaire)
  -c, --cidr <CIDR>        Plage réseau
      --max-cidr-hosts <N> Garde-fou taille CIDR [4096]

Performance :
  -w, --workers <N>        Workers parallèles [4]
  -r, --rate <sec>         "Ma" — délai minimal entre requêtes InternetDB [1.0s]
      --cache-ttl <sec>    TTL du cache local SQLite [3600s]
      --no-cache           Désactiver le cache

Corpus (thème) :
  -s, --strate <année>     Graine thématique (1066, 1944, 2025, 2026, 2075)
  -d, --delta <float>      Seuil Δ déclenchant une alerte dans les logs [0.65]

Sortie :
  -o, --output <fichier>   Fichier de rapport
      --fmt json|ndjson|csv
```

## Pourquoi le cache + le "Ma" (délai inter-requêtes) ?

InternetDB est un service public **gratuit**, sans authentification. Le cache disque
(SQLite, TTL configurable) et le délai minimal entre requêtes (`--rate`, 1s par défaut)
ne sont pas là pour "échapper à une surveillance" — ce sont de bonnes pratiques d'usage
raisonnable d'un service partagé, gratuit et non garanti.

## Le thème Corpus Vauvillensis (Δ, Ports Fantômes)

Conservé tel quel dans l'esprit des outils sources, à titre de mise en forme/tri des
résultats. **Aucune de ces valeurs n'a de signification de sécurité réelle** : elles sont
calculées localement, de façon déterministe (SHA-256 sur l'IP), sans requête réseau.
Seules les données brutes d'InternetDB (`ports`, `hostnames`, `cpes`, `tags`, `vulns`)
constituent une information OSINT réelle.

## Avertissement

InternetDB ne "scanne" jamais la cible en direct : il restitue une image mise en cache
par Shodan. Cela reste toutefois une activité de reconnaissance — n'interrogez que des
cibles que vous êtes autorisé à examiner, et respectez le droit applicable pour tout
usage des informations retournées (ports exposés, CVE).
