# Rapport technique — ECHO-NEBULA v1.0
### Guide de développement, configuration et évolution

---

## 1. Vue d'ensemble

**ECHO-NEBULA v1.0** est un outil Python (mono-fichier, ~1430 lignes) de **cartographie passive d'infrastructures Cloud/DevOps/IA**. Il interroge exclusivement **Shodan InternetDB** (`https://internetdb.shodan.io/<ip>`), un service public gratuit et sans clé API, qui renvoie un instantané déjà indexé (ports, CPE, hostnames, tags, CVE) — sans jamais contacter la cible elle-même.

Le programme superpose à cette source unique :
- un **moteur de signatures** (ports / CPE / indices de hostname) spécialisé Cloud-native, DevOps, IA ;
- un **système de scoring** (« Stack Score » 0–100) et de niveaux à thème « nébuleuse » ;
- une **double interface** CLI (argparse) et GUI (Tkinter) ;
- un **cache SQLite local** et un **orchestrateur multi-thread** avec rate-limiting ;
- des **exports** JSON / NDJSON / CSV.

C'est un dérivé (« v1.0 ») d'un outil antérieur nommé ECHO-UNIFIED v4.1, dont il reprend l'infrastructure réseau/cache/CLI/GUI inchangée, en remplaçant le module d'analyse générique par un moteur de reconnaissance de briques Cloud/DevOps/IA.

### Points d'architecture à retenir avant toute évolution

- **Un seul point de sortie réseau** dans tout le programme : `InternetDBClient` → `https://internetdb.shodan.io`. Toute évolution qui ajouterait une source de données (active ou passive) doit être un choix delibéré et documenté, car c'est actuellement une invariant central de l'outil, rappelé trois fois dans le code (docstring, commentaires de classe, message d'aide CLI).
- Le programme est **stateless vis-à-vis de la cible** : aucune donnée n'est écrite ou modifiée à distance, uniquement des lectures d'un cache tiers déjà public.
- Le fichier est **monolithique** (un seul `.py`) mais déjà découpé en sections logiques nettes (`# ====` en commentaires), ce qui facilite une extraction en modules si le projet grossit.

---

## 2. Cartographie des modules

| Section (lignes approx.) | Rôle |
|---|---|
| `Corpus` (88-119) | Constantes globales : version, palette de couleurs GUI, URL InternetDB, en-têtes CSV |
| `TargetError`, `classify_ip`, `expand_targets` (124-196) | Validation et expansion des cibles (IP seule / fichier / CIDR) |
| `CacheManager` (201-250) | Cache disque SQLite avec TTL |
| `InternetDBClient` (256-330) | Client HTTP unique, throttling, retries, gestion des codes 404/429/5xx |
| `StackSignatures` (342-565) | Base de signatures ports/CPE/hostnames + détection |
| `StackAnalyzer` (573-624) | Score, niveaux, badges, couleurs |
| `ScanResult` (629-683) | Dataclass de résultat, sérialisation JSON/CSV |
| `EchoScanner` (688-825) | Orchestrateur : ThreadPoolExecutor, callbacks, annulation |
| `constellation_report` (829-874) | Synthèse texte en fin de scan |
| `export_results` (878-905) | Export JSON/NDJSON/CSV |
| `DetailsPanel`, `EchoUnifiedGUI` (910-1305) | Interface graphique Tkinter complète |
| `build_parser`, `main` (1309-1429) | CLI argparse et point d'entrée |

---

## 3. Flux de données (pipeline d'un scan)

```
Cibles (--target/-t | --file/-f | --cidr/-c)
        │
        ▼
expand_targets()  ──► valide IPv4, exclut privé/loopback/réservé, déduplique
        │
        ▼
EchoScanner.scan(targets)
        │  ThreadPoolExecutor(workers)
        ▼
_process_one(ip)
        │
        ├─► CacheManager.get(ip)  (hit → pas de requête réseau)
        │
        ▼ (miss)
InternetDBClient.lookup(ip)
        │  throttle (rate-limit min_interval)
        │  GET https://internetdb.shodan.io/<ip>
        │  retries exponentiels sur 429/5xx, gestion 404
        ▼
CacheManager.set(ip, data, status)
        │
        ▼
StackSignatures.detect(status, data)  ──► liste de "matches" (port/cpe/hostname)
        │
        ▼
StackAnalyzer.score() / .level() / .categories() / .badges()
        │
        ▼
ScanResult(...)  ──► callbacks on_result / on_progress / on_log
        │
        ▼
constellation_report() (synthèse globale) + export_results() (JSON/NDJSON/CSV)
```

Ce pipeline est le même en CLI et en GUI : la GUI instancie simplement `EchoScanner` dans un thread `daemon` et relie ses callbacks (`on_log`, `on_result`, `on_progress`) à des mises à jour d'interface via `root.after(0, ...)` (pattern correct pour rester thread-safe avec Tkinter).

---

## 4. Modèle de données InternetDB

Chaque réponse de `https://internetdb.shodan.io/<ip>` a la forme :

```json
{
  "ip": "8.8.8.8",
  "ports": [53, 443],
  "cpes": ["cpe:/a:..."],
  "hostnames": ["dns.google"],
  "tags": ["cdn"],
  "vulns": ["CVE-2023-..."]
}
```

`ScanResult` expose ces champs via des propriétés (`.hostnames`, `.ports`, `.cpes`, `.tags`, `.vulns`) qui font `data.get(...) or []` — donc robustes à un champ absent ou `None`, mais **silencieusement tolérantes** : si Shodan change la forme de sa réponse (renommage de clé), l'outil ne lèvera pas d'erreur, il renverra juste des listes vides. À surveiller si un jour les résultats semblent anormalement pauvres.

---

## 5. Le moteur de signatures (cœur de l'outil)

### 5.1 Trois types de correspondance, trois niveaux de confiance

| Source | Confiance | Logique |
|---|---|---|
| `PORT_SIGNATURES` (dict `port → (nom, catégorie, description, confiance)`) | `strong` la plupart du temps, `heuristic` pour les ports ambigus (ex. `3000`, `8000`, `8080`, `9090`) | ~70 ports référencés |
| `CPE_KEYWORDS` (liste de sous-chaînes CPE) | toujours `strong` | ~25 mots-clés (docker, kubernetes, gitlab, vault...) |
| `HOSTNAME_HINTS` (liste de sous-chaînes de hostname) | toujours `heuristic` | ~16 indices (k8s, jenkins, mcp, agent...) |
| `NODEPORT_RANGE` (30000-32767) | `heuristic` | plage NodePort Kubernetes par défaut |

Cette distinction `strong`/`heuristic` est le principal garde-fou anti-faux-positifs de l'outil : un port `8080` seul ne prouve rien (Jenkins ? Kong ? Nexus ? appli web quelconque ?), alors qu'un CPE explicite ou un port univoque (`6443` = API Kubernetes) est fiable.

### 5.2 Catégories thématiques

8 catégories fixes (`StackSignatures.CATEGORIES`) : `containers`, `cicd`, `observability`, `secrets_net`, `data`, `ai_agents`, `iac_cloud`, `gateway`. Chacune a un label, un emoji, un message de découverte (`DISCOVERY_MSG`) et un badge (`BADGE_MAP`).

### 5.3 `StackSignatures.detect(status, data)`

Fonction pure, sans effet de bord, sans réseau : elle prend le JSON déjà récupéré et retourne une liste de dicts `{kind, key, name, category, desc, confidence}`. C'est le point d'extension le plus simple du projet (voir §8).

---

## 6. Le scoring « Stack Score »

```python
cats_strong   = catégories ayant ≥1 match "strong"
cats_all      = toutes les catégories touchées
n_strong      = nb de catégories "strong"
n_weak_only   = nb de catégories seulement "heuristic"
breadth_bonus = min(nb_matches, 10) * 1.5
score         = min(100, round(n_strong*15 + n_weak_only*6 + breadth_bonus))
```

Logique : chaque catégorie confirmée par une preuve forte vaut 15 points, chaque catégorie seulement suggérée vaut 6 points, et un bonus de diversité (jusqu'à 15 points) récompense le nombre brut de correspondances. Le score est ensuite mappé sur 6 niveaux (`🌑 Silence Radio` → `✨🌌 Nova Stack`) et déclenche un badge « 🌌 Stack Complète » si ≥5 catégories distinctes sont touchées.

**Propriété importante pour une évolution future** : ce score ne dépend que de la *diversité de catégories*, pas de la sévérité (une infra avec un seul port Vault exposé aura un score plus bas qu'une infra avec 5 catégories anodines). Si l'objectif futur est plus orienté "risque" que "richesse de stack", il faudra un second score dédié (voir §9).

---

## 7. Configuration : paramètres CLI et GUI

### 7.1 Sélection de cibles (un seul mode à la fois, groupe mutuellement exclusif)

| Option | Description |
|---|---|
| `-t/--target IP` | IP unique |
| `-f/--file FICHIER` | Liste d'IP (une par ligne, `#` = commentaire) |
| `-c/--cidr CIDR` | Plage réseau IPv4 (ex. `203.0.113.0/24`) |
| `--max-cidr-hosts N` | Garde-fou taille de plage (défaut 4096) |

`expand_targets()` **exclut systématiquement** les IP non publiques (loopback, privé, lien-local, réservé, multicast) — logique, car InternetDB n'indexe que des IP publiques. IPv6 n'est pas supporté (rejeté explicitement).

### 7.2 Performance

| Option | Défaut | Rôle |
|---|---|---|
| `-w/--workers` | 4 | Taille du `ThreadPoolExecutor` |
| `-r/--rate` | 1.0 s | Délai minimal entre deux requêtes InternetDB (par client, donc partagé entre workers via un verrou) |
| `--timeout` | 10 s | Timeout HTTP par requête |
| `--cache-ttl` | 3600 s | Durée de vie du cache SQLite |
| `--no-cache` | off | Désactive complètement le cache disque |

### 7.3 Stack / thème

| Option | Défaut | Rôle |
|---|---|---|
| `-d/--score-threshold` | 50 | Seuil déclenchant l'alerte `🏆 STACK NOTABLE` dans les logs |
| `--no-constellation` | off | Supprime le rapport de synthèse en fin de scan CLI |

### 7.4 Sortie

| Option | Défaut | Rôle |
|---|---|---|
| `-o/--output` | — | Fichier de rapport (sinon impression JSON sur stdout) |
| `--fmt` | json | `json` \| `ndjson` \| `csv` |
| `-v/--verbose` / `-q/--quiet` | — | Niveau de log |
| `--gui` | — | Lance l'interface Tkinter (également lancée automatiquement si aucune cible n'est fournie) |

### 7.5 Interface graphique

La GUI expose les mêmes paramètres (workers, délai, TTL cache, seuil de score) via des `Spinbox`/`Checkbutton`, plus un sélecteur de mode de cible (IP / Fichier / CIDR) et des boutons d'action (`SCAN`, `ANNULER`, `CLEAR`, `CONSTELLATION`, exports). Le scan tourne dans un thread `daemon` séparé pour ne pas geler l'UI ; toute mise à jour d'interface passe par `root.after(0, ...)`.

---

## 8. Points d'extension recommandés (pour faire évoluer l'outil)

### 8.1 Ajouter une signature (le plus fréquent)

- **Nouveau port** : ajouter une entrée à `StackSignatures.PORT_SIGNATURES`, format `port: (nom, catégorie, description, confiance)`. Respecter la règle "strong" seulement si le port est réellement univoque.
- **Nouveau logiciel via CPE** : ajouter un triplet à `CPE_KEYWORDS`.
- **Nouvel indice de hostname** : ajouter un triplet à `HOSTNAME_HINTS` (rester en confiance `heuristic` par convention du projet).
- **Nouvelle catégorie thématique** : ajouter une entrée à `CATEGORIES`, puis obligatoirement une entrée correspondante dans `DISCOVERY_MSG` et `BADGE_MAP` (sinon `KeyError`/badge manquant silencieux — `badges()` fait un test `if c in BADGE_MAP` qui masque l'oubli plutôt que de le signaler).

> Suggestion : un test unitaire simple (`assert set(CATEGORIES) <= set(DISCOVERY_MSG) == set(BADGE_MAP)`) éviterait les incohérences silencieuses à ce niveau.

### 8.2 Modifier le calcul de score

Tout est centralisé dans `StackAnalyzer.score()` — une fonction statique pure prenant `matches` en entrée. C'est le point d'extension idéal pour :
- pondérer différemment certaines catégories (ex. `secrets_net` plus lourd que `observability`) ;
- introduire un score de "risque" séparé du score de "richesse" (voir §9) ;
- prendre en compte `vulns` (actuellement le nombre de CVE **n'entre pas du tout** dans le score, alors qu'il est affiché partout — c'est probablement le premier axe d'évolution utile).

### 8.3 Ajouter un format d'export

`export_results()` est un simple `if/elif` sur `fmt`. Ajouter un format = ajouter une branche, plus mettre à jour `ArgumentParser.add_argument("--fmt", choices=[...])` et le menu GUI (`_export`, boutons dans `_build_controls`).

### 8.4 Ajouter une source de données

C'est le changement le plus structurant. Actuellement `InternetDBClient` est la seule classe réseau, appelée depuis un seul endroit (`EchoScanner._process_one`). Pour ajouter une source :
1. Créer un nouveau client (même contrat de retour `(data, status, from_cache, latency_ms)` recommandé) ;
2. Fusionner les données dans `_process_one` avant `StackSignatures.detect()` ;
3. **Décision de conception à trancher explicitement** : le projet revendique actuellement « aucun sondage actif de la cible » comme contrainte non négociable (rappelée dans le docstring et dans l'en-tête GUI `"Seule source réseau : ... aucun sondage actif de la cible"`). Ajouter une source active (scan de ports, requête MCP JSON-RPC, etc.) changerait la nature légale/éthique de l'outil et devrait au minimum être un mode explicite et clairement annoncé, pas un comportement par défaut.

### 8.5 Découper le fichier

À ce stade (~1400 lignes), un découpage en modules serait raisonnable si le projet continue de grossir :
```
echo_nebula/
├── __init__.py
├── targets.py       # expand_targets, classify_ip, TargetError
├── cache.py         # CacheManager
├── client.py        # InternetDBClient
├── signatures.py     # StackSignatures
├── analyzer.py       # StackAnalyzer
├── scanner.py         # EchoScanner, ScanResult
├── report.py          # constellation_report, export_results
├── gui.py              # DetailsPanel, EchoUnifiedGUI
└── cli.py               # build_parser, main
```
Le code s'y prête bien car les dépendances sont déjà à sens unique (GUI/CLI → Scanner → Signatures/Analyzer → Client/Cache), sans dépendance circulaire visible.

---

## 9. Limites connues et pistes d'amélioration

| Sujet | Constat actuel | Piste |
|---|---|---|
| CVE non pondérées | `vulns` est affiché mais n'influence jamais `stack_score` | Ajouter un score de risque séparé, ou une pondération basée sur la sévérité si les CVE de Shodan incluent un CVSS |
| Ports ambigus nombreux | Plusieurs ports très fréquents (`8080`, `8000`, `3000`, `9090`) sont marqués `heuristic` par nécessité | Pourrait être affiné avec un croisement port+hostname (si les deux indices convergent, remonter la confiance) |
| IPv6 non supporté | Rejeté explicitement (`classify_ip` ne gère que `IPv4Address`, et `expand_targets` rejette tout ce qui n'est pas version 4) | InternetDB supporte IPv4 uniquement au moment de l'écriture — à revalider si Shodan étend le support |
| Tolérance silencieuse aux champs manquants | `data.get(...) or []` partout | Acceptable pour la robustesse, mais masque un éventuel changement de schéma côté Shodan ; un log de niveau DEBUG sur clé inattendue serait utile |
| Rate-limit partagé mais pas réellement distribué | `min_interval` est appliqué par un seul verrou dans `InternetDBClient`, donc correct même avec plusieurs workers (un seul thread peut passer le throttle à la fois) — bon point, pas un bug | — |
| GUI et CLI dans le même fichier | Fonctionnel mais alourdit la lecture | Cf. §8.5 |
| Aucun test automatisé visible dans le fichier fourni | — | Prioriser des tests sur `StackSignatures.detect()` et `StackAnalyzer.score()`, qui sont des fonctions pures faciles à tester unitairement |

---

## 10. Cadre légal / éthique (tel que porté par le code lui-même)

Le fichier documente lui-même ses limites intentionnelles, à préserver dans toute évolution :
- Aucune clé API, aucun service payant (pas d'API Shodan complète, pas de Censys/FOFA/ZoomEye) ;
- Aucun sondage actif de la cible (pas de scan de port, pas de requête JSON-RPC MCP, pas de ping) ;
- Un garde-fou de taille de CIDR (`--max-cidr-hosts`, défaut 4096) contre le scan de masse involontaire ;
- Un rappel explicite dans le docstring que l'usage reste soumis au droit applicable et aux CGU des fournisseurs cloud concernés, même si InternetDB lui-même ne « touche » jamais la cible.

Ces éléments font partie de la conception du projet et pas seulement de sa documentation — toute évolution qui les remettrait en cause (ajout de sondage actif, contournement du rate-limit public, etc.) changerait la nature de l'outil et mérite une décision explicite plutôt qu'un ajout incrémental.

---

## 11. Résumé express pour reprise en main rapide

- **Un seul réseau autorisé** : `InternetDBClient` → InternetDB.
- **Ajouter une signature** = éditer `StackSignatures` (3 dicts/listes + 2 dicts de mapping catégorie).
- **Changer le score** = éditer `StackAnalyzer.score()`, fonction pure et isolée.
- **Ajouter un export** = brancher une branche dans `export_results()` + CLI + GUI.
- **CLI et GUI partagent le même moteur** (`EchoScanner`) via callbacks — ne jamais dupliquer la logique métier dans la GUI.
- **Cache SQLite** transparent, clé = IP, purge automatique des entrées expirées à la fin de chaque scan.
