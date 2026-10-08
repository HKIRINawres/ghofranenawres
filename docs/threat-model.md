# Modélisation de menaces (STRIDE) — brief §3 / §7

Ce document analyse les menaces de sécurité de deux points de vue complémentaires :
1. **l'application** OWASP Juice Shop (la cible déployée),
2. **le pipeline CI/CD** lui-même (qui, s'il est mal protégé, devient un vecteur d'attaque).

Méthode **STRIDE** : Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege. Un fichier `threat-model.json` (format OWASP Threat Dragon) est également
présent à la racine du dépôt.

## 1. Menaces sur l'application

| # | STRIDE | Menace | Surface concernée | Contrôle du pipeline | Statut |
|---|---|---|---|---|---|
| T1 | Tampering / EoP | Injection SQL via les champs de recherche / login | `routes/login.ts`, `routes/search.ts` | Semgrep `p/javascript` (`express-sequelize-injection`) en `sast` | Détecté (bloquant si nouveau) |
| T2 | Tampering | Injection NoSQL via opérateur `$where` | requêtes Mongo | règle Semgrep custom `nosql-where-injection` | Détecté |
| T3 | Tampering | XSS stocké / réfléchi | frontend Angular, entrées utilisateur | Semgrep + ZAP baseline (`dast`) | Détecté |
| T4 | Elevation of privilege | Désérialisation non sécurisée (`js-yaml` 3, `eval`) | parsing YAML, entrées | règle custom `unsafe-yaml-load`, ESLint security (bloque `eval` sur entrée) | Détecté |
| T5 | Information disclosure | Secrets / clés codés en dur (JWT, clés privées) | source, configs | Gitleaks + HMRC (`secrets_scan`, pre-commit) ; Semgrep `hardcoded-jwt-secret` | Détecté (bloquant) |
| T6 | Information disclosure | Fuite de données via en-têtes / erreurs verbeuses | réponses HTTP | ZAP (en-têtes CSP/HSTS, divulgation d'info) | Détecté |
| T7 | Tampering | Composants tiers vulnérables (dépendances) | `package.json`, image | Trivy fs + image, npm audit, Retire.js, SBOM | Détecté (gate) |
| T8 | Spoofing | Contournement de vérification de token (`jsonwebtoken`, CVE-2015-9235) | authentification | Trivy (CVE dépendance), Semgrep | Détecté |
| T9 | EoP | Endpoints sensibles exposés (metrics, listing FTP) | API, `ftp/` | Gauntlt (`acceptance_tests`) : ces endpoints ne doivent pas être publics | Détecté |
| T10 | Denial of service | Absence de rate-limiting | API publique | non couvert automatiquement | **Écart** (revue manuelle) |

## 2. Menaces sur le pipeline CI/CD

Le pipeline manipule des secrets et publie en production : il est lui-même une cible (brief §5 —
« ne pas reproduire dans l'outillage les failles qu'on cherche à corriger »).

| # | STRIDE | Menace | Contrôle mis en place |
|---|---|---|---|
| P1 | Spoofing | Un fork malveillant déclenche le pipeline pour exfiltrer un secret | Les PR de forks **ne reçoivent pas** les secrets GitHub (natif) ; `permissions: contents: read` par défaut |
| P2 | Tampering | Une action tierce référencée par tag mobile est compromise (`@v2`, `@v3`) | Outils **épinglés** (Gitleaks 8.30.1, Trivy 0.74.0, Checkov 3.3.21, Semgrep 1.165.0) ; Checkov audite nos propres workflows |
| P3 | Tampering | Exécution d'un script distant non vérifié (`curl \| sh`) | **Aucun** `curl \| sh` ; installations depuis des release/versions fixes |
| P4 | Information disclosure | Un token du pipeline fuite dans les logs | Secrets GitHub **chiffrés et masqués** ; `GITHUB_TOKEN` **éphémère** par run ; Gitleaks scanne aussi le dépôt |
| P5 | Elevation of privilege | Permissions trop larges accordées au workflow | `permissions` au **minimum** : `contents: read` global, `packages: write` uniquement sur `build`/`deploy` |
| P6 | Tampering / Repudiation | L'image déployée n'est pas celle qui a été scannée | **« Build once, promote »** : `build` pousse un digest ; `docker_scan`/`dast`/`deploy` utilisent **ce même digest** |
| P7 | Repudiation | Impossible de savoir qui a déployé quoi, avec quels résultats | `attestation.md` : SHA commit, digest image, URL run, horodatage, SHA-256 de chaque entrée |
| P8 | Elevation of privilege | Déployer en production alors qu'un scan a échoué | **Fail secure** : un rapport manquant bloque ; `deploy` exige `quality_gate` réussi et un push sur `main` |
| P9 | Tampering | Contournement local des hooks (`git commit --no-verify`) | Chaque contrôle local est **rejoui côté serveur** dans `devsecops.yml` |
| P10 | Spoofing | Fausse exemption ajoutée pour masquer une faille | Exemptions **revues par l'autre membre** en PR, avec responsable + expiration ≤ 90 j |

## 3. Hypothèses et limites

- La cible tourne en **HTTP sur 127.0.0.1** dans le pipeline : les contrôles TLS/HTTPS (ASVS V12) ne
  sont pas testables en CI et restent un **écart**.
- ZAP baseline n'effectue **pas** de scan authentifié : l'analyse dynamique ne voit que ce qu'un
  utilisateur non authentifié atteint (A01 partiel).
- L'image n'est **pas signée** (pas de Cosign) et les **licences** des dépendances ne sont pas
  vérifiées : deux axes d'amélioration listés dans le rapport.
- Juice Shop est **volontairement** vulnérable : le tag `baseline` et les exemptions servent à ne
  bloquer que les **régressions**, pas les failles pédagogiques d'origine.
