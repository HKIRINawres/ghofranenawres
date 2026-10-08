# Matrice de conformité

Cette matrice relie chaque exigence du brief (et de l'OWASP Top 10 / ASVS) au **contrôle automatisé**
qui la vérifie et à l'**endroit où se trouve la preuve**. Statuts : **Couvert** (un contrôle existe et
tourne à chaque push), **Partiel** (le contrôle existe mais ne prouve pas toute l'exigence),
**Écart** (pas encore de contrôle).

## Exigences du brief (§2 à §8)

| Brief | Exigence | Implémenté par | Preuve | Statut |
|---|---|---|---|---|
| §2 | Cartographier le pipeline existant (as-is) | `docs/as-is.md` | document | Couvert |
| §3 | IDE sécurisé + plugins temps réel | `.vscode/extensions.json` (ESLint, SonarLint, Semgrep) | fichier versionné | Couvert |
| §3 | Pre-commit hooks bloquants localement | `.pre-commit-config.yaml` (Gitleaks, HMRC, private-key, Semgrep, Bandit, ESLint security, npm-audit) | fichier versionné | Couvert |
| §3 | Sensibilisation OWASP Top 10 / ASVS | `docs/threat-model.md`, `docs/compliance-matrix.md` | documents | Couvert |
| §4 | SAST | `sast` (Semgrep `p/security-audit`, `p/javascript`, règles custom) | artefact `sast` | Couvert |
| §4 | SCA | `scan_dependencies` (Trivy fs, npm audit, Retire.js) | artefact `scan_dependencies` | Couvert |
| §4 | Scan d'image Docker | `docker_scan` (Trivy image) | artefact `docker_scan` | Couvert |
| §4 | DAST | `dast` (OWASP ZAP baseline, rapide/complet) | `zap-report.html` / `.json` | Couvert |
| §4 | Scan de secrets | `secrets_scan` (Gitleaks, historique complet + nouveau) | artefact `secrets_scan` | Couvert |
| §4 | Scan IaC (optionnel) | `iac_scan` (Checkov : Dockerfile, Terraform, GitHub Actions) | artefact `iac_scan` | Couvert |
| §4 | SBOM (optionnel) | `docker_scan` génère une SBOM CycloneDX de l'image | `sbom-image.cdx.json` | Couvert |
| §5 | Stages dédiés et nommés | jobs nommés comme le brief dans `devsecops.yml` | workflow | Couvert |
| §5 | Quality gates bloquantes (seuils) | `security/gate.py` (1 critique / 5 hautes, Checkov & Gauntlt stricts) | `attestation.md`, `gate-result.json` | Couvert |
| §5 | Bloquant vs non bloquant | secrets/SAST bloquants ; autres en reporting décidé par la gate | `docs/security-policy.md` | Couvert |
| §5 | Secrets du pipeline sécurisés | `GITHUB_TOKEN` éphémère + secrets chiffrés masqués, aucun `curl\|sh`, versions épinglées | workflow | Couvert |
| §5 | Exécution auto à chaque push/PR + local | `on: push/pull_request` ; `pre-commit run` en local | workflow | Couvert |
| §6 | Rapports HTML et/ou JSON | chaque scanner dépose JSON (+ HTML pour ZAP) en artefacts | artefacts du run | Couvert |
| §6 | Centralisation + visualisation | `sonarqube` (SonarQube Cloud) : analyse propre + findings importés | projet SonarQube Cloud | Couvert |
| §6 | Notification auto (email/Slack/Teams) | `security/notify.py` (Teams, Slack, Discord, email selon secrets) | job `quality_gate` | Couvert |
| §6 | Historisation / tendance | SonarQube Cloud (page Activity) + attestations par run | SonarQube Cloud | Couvert |
| §7 | Rapport détaillé + schéma avant/après | `docs/as-is.md`, `docs/devsecops.md` (schémas mermaid) | documents | Couvert |
| §7 | Procédure d'exemption traçable | `security/accepted-risks.json` + `docs/security-policy.md` | fichiers | Couvert |
| §7 | Tests auto à chaque push/PR sans intervention | déclencheurs `push`/`pull_request` | workflow | Couvert |
| §8 | Livrables (pipeline, config, rapport, captures, support) | voir `docs/SETUP.md#preuves` | dépôt + rapport | Partiel (captures à produire) |

## OWASP Top 10 (2021)

| ID | Catégorie | Contrôles dans le pipeline | Statut |
|---|---|---|---|
| A01 | Broken Access Control | ZAP baseline voit ce qu'un utilisateur non authentifié atteint ; Gauntlt vérifie que certains endpoints ne sont pas publics | Partiel |
| A02 | Cryptographic Failures | Gitleaks/HMRC (clés codées en dur) ; ZAP (en-têtes HTTPS/HSTS manquants) | Partiel |
| A03 | Injection | Semgrep `p/javascript` (injections SQL) + règle custom NoSQL (`$where`) ; ESLint security bloque `eval` sur entrée ; ZAP passif | Partiel |
| A04 | Insecure Design | `docs/threat-model.md` (STRIDE) | Partiel (manuel) |
| A05 | Security Misconfiguration | Checkov (Dockerfile, Terraform, workflows) ; Gauntlt (durcissement HTTP) ; ZAP (en-têtes) | Couvert |
| A06 | Vulnerable & Outdated Components | npm-audit (pre-commit), Trivy fs + npm audit + Retire.js (CI), Trivy image, SBOM | Couvert |
| A07 | Identification & Auth Failures | Semgrep (JWT, identifiants codés en dur) ; pas de test de flux d'authentification | Partiel |
| A08 | Software & Data Integrity Failures | Scan de secrets pre-commit + CI ; règle custom `unsafe-yaml-load` (désérialisation) ; image **non signée** (pas de Cosign) | Partiel |
| A09 | Logging & Monitoring Failures | Hors périmètre de cette phase | Écart |
| A10 | Server-Side Request Forgery | Pas de contrôle SSRF dédié | Écart |

## OWASP ASVS 5.0 — niveau 1 (extraits)

| Chapitre | Contrôles automatisés | Statut |
|---|---|---|
| V1 Encodage et sanitisation | Semgrep (SQLi, XSS), ESLint security (`eval` sur entrée) | Partiel |
| V3 Sécurité du frontend web | ZAP (CSP, X-Content-Type-Options…), Gauntlt (durcissement) | Partiel |
| V5 Gestion des fichiers | Gauntlt : le listing du répertoire FTP ne doit pas être public | Partiel |
| V6 Authentification | Semgrep/Gitleaks : identifiants codés en dur ; pas de test de login | Partiel |
| V8 Autorisation | Gauntlt : l'endpoint metrics ne doit pas être public | Partiel |
| V9 Tokens auto-porteurs | Semgrep `hardcoded-jwt-secret` ; Trivy : bypass `jsonwebtoken` (CVE-2015-9235) | Partiel |
| V11 Cryptographie | Gitleaks (clés privées), ESLint `detect-pseudoRandomBytes`, Trivy (`crypto-js`) | Partiel |
| V13 Configuration | Checkov (Dockerfile, Terraform, workflows), Trivy image, Gauntlt nmap, ZAP, scan de secrets | Couvert |
| V15 Code sécurisé & architecture | SCA (Trivy fs/image, npm audit, Retire.js), SBOM, Semgrep, threat model | Couvert |
| V16 Journalisation & erreurs | Aucun (phase Opérations) | Écart |

## Exigences transverses

| Exigence | Vérifiée par | Preuve |
|---|---|---|
| Aucune vulnérabilité critique / ≥ 5 hautes n'atteint la production | `security/gate.py` dans `quality_gate` | `attestation.md` |
| Conformité IaC : toute règle violée échoue | Checkov (strict dans la gate) | artefact `iac_scan` |
| Analyse dynamique du build réel | ZAP baseline contre le conteneur construit | `zap-report.html` |
| Image scannée avant publication | Trivy, HIGH + CRITICAL, sur le digest exact | `trivy.json` |
| Aucun secret dans le code ou les logs | Gitleaks + HMRC (pre-commit et CI) | artefact `secrets_scan` |
| Exceptions justifiées, possédées, temporaires | `accepted-risks.json` (raison, responsable, expiration) | `security/test_gate.py` |
| Traçabilité (qui a déployé quoi, avec quels résultats) | Attestation : SHA commit, digest image, URL run, horodatage, SHA-256 des entrées | `attestation.md` |
| Retour développeur rapide | Gitleaks + Semgrep répondent en ~1 min ; build en parallèle des scans source | runs GitHub Actions |
| Vue centrale + historique des findings | SonarQube Cloud (job `sonarqube`) | projet SonarQube Cloud |
| Signature d'artefact (Cosign) | Non implémenté | **Écart**, axe d'amélioration |
| Vérification de licence des dépendances | Non implémenté | **Écart**, axe d'amélioration |
