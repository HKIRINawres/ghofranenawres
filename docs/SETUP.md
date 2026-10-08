# SETUP — installation et exécution reproductible

Cette procédure permet à une **équipe tierce** de reproduire l'environnement, d'exécuter les contrôles
en local, puis de faire tourner le pipeline complet sur GitHub Actions.

## 1. Prérequis

| Outil | Version | Usage |
|---|---|---|
| Node.js | 24 (défaut du projet) | application + ESLint + npm audit |
| Python | 3.10+ | scripts `security/*.py`, pre-commit |
| Docker | récent | build image + Trivy + ZAP |
| `pre-commit` | via pip | hooks locaux (shift-left) |
| Git | récent | tags, historique |

Les outils de sécurité (Gitleaks, Trivy, Checkov, Semgrep) sont **épinglés** et installés
automatiquement par le pipeline ; en local, seul `pre-commit` les tire (voir `.pre-commit-config.yaml`).

## 2. Installation locale

```bash
# 1. Cloner et entrer dans le dépôt
git clone <URL_DU_DEPOT> && cd <DEPOT>

# 2. Installer les dépendances SANS exécuter les scripts d'installation (postinstall)
npm install --ignore-scripts --no-audit --no-fund
(cd frontend && npm install --ignore-scripts --no-audit --no-fund)

# 3. Installer les hooks de sécurité locaux
pip install pre-commit
pre-commit install          # s'exécute désormais à chaque `git commit`

# 4. (Optionnel) lancer tous les contrôles locaux manuellement
pre-commit run --all-files
```

> `--ignore-scripts` est important : il évite qu'une dépendance exécute du code arbitraire pendant
> l'installation (supply chain). C'est aussi ce que fait le pipeline.

## 3. Configuration du dépôt GitHub

1. **Branche par défaut = `main`.** Le déclencheur `push` et le job `deploy` ciblent `main`.
2. **Créer le tag `baseline`** sur le commit d'import brut de Juice Shop (sert à distinguer les
   failles pédagogiques des nouvelles) :
   ```bash
   git tag baseline <SHA_DU_COMMIT_DE_DEPART>
   git push origin baseline
   ```
3. **Autoriser l'écriture de packages** : *Settings → Actions → General → Workflow permissions →
   Read and write permissions*. Les jobs `build`/`deploy` demandent `packages: write` via le
   `GITHUB_TOKEN` éphémère (aucun token Docker séparé).
4. **Secrets (tous facultatifs)** — *Settings → Secrets and variables → Actions* :

   | Secret | Rôle |
   |---|---|
   | `SONAR_TOKEN` | Envoi vers SonarQube Cloud. Sans lui, le job `sonarqube` est sauté proprement. |
   | `TEAMS_WEBHOOK_URL` / `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` | Notification de blocage |
   | `SMTP_USERNAME` / `SMTP_PASSWORD` / `NOTIFY_EMAIL_TO` (+ `SMTP_SERVER`, `SMTP_PORT`) | Notification email |

   ⚠️ Ces valeurs ne doivent **jamais** être commises dans le dépôt.
5. **SonarQube Cloud** (si `SONAR_TOKEN` est utilisé) : créer un projet sur <https://sonarcloud.io>,
   puis renseigner `sonar.organization` et `sonar.projectKey` dans `sonar-project.properties`.

## 4. Exécution du pipeline

- **Automatique** : chaque `push` sur `main` et chaque `pull_request` déclenchent `devsecops.yml`.
- **Manuel** : *Actions → devsecops → Run workflow* (`workflow_dispatch`), avec l'option
  `full_dast` pour un scan ZAP complet (Ajax spider).
- **Planifié** : dimanche 02:00 UTC, DAST complet.
- **Comparaison de rulesets** (rapport Phase 1) : *Actions → semgrep-compare → Run workflow*.

Ordre des jobs : `secrets_scan`, `sast`, `scan_dependencies`, `iac_scan` (source, en parallèle) →
`build` (image, en parallèle des scans source) → `docker_scan`, `dast`, `acceptance_tests` (sur le
digest exact) → `sonarqube` (vue centrale) → `quality_gate` (décision + notification) → `deploy`
(promotion du digest, sur `main` uniquement).

## 5. Vérifier le résultat

- **Actions → devsecops** : statut de chaque job ; le résumé du `quality_gate` affiche la décision.
- **Artefacts** du run : `secrets_scan`, `sast`, `scan_dependencies`, `iac_scan`, `docker_scan`,
  `dast`, `acceptance_tests`, `quality_gate` (contient `attestation.md`, `gate-result.json`,
  `zap-report.html`).
- **GHCR** : après un push accepté sur `main`, l'image est publiée sous
  `ghcr.io/<propriétaire>/<dépôt>:<sha>` et `:latest`.

## 6. Contournement exceptionnel (faux positif bloquant)

Voir [`security-policy.md`](./security-policy.md#exemption-traçable-brief-7). En bref : ajouter une
entrée dans `security/accepted-risks.json` (identifiant exact, gravité, justification, responsable,
expiration ≤ 90 jours), la faire relire par l'autre membre en PR. Une exemption expirée redevient
bloquante. Ne s'applique **jamais** aux secrets ni au SAST nouveau.

<a id="preuves"></a>
## 7. Preuves à produire pour le rapport (brief §8)

Ces captures/exports **ne peuvent pas être générés ici** : ils proviennent de vos vrais runs. À
produire et à placer dans `docs/reports/evidence/` :

- [ ] Vue d'ensemble d'un run `devsecops` réussi (liste des jobs verts).
- [ ] Un run **bloqué** par le `quality_gate` (montrer la décision rouge + le résumé).
- [ ] Rapport **Gitleaks** (secrets détectés) — artefact `secrets_scan`.
- [ ] Rapport **Semgrep** (findings SAST, ex. injection SQL) — artefact `sast`.
- [ ] Rapport **Trivy image** (vulnérabilités + SBOM CycloneDX) — artefact `docker_scan`.
- [ ] Rapport **ZAP** (`zap-report.html`) — artefact `dast`.
- [ ] Rapport **Checkov** (mauvaises configurations IaC) — artefact `iac_scan`.
- [ ] **Gauntlt** (scénarios d'acceptation) — artefact `acceptance_tests`.
- [ ] **Attestation** (`attestation.md`) montrant commit SHA + digest image + décision.
- [ ] **SonarQube Cloud** : tableau de bord + page Activity (tendance/historique).
- [ ] **GHCR** : l'image publiée avec ses tags après un deploy sur `main`.
- [ ] **pre-commit** en local : un commit bloqué (ex. secret ou finding Semgrep) avant le push.
- [ ] **Notification** (Teams/Slack/Discord/email) reçue lors d'un blocage.
- [ ] (Optionnel) `semgrep-compare` : comparaison des rulesets justifiant le choix retenu.

> Conseil : faites au moins un run sur un commit contenant volontairement un secret de test (dans une
> branche jetable, jamais sur `main`) pour capturer un **vrai blocage** de bout en bout.
