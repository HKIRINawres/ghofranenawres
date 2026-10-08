# Politique de sécurité du pipeline

Ce document définit **ce qui bloque une livraison et pourquoi**, ainsi que la procédure d'exemption.
Il accompagne le workflow `.github/workflows/devsecops.yml` ; la décision technique est implémentée
dans `security/gate.py` et vérifiée par `security/test_gate.py`.

## Principe : bloquant vs non bloquant (brief §5)

Le pipeline distingue deux comportements pour ne pas freiner inutilement les livraisons :

- **Contrôles bloquants** : ils font échouer le run à eux seuls (secrets, SAST sur du nouveau code).
- **Contrôles en reporting** : ils produisent un rapport ; c'est le **quality gate** qui, en lisant
  l'ensemble des rapports, décide de bloquer ou non selon des seuils de sévérité.

L'application cible (Juice Shop) est volontairement vulnérable : les failles déjà présentes au commit
`baseline` sont donc séparées des **nouvelles**. Sans cette distinction, chaque livraison serait
impossible. Le but du gate est d'empêcher toute **régression** de sécurité d'atteindre la production.

## Décision du quality gate

Le déploiement GHCR ne se produit que si le quality gate passe. Les seuils appliqués :

| Contrôle | Outil | Règle de blocage |
|---|---|---|
| `secrets_scan` | Gitleaks | Toute **nouvelle** alerte depuis `baseline` bloque (bloquant par lui-même) |
| `sast` | Semgrep | Tout **nouveau** finding depuis `baseline` bloque (bloquant par lui-même) |
| `scan_dependencies` | Trivy fs, npm audit, Retire.js | ≥ 1 critique **ou** ≥ 5 hautes non acceptées bloque |
| `docker_scan` | Trivy image | ≥ 1 critique **ou** ≥ 5 hautes non acceptées bloque |
| `dast` | OWASP ZAP baseline | ≥ 1 critique **ou** ≥ 5 hautes non acceptées bloque |
| `iac_scan` | Checkov (Dockerfile, Terraform, workflows) | Toute mauvaise configuration non acceptée bloque |
| `acceptance_tests` | Gauntlt | Tout scénario d'acceptation échoué non accepté bloque |
| `sonarqube`, `notify` | SonarQube Cloud, Teams/Slack/Discord/email | **Reporting uniquement** ; intégrations facultatives, ne décident rien |

**Fail secure** : un rapport manquant (job en échec, artefact absent) est traité comme bloquant. On ne
peut pas déployer « parce que le scan n'a pas eu le temps de tourner ».

Les constats faibles, moyens et informatifs sont conservés dans les rapports mais ne bloquent pas. Le
choix des seuils (1 critique / 5 hautes) est justifié dans le rapport de projet : il bloque toute
vulnérabilité critique unitaire, et un faisceau de hautes sévérités, tout en tolérant le bruit de fond
d'une application d'entraînement.

## Exemption traçable (brief §7)

Un faux positif bloquant, ou un risque accepté consciemment, passe par `security/accepted-risks.json`.
Chaque entrée doit comporter :

- l'**identifiant exact** du constat (règle + fichier + empreinte),
- sa **gravité**,
- une **justification** (pourquoi ce n'est pas exploitable / pourquoi on accepte),
- un **responsable** (nom du membre du binôme),
- une **date d'expiration** (≤ 90 jours).

Règles de gouvernance :

1. La **correction du code reste la solution privilégiée** ; l'exemption est un dernier recours.
2. Toute exemption est **relue par l'autre membre du binôme** dans une pull request (traçabilité de
   la décision via l'historique Git).
3. Une exemption **expirée redevient bloquante** automatiquement (`security/test_gate.py` le vérifie).
4. Les exemptions ne s'appliquent **jamais** aux contrôles bloquants par eux-mêmes (secrets, SAST
   nouveau) : un secret ou une nouvelle injection ne se « reporte » pas.

## Gestion des identifiants du pipeline (brief §5)

Le pipeline ne doit pas reproduire les failles qu'il cherche à corriger :

- Les workflows utilisent le **`GITHUB_TOKEN` éphémère** (créé par GitHub pour chaque run), avec
  `packages: write` uniquement sur les jobs `build` et `deploy`.
- SonarQube et les canaux de notification utilisent des **secrets GitHub chiffrés**, masqués dans les
  logs, jamais des valeurs commises dans le dépôt.
- Les **pull requests issues de forks ne reçoivent pas les secrets** GitHub (comportement natif), ce
  qui empêche un contributeur externe d'exfiltrer un token via le pipeline.
- Aucun `curl … | sh` : les outils sont installés depuis des **versions épinglées** (Gitleaks, Trivy,
  Checkov, Semgrep), pour qu'une nouvelle publication ne change pas silencieusement les résultats.

## Rapports et historisation (brief §6)

- Chaque scanner dépose ses rapports comme **artefacts** du run GitHub Actions (JSON, HTML, SBOM
  CycloneDX).
- `security/annotate.py` ajoute, dans chaque job, une **annotation par finding** sur son fichier et sa
  ligne (rouge = nouveau/bloquant, jaune = connu/accepté) et liste tout dans le résumé du job.
- Le quality gate produit **`attestation.md`** et **`gate-result.json`** : décision, constats,
  exemptions, SHA du commit, **digest de l'image**, URL du run, horodatage et empreinte SHA-256 de
  chaque entrée. `deploy` re-taggue ce même digest → traçabilité complète (qui a déployé quoi, avec
  quels résultats).
- **SonarQube Cloud** centralise ses propres résultats + ceux de Semgrep, Gitleaks, Trivy fs et
  Checkov (convertis par `security/sonar_issues.py`), et conserve l'**historique** run après run
  (page Activity = tendance du niveau de sécurité dans le temps).
- **Notification** automatique (`security/notify.py`) en cas de blocage, sur Teams/Slack/Discord/email
  selon les secrets configurés.
