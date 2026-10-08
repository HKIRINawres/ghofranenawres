# Rapport de projet — Sécurisation DevSecOps d'un pipeline CI/CD

**Projet :** intégration de contrôles de sécurité automatisés (« shift-left ») dans un pipeline CI/CD,
de la phase de codage local jusqu'au déploiement en production.
**Application cible :** OWASP Juice Shop (application volontairement vulnérable, idéale pour démontrer
la détection de failles réelles).
**CI/CD :** GitHub Actions. **Binôme :** [Noms à compléter]. **Date :** [à compléter].

---

## 1. Contexte et objectifs

Les pipelines CI/CD classiques automatisent la compilation, les tests et le déploiement, mais
intègrent rarement la **sécurité** de façon bloquante. Une vulnérabilité critique peut ainsi atteindre
la production tant que les tests fonctionnels passent. L'objectif de ce projet est d'**intégrer la
sécurité en continu** dans le pipeline, selon l'approche **« shift-left »** : détecter le plus tôt
possible (dès le poste du développeur), et **bloquer automatiquement** toute vulnérabilité critique
avant la mise en production.

Il ne s'agit pas seulement d'ajouter des outils, mais d'installer une **culture de sécurité
continue** : retour rapide au développeur, explication de chaque faille, traçabilité des décisions.

**Objectifs opérationnels :**

- Cartographier le pipeline existant et identifier ses faiblesses de sécurité (état « as-is »).
- Ajouter des contrôles automatisés : SAST, SCA, scan de secrets, scan d'image Docker, DAST, scan IaC, SBOM.
- Mettre en place le shift-left local (IDE sécurisé, pre-commit hooks).
- Définir des **quality gates** bloquantes avec seuils de sévérité justifiés.
- Assurer le **reporting**, la **centralisation**, l'**historisation** et la **notification**.
- Produire une documentation claire, reproductible et exploitable par une équipe tierce.

## 2. Méthodologie

Le travail est organisé en **trois phases**, du plus proche du développeur au plus proche de la
production :

- **Phase 1 — Shift-left (poste développeur).** Détection en temps réel dans l'IDE et blocage local
  au `git commit` via des pre-commit hooks. Objectif : corriger avant même de pousser.
- **Phase 2 — Contrôles automatisés dans le pipeline.** Un job par contrôle de sécurité, exécuté à
  chaque push et pull request, produisant des rapports normalisés.
- **Phase 3 — Décision et déploiement.** Un **quality gate** unique agrège tous les rapports, décide
  de bloquer ou non, notifie l'équipe, puis le **deploy** promeut l'image en production.

Méthode de travail : **analyse de l'existant → conception du pipeline cible → implémentation →
validation par un run réel → documentation**. Chaque exigence du cahier des charges est reliée à un
contrôle et à une preuve dans la **matrice de conformité** (`docs/compliance-matrix.md`).

Une notion centrale : l'application cible étant volontairement vulnérable, nous distinguons les
failles **déjà présentes** à l'import (marquées par un tag Git `baseline`) des **nouvelles**
régressions. Le pipeline bloque sur le **nouveau**, ce qui rend la démarche applicable à un vrai
projet sans être paralysée par le bruit de fond.

## 3. État des lieux du pipeline existant (« as-is »)

L'analyse détaillée figure dans `docs/as-is.md`. En synthèse, le pipeline d'origine (GitHub Actions)
comprennait lint, tests unitaires/intégration/E2E, packaging, build et test Docker, publication et
déploiement — mais **uniquement fonctionnels**.

**Principales faiblesses identifiées :**

| # | Faiblesse | Conséquence |
|---|---|---|
| W1 | Scans de sécurité **manuels** (`workflow_dispatch`) | rien ne tourne automatiquement à chaque push |
| W2 | **Aucune gate de sécurité** entre build et déploiement | un build vulnérable est déployé si les tests passent |
| W3 | Le SAST (CodeQL) existe mais **ne bloque jamais** | les findings n'arrêtent ni merge ni release |
| W4 | Le DAST (ZAP) tourne **après** déploiement, règles désactivées | problèmes découverts après exposition |
| W5 | **Pas de shift-left local** (ni pre-commit, ni règles IDE) | remontée tardive, après push |
| W6 | Scans **dispersés et redondants**, versions d'actions incohérentes | aucune vue centralisée, maintenance difficile |
| W7 | Image Docker **poussée sans scan bloquant** | image critique atteint le registre |

## 4. Outils choisis et justification

| Contrôle | Outil retenu | Justification |
|---|---|---|
| Scan de secrets | **Gitleaks** | rapide, scan de tout l'historique, sortie JSON, hook pre-commit officiel |
| SAST | **Semgrep** | multi-langage, règles personnalisables, mode `baseline` (diff), même moteur en local et en CI |
| SCA (dépendances) | **Trivy fs** + npm audit + Retire.js | Trivy couvre plusieurs écosystèmes ; npm audit/Retire.js complémentaires côté JS |
| Scan d'image | **Trivy image** + SBOM CycloneDX | même outil que la SCA, génère la SBOM pour la traçabilité |
| DAST | **OWASP ZAP baseline** | référence DAST, scan passif + spider, rapport HTML/JSON |
| Scan IaC | **Checkov** | couvre Dockerfile, Terraform **et** nos propres workflows GitHub Actions |
| Tests d'acceptation sécurité | **Gauntlt** | scénarios d'attaque déclaratifs (nmap, curl) sur le conteneur réel |
| Centralisation / historique | **SonarQube Cloud** | vue unique + tendance (page Activity), importe les findings des autres outils |
| Gate locale | **pre-commit** + ESLint security + Bandit | bloque au commit ; Bandit audite nos scripts Python |
| IDE sécurisé | **VS Code** + SonarLint, ESLint, Semgrep | détection en temps réel pendant la saisie |

**Choix structurants :**

- **Versions épinglées** (Gitleaks 8.30.1, Trivy 0.74.0, Checkov 3.3.21, Semgrep 1.165.0) : une
  nouvelle publication ne peut pas changer silencieusement les résultats.
- **Aucun `curl … | sh`** : on n'exécute pas de script distant non vérifié dans un pipeline qui détient
  des secrets.
- **« Build once, promote »** : l'image est construite **une fois**, poussée comme candidate, puis tous
  les contrôles d'image et le déploiement utilisent **le même digest**. Ce qui est déployé est, par
  construction, ce qui a été scanné.

## 5. Intégration dans le pipeline (GitHub Actions)

Le pipeline est consolidé dans **un seul** fichier `.github/workflows/devsecops.yml`, avec un job par
contrôle, nommé comme dans le cahier des charges :

`secrets_scan` → `sast` → `scan_dependencies` → `iac_scan` (contrôles source, en parallèle) ;
`build` (image candidate, **en parallèle** des scans source) ;
`docker_scan`, `dast`, `acceptance_tests` (sur le digest exact) ;
`sonarqube` (vue centrale) ;
`quality_gate` (décision + notification) ;
`deploy` (promotion sur `main`).

**Point de conception important — la place du build.** Le `build` ne dépend **pas** des scans source.
S'il en dépendait, un finding SAST empêcherait la construction de l'image, et `docker_scan`, `dast` et
`acceptance_tests` ne tourneraient jamais : le quality gate déciderait alors sur des **rapports
incomplets**. En construisant en parallèle, tous les contrôles produisent leur rapport, et la décision
est prise sur un ensemble complet. La compilation de l'application a lieu une seule fois, dans le build
de l'image — il n'y a donc pas de job de build applicatif séparé et redondant.

**Déclenchement :** push sur `main`, toute pull request, exécution planifiée hebdomadaire (DAST
complet), et lancement manuel. Le `deploy` ne s'exécute que sur un push dans `main` **et** si le
`quality_gate` est passé.

### Quality gates — bloquant vs non bloquant

| Contrôle | Règle de blocage |
|---|---|
| `secrets_scan` (Gitleaks) | toute **nouvelle** alerte depuis `baseline` bloque |
| `sast` (Semgrep) | tout **nouveau** finding depuis `baseline` bloque |
| `scan_dependencies`, `docker_scan`, `dast` | ≥ 1 critique **ou** ≥ 5 hautes non acceptées bloque |
| `iac_scan` (Checkov), `acceptance_tests` (Gauntlt) | toute alerte non acceptée bloque |
| `sonarqube`, `notify` | reporting uniquement, ne décident rien |

**Justification des seuils.** Bloquer dès **1 critique** empêche toute vulnérabilité gravissime
d'atteindre la production. Le seuil de **5 hautes** évite de paralyser les livraisons sur du bruit de
fond tout en bloquant un faisceau d'alertes sérieuses. Les sévérités faibles/moyennes sont conservées
en reporting. **Fail secure** : un rapport manquant est traité comme bloquant — on ne déploie jamais
« parce que le scan n'a pas eu le temps de tourner ».

### Gestion sécurisée des secrets du pipeline

Le pipeline ne reproduit pas les failles qu'il corrige : `GITHUB_TOKEN` **éphémère** avec permissions
minimales (`contents: read`, `packages: write` uniquement sur `build`/`deploy`), secrets **chiffrés et
masqués** (`SONAR_TOKEN`, webhooks de notification), et **aucun secret** transmis aux pull requests
issues de forks.

## 6. Reporting, centralisation et notification

- **Rapports** JSON (et HTML pour ZAP) déposés en **artefacts** du run pour chaque contrôle.
- **Annotations** : `security/annotate.py` ajoute une annotation par finding sur son fichier et sa
  ligne (rouge = nouveau/bloquant, jaune = connu/accepté) et liste tout dans le résumé du job — le
  développeur voit **où** est le problème, ce qui favorise la montée en compétence.
- **Centralisation** : SonarQube Cloud regroupe ses propres résultats et ceux de Semgrep, Gitleaks,
  Trivy fs et Checkov.
- **Historisation** : la page Activity de SonarQube conserve la **tendance** run après run, et chaque
  run produit une **attestation** datée.
- **Notification** : `security/notify.py` alerte Teams/Slack/Discord/email en cas de blocage.

## 7. Traçabilité et procédure d'exemption

Le `quality_gate` produit `attestation.md` et `gate-result.json` : SHA du commit, **digest de
l'image**, URL du run, horodatage et empreinte SHA-256 de chaque rapport en entrée. Comme `deploy`
re-taggue ce même digest, on sait exactement **qui a déployé quoi, avec quels résultats**.

**Exemption (faux positif bloquant).** Ajout d'une entrée dans `security/accepted-risks.json` avec :
identifiant exact du constat, gravité, **justification**, **responsable**, **date d'expiration**
(≤ 90 jours). Règles : la correction du code reste prioritaire ; l'exemption est **relue par l'autre
membre du binôme** en pull request (traçabilité via Git) ; une exemption **expirée redevient
bloquante** ; les contrôles bloquants par eux-mêmes (secrets, SAST nouveau) ne sont **jamais**
exemptables.

## 8. Résultats obtenus

> ⚠️ **À compléter avec vos vrais runs.** Les valeurs ci-dessous sont les résultats attendus sur
> Juice Shop ; remplacez-les par vos chiffres réels et insérez vos captures (checklist dans
> `docs/SETUP.md` §7).

- **Scan de secrets (Gitleaks)** : [N] secrets détectés dans l'historique (clés, tokens) —
  *insérer capture*.
- **SAST (Semgrep)** : [N] findings dont les injections SQL de `routes/login.ts` et `routes/search.ts`
  (CWE-89) et les injections NoSQL — *insérer capture*.
- **SCA (Trivy fs / npm audit)** : [N] critiques + [N] hautes sur les dépendances — *insérer capture*.
- **Scan d'image (Trivy)** : [N] critiques + [N] hautes sur l'image construite ; SBOM CycloneDX
  générée — *insérer capture*.
- **DAST (ZAP)** : [N] alertes (en-têtes de sécurité manquants, divulgation d'information) —
  *insérer `zap-report.html`*.
- **IaC (Checkov)** : [N] mauvaises configurations sur Dockerfile/Terraform/workflows — *insérer capture*.
- **Quality gate** : exemple d'un run **bloqué** (décision rouge) et d'un run **passé** avec
  attestation — *insérer captures*.
- **Déploiement** : image publiée sur `ghcr.io/<propriétaire>/<dépôt>:<sha>` et `:latest` après un push
  accepté sur `main` — *insérer capture GHCR*.
- **Shift-left local** : un commit **bloqué** par pre-commit (secret ou finding Semgrep) avant push —
  *insérer capture terminal*.

**Démonstration de bout en bout recommandée :** sur une branche jetable, commiter volontairement un
faux secret de test → observer le blocage pre-commit en local, puis le blocage `secrets_scan` en CI,
puis la notification. Cela prouve la chaîne complète « shift-left → gate → alerte ».

## 9. Difficultés rencontrées

- **Bruit de fond d'une application volontairement vulnérable** : sans distinction ancien/nouveau,
  chaque run échouait. Résolu par le tag `baseline` + le mode diff de Semgrep/Gitleaks et les
  exemptions traçables.
- **Placement du build** : faire dépendre le build des scans source cassait les contrôles d'image
  (rapports incomplets). Résolu en construisant en parallèle et en décidant uniquement au quality gate.
- **Cohérence local / CI** : les hooks pre-commit peuvent être contournés (`--no-verify`). Résolu en
  rejouant **les mêmes contrôles** côté serveur, avec les **mêmes versions** d'outils.
- **Faux positifs** (ex. certaines règles Checkov sur nos propres workflows) : gérés par le processus
  d'exemption justifié et borné dans le temps, plutôt que par la désactivation des outils.
- **Dispersion initiale** : de nombreux workflows redondants et manuels. Résolu par la consolidation en
  un pipeline unique et lisible.

## 10. Axes d'amélioration

- **Signature d'artefacts** (Cosign) et vérification de signature au déploiement (intégrité, A08).
- **Vérification des licences** des dépendances (conformité juridique).
- **DAST authentifié** (ZAP avec un contexte de connexion) pour couvrir les routes protégées (A01).
- **Tests TLS/HTTPS** (ASVS V12), non testables aujourd'hui car la cible tourne en HTTP local.
- **Journalisation et monitoring** de sécurité (A09/V16) : corrélation des alertes, tableau de bord
  Grafana/ELK.
- **Contrôle SSRF** dédié (A10).
- **Déploiement vers un environnement réel isolé** ( staging → production ) au-delà de la promotion
  d'image sur le registre.

## 11. Conclusion

Le pipeline obtenu intègre **tous** les contrôles demandés (secrets, SAST, SCA, image, DAST, IaC,
SBOM), du **poste développeur** jusqu'au **déploiement**, avec une **décision unique et traçable**
(quality gate + attestation) et des **seuils justifiés**. La consolidation en un seul workflow,
l'épinglage des versions et le principe « build once, promote » rendent l'ensemble **lisible,
reproductible et auditable**. Au-delà des outils, la démarche installe un **retour rapide et pédagogique**
au développeur, cœur de l'approche shift-left.

## 12. Livrables et arborescence

- `.github/workflows/devsecops.yml` — pipeline principal (commenté).
- `.github/workflows/semgrep-compare.yml` — utilitaire manuel de comparaison de rulesets.
- `.pre-commit-config.yaml`, `.vscode/extensions.json` — shift-left local.
- `sonar-project.properties` — configuration SonarQube Cloud.
- `security/` — scripts du pipeline (gate, annotate, notify, sonar_issues, run-acceptance, règles
  Semgrep/ESLint/ZAP, `accepted-risks.json`).
- `docs/` — `as-is.md`, `devsecops.md`, `security-policy.md`, `compliance-matrix.md`,
  `threat-model.md`, `SETUP.md`, `rapport-projet.md` (ce document), `reports/evidence/` (captures).
