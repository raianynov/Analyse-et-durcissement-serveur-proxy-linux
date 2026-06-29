**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 4
## Analyse et durcissement d'un reverse proxy Linux

| | |
|---|---|
| **Système cible** | Reverse proxy Traefik (AlmaLinux 10.2) |
| **Document** | Partie 1 — Analyse du système |
| **Auteur** | Raian Remir |
| **Date** | Juin 2026 |
| **Version** | 1.0 |
| **Diffusion** | Usage pédagogique |

---

## Sommaire

1. Fonction métier
2. Identification du système
3. Cartographie des ports et services
4. Configuration de Traefik
5. Comptes, groupes et privilèges
6. Contrôle d'accès local (SELinux)
7. Pare-feu (firewalld)
8. Protection contre les tentatives d'authentification
9. Certificats
10. Synthèse de la surface d'attaque

---

## 1. Fonction métier

La machine est le **point d'entrée web** du campus : un **reverse proxy Traefik**
qui reçoit le trafic HTTP/HTTPS et le redistribue vers les services applicatifs
hébergés derrière lui. Son rôle se limite donc à trois fonctions : terminer les
connexions entrantes sur les ports 80 et 443, router ces requêtes vers les services
en amont, et permettre son administration (SSH et tableau de bord Traefik). Tout
composant ne contribuant pas à ce rôle constitue une surface d'attaque inutile.

## 2. Identification du système

| Élément | Valeur |
|---|---|
| Distribution | AlmaLinux 10.2 (Lavender Lion) |
| Noyau | Linux 6.12.0-211.22.1.el10_2.x86_64 |
| Système d'init | systemd |
| Reverse proxy | Traefik (binaire natif `/usr/local/bin/traefik`) |
| Contrôle d'accès | SELinux **enforcing**, politique `targeted` |
| Pare-feu | firewalld (zone `public`) |
| Anti-bruteforce | fail2ban (jail `sshd` active) |
| Accès distant | OpenSSH (sshd) |
| Adresse IP | 192.168.5.131/24 sur `ens33` |
| Compte d'administration | admin (uid 1000, groupe wheel) |

Le système est **moderne et supporté** (fin de support 2035), à la différence d'un
Metasploitable. La problématique n'est donc pas de corriger des versions obsolètes
mais de **réduire une surface d'attaque trop large par rapport au rôle** et de
**corriger des défauts de configuration**, à commencer par l'exposition du tableau
de bord Traefik et l'exécution du proxy en root.

## 3. Cartographie des ports et services

Relevé obtenu par `sudo ss -tulpn`. La colonne Rôle qualifie chaque composant au
regard de la fonction de reverse proxy.

| Port | Service | Programme | Rôle |
|---|---|---|---|
| 22 | SSH | sshd | Nécessaire (administration, à restreindre et durcir) |
| 80 | HTTP | traefik | Nécessaire (entrée web, à rediriger vers 443) |
| 443 | HTTPS | traefik | Nécessaire (entrée sécurisée, à configurer — voir §4) |
| **8080** | Dashboard Traefik | traefik | **À neutraliser** (API `insecure`, HTTP clair, sans auth) |
| **9090** | Cockpit | systemd (socket) | Inutile (administration web non requise) |
| **21** | FTP | vsftpd | Inutile (aucun usage sur un reverse proxy) |
| **631** | IPP | cupsd | Inutile (impression) |
| **5353** | mDNS | avahi-daemon | Inutile (découverte de services) |
| 323 | NTP | chronyd | Nécessaire (synchro horaire, déjà en écoute locale) |

Sur neuf ports en écoute, **trois seulement** (22, 80, 443) correspondent au rôle.
Le port 8080 est un défaut de configuration à corriger, les autres (9090, 21, 631,
5353) relèvent de services à supprimer.

## 4. Configuration de Traefik

### 4.1 Configuration statique relevée

Fichier `/etc/traefik/traefik.yml` :

```yaml
api:
  dashboard: true
  insecure: true
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
providers:
  file:
    filename: /etc/traefik/dynamic.yml
```

### 4.2 Problèmes identifiés

**a) `api.insecure: true` — exposition du dashboard.** Cette directive est la cause
directe de l'ouverture du port 8080 : le tableau de bord et l'API d'administration
sont exposés en **HTTP clair, sans authentification, sur toutes les interfaces**
(`*:8080`). La documentation Traefik réserve ce mode au débogage local et
déconseille formellement son emploi en production. C'est l'équivalent moderne d'une
console d'administration laissée ouverte : le point le plus critique à traiter.

**b) `providers.file` pointe vers un fichier inexistant.** La configuration référence
`/etc/traefik/dynamic.yml`, mais ce fichier est absent (le répertoire `/etc/traefik`
ne contient que `traefik.yml`). Le service journalise en conséquence :

```
ERR Cannot start the provider *file.Provider
error="error adding file watcher: no such file or directory"
```

Conséquence importante : **aucun routeur, aucun service amont et aucun certificat ne
sont définis**. Le port 443 est ouvert mais ne dessert rien ; le reverse proxy ne
proxifie aucun trafic dans son état actuel. Le durcissement devra donc créer cette
configuration dynamique pour que le port 443 ait une fonction réelle (terminaison
TLS et routage vers un service).

**c) Absence de configuration TLS / ACME.** Aucun résolveur de certificats ni aucune
option TLS n'est défini. Des certificats sont pourtant présents sur le système
(`/etc/pki/tls/certs/edge.crt`), prêts à être branchés en terminaison TLS statique.

### 4.3 Service systemd

Fichier `/etc/systemd/system/traefik.service` :

```ini
[Unit]
Description=Traefik Reverse Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml
Restart=always

[Install]
WantedBy=multi-user.target
```

Deux faiblesses majeures :

- **Exécution en `root`.** Un processus exposé en frontal sur Internet dispose des
  pleins pouvoirs sur la machine en cas de compromission. Le contexte SELinux
  confirme l'absence de confinement : `system_u:system_r:unconfined_service_t`. Un
  compte de service dédié `svc-traefik` (uid 993) existe déjà sur le système mais
  **n'est pas utilisé**.
- **Aucun cloisonnement systemd.** L'unit n'active aucune des protections
  disponibles (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, restriction des
  appels système, etc.), alors que le rôle s'y prête parfaitement.

## 5. Comptes, groupes et privilèges

### 5.1 Comptes interactifs (`/etc/passwd`, shells de login)

| Compte | UID | Shell | Évaluation |
|---|---|---|---|
| admin | 1000 | /bin/bash | Administrateur légitime |
| admin-traefik | 1001 | /bin/bash | À évaluer (compte humain, dans `wheel`) |
| admin-dns | 1002 | /bin/bash | Hors périmètre (pas de DNS sur ce serveur) |
| staiaire | 1003 | /bin/bash | À traiter (compte nominatif, présent dans `wheel`) |
| test | 1004 | /bin/bash | À supprimer (compte de test, **sudoer**) |
| backup | 1005 | /bin/bash | À traiter (**sudoer NOPASSWD**, shell interactif) |
| svc-traefik | 993 | /sbin/nologin | Compte de service (à utiliser pour Traefik) |

### 5.2 Privilèges sudo

Extrait de `/etc/sudoers` :

```
root         ALL=(ALL)       ALL
admin        ALL=(ALL)       NOPASSWD: ALL
admin-traefik ALL=(ALL) ALL
test         ALL=(ALL)       ALL
staiaire     ALL=(ALL)       ALL
backup       ALL=(ALL)       NOPASSWD: ALL
%wheel       ALL=(ALL)       ALL
```

Groupe `wheel` : `admin, test, staiaire, admin-traefik`.

Problèmes :

- **`admin` et `backup` en `NOPASSWD: ALL`.** Toute compromission de l'une de ces
  sessions (vol de session, clé SSH dérobée) donne un accès root **sans même
  connaître de mot de passe**. Le `NOPASSWD` doit être retiré.
- **Multiplication des sudoers** : `test`, `staiaire`, `backup` cumulent un shell
  interactif et des droits sudo complets, sans rapport avec le rôle du serveur.
- **`backup` avec un shell `/bin/bash`** : un compte de sauvegarde n'a pas besoin
  d'une session interactive ni de sudo complet.

## 6. Contrôle d'accès local — SELinux

| Élément | Valeur |
|---|---|
| Statut | enabled |
| Mode courant | **enforcing** |
| Mode fichier de conf | enforcing |
| Politique chargée | targeted |

SELinux est actif et en mode enforcing, ce qui constitue un acquis. Le seul point
faible relevé est que **Traefik s'exécute dans le domaine non confiné**
(`unconfined_service_t`) du fait de son lancement en root via un binaire hors des
emplacements standard. Le confinement effectif du proxy passera d'abord par son
exécution sous compte de service dédié.

## 7. Pare-feu — firewalld

Zone active `public` (interface `ens33`) :

```
services: cockpit dhcpv6-client http https ssh
ports:    8080/tcp 80/tcp 443/tcp
```

La zone autorise explicitement :

- `8080/tcp` : laisse passer le dashboard insecure (à retirer) ;
- le service `cockpit` (port 9090, à retirer) ;
- `http`/`https` (80/443) et le port 80/443 en doublon : nécessaires ;
- `ssh` : nécessaire mais ouvert à toutes les sources, à restreindre au réseau
  d'administration.

Le port 21 (vsftpd) n'est pas listé dans la zone : il est aujourd'hui filtré par
firewalld, mais le service tourne malgré tout et sera supprimé à la source.

## 8. Protection contre les tentatives d'authentification — fail2ban

Une jail `sshd` est active. Sa configuration (`/etc/fail2ban/jail.local`) est
toutefois très permissive :

```
[DEFAULT]
bantime  = 60
findtime = 600
maxretry = 50

[sshd]
enabled  = true
maxretry = 50
```

- `maxretry = 50` autorise cinquante échecs avant blocage : largement trop élevé
  pour être dissuasif.
- `bantime = 60` ne bannit l'attaquant qu'une minute.

Par ailleurs, un filtre `traefik-auth` est fourni par le paquet
(`/etc/fail2ban/filter.d/traefik-auth.conf`) mais **aucune jail `traefik-auth` n'est
active**, et Traefik n'écrit pas de journal d'accès — il n'y a donc aujourd'hui
aucune protection des authentifications côté proxy.

## 9. Certificats

Certificats présents sur le système :

```
/etc/ssl/cert.pem
/etc/pki/tls/cert.pem
/etc/pki/tls/certs/ca-bundle.crt
/etc/pki/tls/certs/ca-bundle.trust.crt
/etc/pki/tls/certs/edge.crt
```

`edge.crt` est le certificat destiné à la terminaison TLS du reverse proxy. Il
n'est pour l'heure **référencé nulle part** dans la configuration de Traefik (cf.
§4.2), faute de configuration dynamique. Sa mise en service fait partie du
durcissement (terminaison TLS sur le port 443).

## 10. Synthèse de la surface d'attaque

### 10.1 Éléments à conserver et durcir

| Composant | Port | Action de durcissement |
|---|---|---|
| Traefik (entrée web) | 80 | Rediriger vers 443 |
| Traefik (entrée sécurisée) | 443 | Configurer TLS + routage (dynamic.yml) |
| Dashboard Traefik | (interne) | HTTPS + authentification + accès LAN uniquement |
| SSH | 22 | Restreindre la source, durcir sshd, fail2ban |

### 10.2 Éléments à corriger ou éliminer

| Famille | Élément | Risque principal |
|---|---|---|
| Configuration dangereuse | `api.insecure: true` → dashboard 8080 | Administration du proxy sans authentification |
| Exécution privilégiée | Traefik en root, unit non cloisonnée | Compromission totale en cas de faille du proxy |
| Services hors périmètre | vsftpd 21, cups 631, avahi 5353, cockpit 9090 | Surface et vulnérabilités inutiles |
| Comptes & privilèges | `test`, `backup`, `staiaire`, `admin-dns` ; `NOPASSWD` | Élévation de privilèges, comptes superflus |
| Filtrage trop large | SSH ouvert à tous, 8080 et cockpit autorisés | Exposition de l'administration |
| Anti-bruteforce faible | fail2ban `maxretry=50`, jail traefik absente | Bruteforce SSH et dashboard peu entravés |

### 10.3 Conclusion

Le serveur remplit un rôle simple — reverse proxy — mais expose une surface
nettement plus large que ce rôle n'exige : un tableau de bord d'administration
ouvert sans authentification, un proxy exécuté en root sans cloisonnement, quatre
services sans rapport avec sa fonction, des comptes et des privilèges sudo
excessifs, un filtrage réseau trop permissif et une protection anti-bruteforce
symbolique. Le durcissement consiste à **ramener le système à son rôle** :
sécuriser puis cloisonner Traefik, rendre le port 443 réellement fonctionnel,
supprimer les services superflus, reprendre comptes et privilèges, resserrer le
pare-feu autour de 80/443 et d'un SSH restreint, et renforcer fail2ban — le tout
en préservant la fonction de reverse proxy.
