**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 4
## Analyse et durcissement d'un reverse proxy Linux

| | |
|---|---|
| **Système cible** | Reverse proxy Traefik (AlmaLinux 10.2) |
| **Document** | Partie 2 — Plan de durcissement |
| **Auteur** | Raian Remir |
| **Date** | Juin 2026 |
| **Version** | 1.0 |
| **Diffusion** | Usage pédagogique |

---

## Sommaire

1. Sécurisation du tableau de bord Traefik
2. Exécution en compte non privilégié
3. Cloisonnement systemd du service
4. Suppression des services superflus
5. Gestion des comptes et des privilèges
6. Filtrage réseau (firewalld)
7. Durcissement de SSH
8. Protection contre le bruteforce (fail2ban)
9. Validation finale et synthèse

---

Chaque mesure suit la structure : état initial, mesures appliquées, vérification
(avec la sortie réelle relevée), état final. La cible est AlmaLinux 10.2 (systemd,
firewalld, SELinux enforcing). Avant toute action, un instantané de la machine
virtuelle est réalisé ; après chaque étape, le fonctionnement du reverse proxy est
contrôlé. L'accès s'effectue par SSH (`admin@192.168.5.131`) ou par la console de
la machine virtuelle. Les mots de passe indiqués sont des placeholders
(`<MDP_DASHBOARD>`, etc.) à remplacer par des mots de passe forts.

État de référence des ports avant durcissement (`sudo ss -tulpn`) :

| Port | Service | Rôle |
|---|---|---|
| 22 | sshd | Nécessaire |
| 80 | traefik | Nécessaire (servait le dashboard en clair) |
| 443 | traefik | Ouvert mais ne desservait rien |
| 8080 | traefik | Dashboard insecure, HTTP clair, sans auth |
| 9090 | cockpit | Inutile |
| 21 | vsftpd | Inutile |
| 631 | cups | Inutile |
| 5353 | avahi-daemon | Inutile |
| 323 | chronyd | Nécessaire (déjà en écoute locale) |

## Thème 1 — Sécurisation du dashboard Traefik

**État initial.** La configuration statique `/etc/traefik/traefik.yml` activait
`api.insecure: true`, exposant le tableau de bord et l'API d'administration sur le
port 8080, en HTTP clair, sans authentification et sur toutes les interfaces. Par
ailleurs le provider fichier pointait vers `/etc/traefik/dynamic.yml`, **absent** du
système : aucun routeur ni certificat n'était défini, le port 443 était ouvert mais
ne desservait rien, et le service journalisait en boucle
`error adding file watcher: no such file or directory`.

Relevé initial :
```
$ sudo ss -tulpn | grep -E ':8080|:443|:80 '
tcp  *:80    LISTEN  traefik
tcp  *:443   LISTEN  traefik
tcp  *:8080  LISTEN  traefik

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://192.168.5.131:8080/dashboard/
HTTP 200
```

**Mesures.**

1. Réécriture de la configuration statique : `api.insecure: false` (fermeture du
   port 8080), activation du journal d'accès (exploité au thème 9), et redirection
   systématique du point d'entrée web (80) vers websecure (443).

`/etc/traefik/traefik.yml` :
```yaml
global:
  checkNewVersion: false
  sendAnonymousUsage: false
api:
  dashboard: true
  insecure: false
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
log:
  level: INFO
  filePath: "/var/log/traefik/traefik.log"
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
providers:
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true
```

2. Génération d'un identifiant Basic Auth pour le dashboard (paquet `httpd-tools`) :
```bash
sudo dnf install -y httpd-tools
htpasswd -nbB admin '<MDP_DASHBOARD>'
```

3. Création de la configuration dynamique manquante `/etc/traefik/dynamic.yml` :
   terminaison TLS avec le certificat `edge.crt`, options TLS modernes (TLS 1.2
   minimum), routeur du dashboard (`api@internal`) protégé par trois middlewares
   (restriction au LAN `192.168.5.0/24`, authentification, en-têtes de sécurité), et
   routeur de démonstration vers un backend local. Les `$` du hash sont doublés
   (`$$`) pour ne pas être interprétés comme des variables.

```yaml
tls:
  certificates:
    - certFile: /etc/pki/tls/certs/edge.crt
      keyFile: /etc/pki/tls/private/edege.key
  options:
    modern:
      minVersion: VersionTLS12
      sniStrict: false
http:
  middlewares:
    lan-only:
      ipAllowList:
        sourceRange:
          - 127.0.0.1/32
          - 192.168.5.0/24
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$$2y$$05$$...hash..."
    secure-headers:
      headers:
        stsSeconds: 31536000
        frameDeny: true
        contentTypeNosniff: true
  routers:
    dashboard:
      rule: "PathPrefix(`/api`) || PathPrefix(`/dashboard`)"
      entryPoints: [websecure]
      service: api@internal
      middlewares: [lan-only, dashboard-auth, secure-headers]
      tls:
        options: modern
    demo:
      rule: "PathPrefix(`/`)"
      entryPoints: [websecure]
      service: demo-svc
      middlewares: [secure-headers]
      tls:
        options: modern
  services:
    demo-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8088/"
```

4. Mise en place du backend de démonstration servi en loopback sur `127.0.0.1:8088`
   par un service systemd cloisonné, afin de donner une fonction réelle au port 443 :
```bash
sudo mkdir -p /var/www/demo /var/log/traefik
# page index.html dans /var/www/demo
sudo systemctl enable --now demo-backend.service
sudo systemctl restart traefik
```

**Vérification.**
```
$ sudo python3 -c "import yaml; yaml.safe_load(open('/etc/traefik/dynamic.yml')); print('YAML OK')"
YAML OK

$ sudo ss -tulpn | grep traefik
tcp  *:80   LISTEN  traefik
tcp  *:443  LISTEN  traefik
(plus de port 8080)

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" --max-time 5 http://192.168.5.131:8080/dashboard/
HTTP 000   (connexion refusée)

$ curl -s -o /dev/null -w "HTTP %{http_code} -> %{redirect_url}\n" http://192.168.5.131/
HTTP 301 -> https://192.168.5.131/

$ curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/
HTTP 200

$ curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/dashboard/
HTTP 401

$ curl -sk -u admin:'<MDP_DASHBOARD>' -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/dashboard/
HTTP 200

$ curl -sk https://192.168.5.131/ | grep -i "démonstration"
  <h1>Service de démonstration</h1>
```

**État final.** Le port 8080 est fermé. Le dashboard n'est plus accessible qu'en
HTTPS, derrière une authentification, et uniquement depuis le réseau
192.168.5.0/24. Le trafic HTTP est redirigé vers HTTPS. Le port 443 est désormais
fonctionnel : terminaison TLS et routage vers un service réel. Le reverse proxy
remplit effectivement son rôle.

## Thème 2 — Exécution de Traefik en compte non privilégié

**État initial.** Le service `traefik.service` lançait le proxy en `root`
(`User=root`), exposé en frontal, sans aucun cloisonnement. Le contexte SELinux
confirmait l'absence de confinement (`unconfined_service_t`). Un compte de service
dédié `svc-traefik` (uid 993, `/sbin/nologin`) existait mais n'était pas utilisé.

```
$ ps -o user,pid,cmd -C traefik
USER  PID  CMD
root  994  /usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml
```

**Mesures.**

1. Attribution à `svc-traefik` des droits nécessaires : propriété du répertoire de
   logs, et lecture de la clé privée TLS via le groupe (sans l'ouvrir à tous) :
```bash
sudo chown -R svc-traefik:svc-traefik /var/log/traefik
sudo chmod 750 /var/log/traefik
sudo chown root:svc-traefik /etc/pki/tls/private/edege.key
sudo chmod 640 /etc/pki/tls/private/edege.key
```

2. Réécriture de l'unit `traefik.service` : exécution en `svc-traefik`, et octroi de
   la seule capacité `CAP_NET_BIND_SERVICE`, qui autorise la liaison aux ports
   inférieurs à 1024 (80 et 443) **sans privilèges root**.
```ini
[Service]
User=svc-traefik
Group=svc-traefik
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

**Vérification.**
```
$ ps -o user,pid,cmd -C traefik
USER      PID   CMD
svc-tra+  3170  /usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml

$ sudo ss -tulpn | grep traefik
tcp  *:80   LISTEN  traefik (pid=3170)
tcp  *:443  LISTEN  traefik (pid=3170)

$ curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/
HTTP 200
$ curl -sk -u admin:'<MDP_DASHBOARD>' -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/dashboard/
HTTP 200
```

**État final.** Traefik s'exécute sous un compte non privilégié. Il conserve la
liaison aux ports 80 et 443 grâce à la seule capacité `CAP_NET_BIND_SERVICE`. Une
compromission du proxy ne donne plus un accès root à la machine.

## Thème 3 — Cloisonnement systemd du service Traefik

**État initial.** L'unit `traefik.service` n'activait aucune des protections
systemd disponibles (accès complet au système de fichiers, aux appels système, aux
périphériques, etc.).

**Mesures.** Ajout d'un jeu de directives de cloisonnement à l'unit (appliquées
dans le même fichier que le thème 2) :
```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
ReadWritePaths=/var/log/traefik
```

`ProtectSystem=strict` rend l'ensemble du système de fichiers en lecture seule,
`ReadWritePaths` rouvrant uniquement le répertoire de logs. `SystemCallFilter`
restreint le service aux appels système d'un service standard (liste blanche),
`MemoryDenyWriteExecute` interdit les pages mémoire à la fois inscriptibles et
exécutables (anti-exploitation).

**Vérification.**
```
$ sudo systemctl show traefik -p User -p NoNewPrivileges -p ProtectSystem -p AmbientCapabilities -p MemoryDenyWriteExecute
User=svc-traefik
AmbientCapabilities=cap_net_bind_service
NoNewPrivileges=yes
ProtectSystem=strict
MemoryDenyWriteExecute=yes
SystemCallFilter=_llseek _newselect accept accept4 access add_key alarm ... (liste blanche)

$ sudo systemctl status traefik --no-pager | grep Active
Active: active (running)
```

**État final.** Le service Traefik est fortement cloisonné : système de fichiers en
lecture seule hormis ses logs, appels système restreints à une liste blanche,
mémoire non exécutable-inscriptible, isolation des périphériques et du noyau. Le
service reste pleinement fonctionnel.

**Limite.** Le contexte SELinux du process demeure `unconfined_service_t` : un
confinement SELinux fin nécessiterait l'écriture d'une politique dédiée (le binaire
résidant hors des emplacements standard couverts par la politique `targeted`), ce
qui dépasse le périmètre du TP. L'isolation est néanmoins assurée par l'abandon des
privilèges root (thème 2) et le cloisonnement systemd ci-dessus.

## Thème 4 — Suppression des services inutiles

**État initial.** Quatre services sans rapport avec le rôle de reverse proxy étaient
actifs : vsftpd (FTP, port 21), cups (impression, port 631), avahi-daemon (mDNS,
port 5353) et cockpit (administration web, port 9090).

```
$ for s in vsftpd cups avahi-daemon cockpit.socket; do systemctl is-active $s; done
vsftpd        : active
cups          : active
avahi-daemon  : active
cockpit.socket: active

$ sudo ss -tulpn | grep -E ':21 |:631|:5353|:9090'
udp  0.0.0.0:5353   avahi-daemon
tcp  127.0.0.1:631  cupsd
tcp  *:21           vsftpd
tcp  *:9090         systemd (cockpit)
```

**Mesures.** Arrêt, désactivation et masquage de chaque service. Les sockets
associés (`cups.socket`, `avahi-daemon.socket`, `cockpit.socket`) sont également
masqués, car sous systemd c'est le socket qui réactive le service à la demande :
désactiver le seul `.service` laisserait le port se rouvrir au premier accès. Le
masquage (`mask`) crée un lien vers `/dev/null` qui interdit tout démarrage.
```bash
for s in vsftpd cups cups.socket cups.path avahi-daemon avahi-daemon.socket cockpit.socket cockpit; do
  sudo systemctl stop $s
  sudo systemctl disable $s
  sudo systemctl mask $s
done
```

**Vérification.**
```
$ for s in vsftpd cups avahi-daemon cockpit.socket; do
    printf "%-20s : active=%s | %s\n" "$s" "$(systemctl is-active $s)" "$(systemctl is-enabled $s)"
  done
vsftpd         : active=inactive | masked
cups           : active=inactive | masked
avahi-daemon   : active=inactive | masked
cockpit.socket : active=inactive | masked

$ sudo ss -tulpn | grep -E ':21 |:631|:5353|:9090'
Aucun de ces ports n'écoute (objectif atteint)

$ sudo ss -tulpn
udp  127.0.0.1:323   chronyd     (NTP, loopback)
tcp  0.0.0.0:22      sshd        (SSH)
tcp  127.0.0.1:8088  python3     (backend démo, loopback)
tcp  *:80            traefik     (HTTP -> HTTPS)
tcp  *:443           traefik     (HTTPS)

$ curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://192.168.5.131/
HTTP 200
```

**État final.** Les quatre services inutiles sont arrêtés, désactivés et masqués.
La surface réseau exposée se réduit à trois ports nécessaires (22, 80, 443) ; les
services chronyd (NTP) et le backend de démonstration n'écoutent qu'en loopback et
ne sont pas accessibles depuis le réseau. Le reverse proxy reste fonctionnel.

## Thème 5 — Gestion des comptes et des privilèges

**État initial.** Plusieurs comptes interactifs sans rapport avec le rôle du serveur
et des privilèges sudo excessifs :
```
$ grep -vE 'nologin|/false' /etc/passwd   (comptes humains)
admin, admin-traefik, admin-dns, staiaire, test, backup  (tous /bin/bash)

$ sudo grep -E 'ALL|NOPASSWD' /etc/sudoers
admin          ALL=(ALL)  NOPASSWD: ALL
admin-traefik  ALL=(ALL)  ALL
test           ALL=(ALL)  ALL
staiaire       ALL=(ALL)  ALL
backup         ALL=(ALL)  NOPASSWD: ALL
%wheel         ALL=(ALL)  ALL

$ getent group wheel
wheel:x:10:admin,test,staiaire,admin-traefik
```

Problèmes : `admin` et `backup` en `NOPASSWD: ALL` (root sans mot de passe) ;
comptes de test (`test`), nominatif (`staiaire`) et hors périmètre (`admin-dns`,
pas de service DNS) dotés d'un shell interactif et, pour certains, de sudo complet ;
`backup` avec un shell interactif alors qu'un compte de sauvegarde n'en a pas besoin.

**Mesures.** Traitées dans un ordre préservant l'accès administrateur : les comptes
superflus d'abord, le retrait du `NOPASSWD` d'`admin` en dernier, après vérification
de la connaissance de son mot de passe.

1. Verrouillage des comptes superflus et suppression de leur shell interactif
   (verrouillage réversible) :
```bash
for u in test staiaire admin-dns; do sudo passwd -l $u; sudo usermod -s /sbin/nologin $u; done
sudo usermod -s /sbin/nologin backup
```

2. Nettoyage du groupe `wheel` (retrait des comptes superflus, conservation des
   administrateurs légitimes) :
```bash
sudo gpasswd -d test wheel
sudo gpasswd -d staiaire wheel
```

3. Réécriture des règles sudo : suppression des lignes `test`, `staiaire` et du
   `NOPASSWD` de `backup`, puis retrait du `NOPASSWD` d'`admin`. Édition validée par
   `visudo -c` à chaque étape :
```bash
sudo cp /etc/sudoers /etc/sudoers.bak
sudo sed -i -E '/^test[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL/d' /etc/sudoers
sudo sed -i -E '/^staiaire[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL/d' /etc/sudoers
sudo sed -i -E '/^backup[[:space:]]+ALL=\(ALL\)[[:space:]]+NOPASSWD:[[:space:]]+ALL/d' /etc/sudoers
sudo sed -i -E 's%^admin[[:space:]]+ALL=\(ALL\)[[:space:]]+NOPASSWD:[[:space:]]+ALL%admin   ALL=(ALL)       ALL%' /etc/sudoers
sudo visudo -c
```

**Vérification.**
```
$ sudo visudo -c
/etc/sudoers: parsed OK

$ sudo grep -E 'ALL|NOPASSWD' /etc/sudoers   (lignes actives)
root           ALL=(ALL)  ALL
admin          ALL=(ALL)  ALL
admin-traefik  ALL=(ALL)  ALL
%wheel         ALL=(ALL)  ALL

$ sudo -k; sudo -l
[sudo] password for admin:        <- le mot de passe est désormais demandé

$ for u in admin admin-traefik admin-dns staiaire test backup svc-traefik; do
    printf "%-15s : statut=%s | shell=%s\n" "$u" "$(sudo passwd -S $u | awk '{print $2}')" "$(getent passwd $u | cut -d: -f7)"
  done
admin          : statut=P | shell=/bin/bash
admin-traefik  : statut=P | shell=/bin/bash
admin-dns      : statut=L | shell=/sbin/nologin
staiaire       : statut=L | shell=/sbin/nologin
test           : statut=L | shell=/sbin/nologin
backup         : statut=P | shell=/sbin/nologin
svc-traefik    : statut=L | shell=/sbin/nologin

$ getent group wheel
wheel:x:10:admin,admin-traefik
```

**État final.** Plus aucun privilège sudo sans mot de passe. Les comptes de test,
nominatif et hors périmètre sont verrouillés et privés de shell interactif. Le
compte de sauvegarde conserve son existence mais perd sa session interactive. Le
groupe `wheel` et les règles sudo sont réduits aux deux administrateurs légitimes
(`admin`, `admin-traefik`). Les comptes superflus, verrouillés à ce stade, pourront
être supprimés (`userdel`) en fin de durcissement après confirmation qu'aucun
service n'en dépend.

## Thème 6 — Filtrage réseau (firewalld)

**État initial.** La zone `public` autorisait, au-delà du nécessaire, le port 8080
(dashboard insecure), le service `cockpit` (port 9090) et le service `ssh` ouvert à
toutes les sources.
```
$ sudo firewall-cmd --list-all
public (default, active)
  services: cockpit dhcpv6-client http https ssh
  ports:    8080/tcp 80/tcp 443/tcp
  rich rules:
```

**Mesures.** Réalisées dans un ordre préservant la session SSH : la règle
autorisant SSH depuis le LAN est ajoutée et activée **avant** le retrait du service
SSH global.

1. Autoriser SSH uniquement depuis le réseau d'administration (rich rule) :
```bash
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.5.0/24" service name="ssh" accept'
sudo firewall-cmd --reload
```
(Validation par ouverture d'une seconde session SSH avant de poursuivre.)

2. Retirer le SSH global, le port 8080, cockpit et dhcpv6-client (non utilisé) :
```bash
sudo firewall-cmd --permanent --zone=public --remove-service=ssh
sudo firewall-cmd --permanent --zone=public --remove-port=8080/tcp
sudo firewall-cmd --permanent --zone=public --remove-service=cockpit
sudo firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
sudo firewall-cmd --reload
```

**Vérification.**
```
$ sudo firewall-cmd --list-all
public (default, active)
  services: http https
  ports:    80/tcp 443/tcp
  rich rules:
        rule family="ipv4" source address="192.168.5.0/24" service name="ssh" accept

$ curl -s -o /dev/null -w "HTTP 80: %{http_code}\n" http://192.168.5.131/
HTTP 80: 301
$ curl -sk -o /dev/null -w "HTTPS 443: %{http_code}\n" https://192.168.5.131/
HTTPS 443: 200
```
La session SSH reste active (preuve que le port 22 demeure joignable depuis le LAN).

**État final.** Le pare-feu n'autorise plus que le trafic web (80/443, services
`http`/`https`) à toutes les sources, et SSH (port 22) uniquement depuis le réseau
192.168.5.0/24. Le dashboard insecure (8080) et l'administration cockpit (9090) ne
sont plus autorisés au niveau réseau, en cohérence avec la suppression des services
correspondants.

## Thème 7 — Durcissement de SSH

**État initial.** Le fichier principal `/etc/ssh/sshd_config` portait des valeurs
permissives (`PermitRootLogin yes`, `PasswordAuthentication yes`, `MaxAuthTries 10`,
`X11Forwarding yes`). Sur AlmaLinux, la configuration effective se gère par fichiers
drop-in dans `/etc/ssh/sshd_config.d/`, prioritaires sur le fichier principal.

**Mesures.** Conformément à la bonne pratique de la distribution, le durcissement
est appliqué via un fichier drop-in dédié `01-hardening.conf` plutôt qu'en éditant
le fichier principal. La démarche préserve l'accès : une clé est générée et déposée,
la connexion par clé est testée et validée, puis seulement l'authentification par
mot de passe est désactivée.

1. Génération d'une paire de clés sur le poste d'administration (ed25519, supporté
   par l'OpenSSH récent d'AlmaLinux) et dépôt de la clé publique :
```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\tp4_proxy -C "admin-tp4"
type $env:USERPROFILE\.ssh\tp4_proxy.pub | ssh admin@192.168.5.131 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

2. Création d'un raccourci de connexion dans `%USERPROFILE%\.ssh\config` sur le
   poste d'administration, afin de simplifier les connexions ultérieures (la clé et
   l'utilisateur étant mémorisés, la commande `ssh proxy-tp4` suffit) :
```
Host proxy-tp4
    HostName 192.168.5.131
    User admin
    IdentityFile ~/.ssh/tp4_proxy
    IdentitiesOnly yes
```

3. Test de la connexion par clé **avant** tout durcissement (filet de sécurité),
   via le raccourci :
```powershell
ssh proxy-tp4 "echo 'Connexion par clé OK'"
```

4. Fichier `/etc/ssh/sshd_config.d/01-hardening.conf` :
```
# === Durcissement SSH (TP4) ===
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
```
puis `sudo systemctl reload sshd`.

**Vérification.**
```
$ sudo sshd -T | grep -iE '^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|maxauthtries)'
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
x11forwarding no
maxauthtries 3

$ sudo journalctl -u sshd | grep "Accepted" | tail -1
Accepted publickey for admin from 192.168.5.1 port 3592 ssh2: ED25519 SHA256:...

# Depuis le poste d'administration :
PS> ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password admin@192.168.5.131 "echo test"
admin@192.168.5.131: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

PS> ssh -i $env:USERPROFILE\.ssh\tp4_proxy admin@192.168.5.131 "echo cle-ok"
cle-ok

PS> ssh proxy-tp4 "echo cle-ok"
cle-ok
```

**État final.** L'authentification SSH se fait exclusivement par clé (ed25519) ; la
connexion root est interdite, l'authentification par mot de passe et les mots de
passe vides sont refusés, le nombre de tentatives est limité à trois et le transfert
X11 est désactivé. Le rejet effectif de l'authentification par mot de passe et le
bon fonctionnement de la clé sont vérifiés depuis le poste d'administration. Combiné
au filtrage du port 22 sur le LAN (thème 6), l'accès distant est doublement
restreint.

## Thème 8 — Protection contre le bruteforce (fail2ban)

**État initial.** Une jail `sshd` était active mais très permissive (`maxretry = 50`,
`bantime = 60`, soit cinquante tentatives tolérées et un bannissement d'une minute).
Aucune jail ne protégeait l'authentification du reverse proxy, et Traefik n'écrivait
pas de journal d'accès exploitable.
```
$ sudo fail2ban-client get sshd maxretry
50
$ sudo fail2ban-client get sshd bantime
60
```

**Mesures.**

1. Configuration de l'accessLog de Traefik au format CLF (`common`), exploité par
   fail2ban, et écriture immédiate (`bufferingSize: 0`) — modification du
   `traefik.yml` (le format JSON initial était incompatible avec les filtres CLF).

2. Constat d'une particularité de Traefik : les rejets d'authentification du
   tableau de bord interne (`api@internal`) ne sont pas écrits dans l'accessLog. Pour
   disposer de journaux d'échec exploitables, le middleware d'authentification est
   ajouté au routeur de démonstration (service `file` classique), dont les réponses
   401 sont, elles, journalisées.

3. Écriture d'un filtre adapté au format CLF réel de Traefik
   (`/etc/fail2ban/filter.d/traefik-custom.conf`), le filtre `traefik-auth` fourni
   ne correspondant pas au format produit :
```
[Definition]
failregex = ^<HOST> .*" (?:401|403) \d
datepattern = \[%%d/%%b/%%Y:%%H:%%M:%%S %%z\]
ignoreregex =
```

4. Configuration des jails (`/etc/fail2ban/jail.local`) : durcissement de `sshd`
   (backend systemd) et activation de la jail `traefik-auth` (backend fichier) :
```
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 4
ignoreip = 127.0.0.1/8 192.168.5.0/24

[sshd]
enabled = true
backend = systemd
maxretry = 4
bantime = 3600

[traefik-auth]
enabled = true
filter  = traefik-custom
logpath = /var/log/traefik/access.log
maxretry = 4
bantime = 3600
```

5. Correction des permissions du répertoire de logs (`chmod 755 /var/log/traefik`)
   pour que fail2ban puisse lire le journal (les permissions `750` du thème 2 le lui
   interdisaient).

**Vérification.** La chaîne complète a été validée de bout en bout. Test du filtre
sur le journal réel :
```
$ sudo fail2ban-regex /var/log/traefik/access.log /etc/fail2ban/filter.d/traefik-custom.conf
Lines: 8 lines, 0 ignored, 7 matched, 1 missed
```
Détection et bannissement automatiques (après dépassement de `maxretry`) :
```
$ sudo fail2ban-client status traefik-auth
Status for the jail: traefik-auth
|- Filter
|  |- Total failed:     6
|  `- File list:        /var/log/traefik/access.log
`- Actions
   |- Currently banned: 1
   `- Banned IP list:   192.168.5.99

$ sudo firewall-cmd --list-rich-rules | grep 192.168.5.99
rule family="ipv4" source address="192.168.5.99" port port="https" protocol="tcp" reject
rule family="ipv4" source address="192.168.5.99" port port="http" protocol="tcp" reject
```

**État final.** Deux jails opérationnelles : `sshd` (durcie, `maxretry` ramené de 50
à 4, `bantime` de 60 s à 1 h, détection via le journal systemd) et `traefik-auth`
(détection des réponses 401/403 du reverse proxy, bannissement automatique via
firewalld). La chaîne tentative échouée → journalisation → détection → bannissement
est démontrée : l'IP fautive est rejetée sur les ports http et https. La liste
blanche `ignoreip` préserve le réseau d'administration.

## Validation finale de l'état du système

Après application des huit thèmes, une vérification globale confirme la cohérence de
l'état final : Traefik fonctionne sous compte non privilégié, seuls les trois ports
nécessaires sont exposés, et l'ensemble des contrôles d'accès se comporte comme
attendu.

```
$ sudo systemctl status traefik | grep -E 'Active|Main PID'
Active: active (running)
Main PID: 2710 (traefik)
$ ps -o user -C traefik --no-headers | head -1
svc-traefik

$ sudo ss -tulpn | grep -vE '127.0.0.1|::1'
tcp  LISTEN  0.0.0.0:22   sshd
tcp  LISTEN  *:443        traefik
tcp  LISTEN  *:80         traefik

$ curl -s  -o /dev/null -w "HTTP 80 (redirect): %{http_code}\n"  http://192.168.5.131/
HTTP 80 (redirect): 301
$ curl -sk -o /dev/null -w "HTTPS demo sans auth: %{http_code}\n" https://192.168.5.131/
HTTPS demo sans auth: 401
$ curl -sk -u admin:<MDP> -o /dev/null -w "HTTPS demo avec auth: %{http_code}\n" https://192.168.5.131/
HTTPS demo avec auth: 200
$ curl -sk -u admin:<MDP> -o /dev/null -w "Dashboard avec auth: %{http_code}\n" https://192.168.5.131/dashboard/
Dashboard avec auth: 200
$ curl -sk -o /dev/null -w "Dashboard sans auth: %{http_code}\n" https://192.168.5.131/dashboard/
Dashboard sans auth: 401
```

Cette validation synthétise l'aboutissement du durcissement : surface réseau réduite
à trois ports (22 filtré sur le LAN, 80, 443), proxy exécuté sous `svc-traefik`,
redirection HTTP vers HTTPS effective, et authentification exigée aussi bien sur le
service exposé que sur le tableau de bord d'administration.

## Récapitulatif

| Thème | Mesure | Impact métier |
|---|---|---|
| 1 | Sécurisation du dashboard Traefik (HTTPS + Basic Auth + LAN), fermeture du port 8080, création du dynamic.yml, redirection 80→443 | reverse proxy rendu fonctionnel |
| 2 | Exécution de Traefik en compte non privilégié `svc-traefik` (CAP_NET_BIND_SERVICE) | aucun |
| 3 | Cloisonnement systemd du service (ProtectSystem, NoNewPrivileges, SystemCallFilter…) | aucun |
| 4 | Suppression des services inutiles (vsftpd, cups, avahi, cockpit) | aucun |
| 5 | Comptes et privilèges (retrait NOPASSWD, comptes superflus verrouillés, wheel et sudoers nettoyés) | aucun |
| 6 | Filtrage firewalld (http/https seuls, SSH restreint au LAN, 8080/9090/cockpit fermés) | aucun |
| 7 | Durcissement SSH (clé uniquement, root interdit, MaxAuthTries 3, X11 off) | administration par clé |
| 8 | fail2ban (jail SSH durcie + jail traefik-auth, ban firewalld sur les 401) | démo authentifiée |

État des ports, avant et après :

| | Avant | Après |
|---|---|---|
| Ports exposés au réseau | 9 (21, 22, 80, 443, 8080, 9090, 631, 5353, 323) | 3 (22 filtré LAN, 80, 443) |
| Dashboard d'administration | port 8080, HTTP clair, sans authentification | HTTPS, Basic Auth, LAN uniquement |
| Exécution de Traefik | root, non cloisonné | `svc-traefik`, cloisonné (systemd) |
| Port 443 | ouvert mais ne dessert rien | terminaison TLS + routage fonctionnels |
| SSH | root autorisé, mot de passe, ouvert à tous | clé uniquement, root interdit, LAN uniquement |
| Privilèges sudo | `admin` et `backup` en NOPASSWD | mot de passe requis, comptes superflus verrouillés |
| Anti-bruteforce | jail SSH `maxretry=50`, `bantime=60` | jails SSH + traefik-auth, `maxretry=4`, `bantime=3600` |

La surface d'attaque passe de neuf services exposés, dont un tableau de bord
d'administration ouvert sans authentification et un proxy exécuté en root, à trois
services nécessaires, le reverse proxy étant cloisonné, authentifié et rendu
réellement fonctionnel. La correction de fond des deux limites résiduelles (contexte
SELinux du proxy, certificat auto-signé) relève respectivement d'une politique
SELinux dédiée et d'une PKI, hors périmètre de ce travail.
