# TODO
- Wazuh 4.7
  - File integrity monitoring
  - Active response for attack
  - CIS
  - Mail alert
- Suricata 7.0.4
  - Detect port scan
  - Detect fuzzing
  - Detect form brute-force & directory brute-force
- Configuration
  - SSH
  - Nginx
  - Docker
    - Unpriviledged user
    - Disable root
    - security-opt=no-new-priviledges
    - read-only ? partial ?
    - Networking ?
- Zero trust
- Firewall


# SOMMAIRE

1. [Problèmes rencontrés]()

# PROBLÈMES RENCONTRÉS

Debian 12 n'utilise plus rsyslog mais journalctl, donc il faut réinstaller rsyslog et le configurer pour le faire marcher avec wazuh => chiant donc préfère down grade à debian 11 pour que ça marche "out of the box".

Finalement les repos sont trop vieux et deprecated donc je suis passé sur ubuntu 22.04

# Installation wazuh server, dashboard et manager dans des conteneurs docker

```
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.3
cd wazuh-docker/single-node/
sudo sysctl -w vm.max_map_count=262144
```
Default credentials :

Username : admin

Password : SecretPassword

Pour générer les mots de passe :
```
docker run --rm -ti wazuh/wazuh-indexer:4.7.3 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```

On peut modifier le mot de passe en éditant config/wazuh_indexer/internal_users.yml et docker-compose.yml.
C'est ce que j'ai fais et j'ai supprimé tous les users sauf admin et kibanaserver.

Il faut aussi modifier le mot de passe par défaut de l'utilisateur de l'API dans config/wazuh_dashboard/wazuh.yml et docker-compose.yml.

```
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Pour enroller le serveur il suffit de suivre le procédure classique.

Puis reboot le système (ça marche surement aussi en relançant les conteneurs docker mais pas testé).

# Configuration de wazuh

/!\ Ignorer les alertes sur /bin/diff, c'est un faux positif connu /!\

## Changer le niveau d'alerte de déconnexion, arrêt et suppression de l'agent wazuh de 3 à 12

Pour wazuh manager, ajouter ça dans /var/ossec/etc/rules/local_rules.xml
```
<group name="ossec,">
  <rule id="504" level="12" overwrite="yes">
    <if_sid>500</if_sid>
    <match>Agent disconnected</match>
    <description>Wazuh agent disconnected.</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>pci_dss_10.6.1,pci_dss_10.2.6,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_AU.14,nist_800_53_AU.5,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8,</group>
  </rule>

  <rule id="505" level="12" overwrite="yes">
    <if_sid>500</if_sid>
    <match>Agent removed</match>
    <description>Wazuh agent removed.</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>pci_dss_10.6.1,pci_dss_10.2.6,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_AU.14,nist_800_53_AU.5,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8,</group>
  </rule>

  <rule id="506" level="12" overwrite="yes">
    <if_sid>500</if_sid>
    <match>Agent stopped</match>
    <description>Wazuh agent stopped.</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>pci_dss_10.6.1,pci_dss_10.2.6,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_AU.14,nist_800_53_AU.5,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8,</group>
  </rule>
</group>
```

```
service wazuh-manager restart
```

## Active-response SSH brute-force

Ajouter ça dans la partie active response de /var/ossec/etc/ossec.conf, dans le conteneurs de wazuh manager :
```
<command>firewall-drop</command>
<location>local</location>
<rules_id>5710, 5760</rules_id>
<timeout>180</timeout>
```

## Intégration de suricata

Installation de suricata
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata -y
```

Télécharger les ruleset de suricata Emerging Threats
```
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 640 /etc/suricata/rules/*.rules
```

Modifier /etc/suricata/suricata.yaml pour mettre ces paramètres correctements :

```
HOME_NET: "135.125.238.153/32"
EXTERNAL_NET: "any"
```

```
af-packet:
  - interface: ens3
```

```
default-rule-path: /etc/suricata/rules

rule-files:
  - "*.rules"
```

Ajouter un nouveau groupe nommé "Suricata" (je l'ai fais via le dashboard)

Ajouter le ou les agents souhaités au groupe (pareil, j'ai fais avec le dashboard)

Ajouter ça dans /var/ossec/etc/shared/Suricata/agent.conf du conteneur wazuh manager (on aurait aussi pu faire via le dashboard)
```
<agent_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</agent_config>
```

Dans cet exemple, je vais seulement ajouter la détection de scan NMAP

Ajouter ça dans /var/ossec/etc/rules/local_rules.xml
```
<group name="custom_suricata_detection,">
  <rule id="100201" level="10">
    <if_sid>86600</if_sid>
    <field name="event_type">^alert$</field>
    <match>ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)</match>
    <description>Nmap scripting engine detected. </description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>
</group>
```
A VOIR, PARCE QUE CETTE REGLE A ARRETE D'ETRE TRIGGER PAR SURICATA, C'EST ETRANGE
```
service wazuh-manager restart
```

```
sudo systemctl start suricata
sudo systemctl enable suricata
sudo suricata-update
sudo systemctl restart suricata
```

## Amélioration des règles de SURICATA /!\ EN COURS /!\



## Vulnerability detection 

Dans /var/ossec/etc/ossec.conf, passer <enabled>no</enabled> à <enabled>yes</enabled> pour <vulnerability-detector> et pour l'OS correspondant
```
<vulnerability-detector>
    <enabled>yes</enabled>
...
...
...
    <!-- Debian OS vulnerabilities -->
    <provider name="debian">
      <enabled>yes</enabled>
      <os>buster</os>
      <os>bullseye</os>
      <os>bookworm</os>
      <update_interval>1h</update_interval>
    </provider>
```

```
service wazuh-manager restart
```

# CIS

## ID : 28668 Ensure inactive password lock is 30 days or less

Modifier /etc/default/useradd pour y ajouter :
```
INACTIVE=30
```

On peut aussi utiliser `chage --inactive 30 <user>` pour ajouter ce paramètre sur les utilisateurs déjà crées.

Je l'ai fais sur mon user et le user ubuntu.

## ID : 28666 Ensure password expiration is 365 days or less

Modifier /etc/login.defs pour y ajouter/modifier :
```
PASS_MAX_DAYS	365
```

On peut aussi utiliser `chage --maxdays 365 <user>` pour ajouter ce paramètre sur les utilisateurs déjà crées.

Je l'ai fais sur mon user et le user ubuntu.

## ID : 28665 Ensure minimum days between password changes is configured

Modifier /etc/login.defs pour y ajouter/modifier :
```
PASS_MIN_DAYS	1
```

On peut aussi utiliser `chage --mindays 1 <user>` pour ajouter ce paramètre sur les utilisateurs déjà crées.

Je l'ai fais sur mon user et le user ubuntu.


# Mettre le serveur à l'heure

```
timedatectl set-timezone Europe/Paris
```















## Mettre en place les alertes par mail /!\ EN COURS /!\


# SSH Configuration hardening /!\ EN COURS /!\

[SSH conf](./sshd_config)

Autoriser seulement certains utilisateurs :
```
AllowUsers axel
```

Désactiver la connexion par mot de passe :
```
PasswordAuthentication no
```

Rendre le login plus verbeux :
```
LogLevel VERBOSE
```

Laisser 60 secondes à l'utilisateur pour entrer son mot de passe ou sa clé :
```
LoginGraceTime 60
```

Désactiver la possibilité de connexion pour root :
```
PermitRootLogin no
```

Laisser 4 essais à l'utlisateur pour se connecter :
```
MaxAuthTries 4
```











# NGINX Configuration hardening

*Ajouter les explications pour chaque ligne*
*L'ajouter quand la contenerisation sera faite*

# Docker

- ## Ajout de NGINX + conf /!\ EN COURS /!\

Pour que nginx puisse fonctionner en HTTPS, re-mapper les ports de wazuh dashboard (443) vers un autre (ici 5601) en modifiant le docker compose.

- ## File integrity monitoring /!\ EN COURS /!\

Activé par défaut, on peut ajouter des répertoires à vérifier dans /var/ossec/etc/ossec.conf

```
  <syscheck>
    <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
  </syscheck>
```

```
service wazuh-manager restart
```





---
/!\ /var/ossec/etc/ossec.conf EST RÉINITIALISÉ SI LE CONTENEUR MANAGER EST STOPPÉ, TROUVER UN MOYEN POUR QUE ÇA N'ARRIVE PAS /!\
Plutôt modifier directement les fichiers sur la machine au lieu du conteneur et dans ce cas redémarrer tout le conteneur ?






https://wazuh.com/blog/monitoring-root-actions-on-linux-using-auditd-and-wazuh/