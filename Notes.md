# Installation wazuh server, dashboard et manager dans des conteneurs docker

```
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.3
cd wazuh-docker/single-node/
sudo sysctl -w vm.max_map_count=262144
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
Default credentials :
Username : admin
Password : SecretPassword

Sinon on peut modifier le mot de passe en modifier config/wazuh_indexer/internal_users.yml et docker-compose.yml.
C'est ce que j'ai fais et j'ai supprimé tous les users sauf admin et kibanaserver.

Il faut aussi modifier le mot de passe par défaut de l'utilisateur de l'API dans config/wazuh_dashboard/wazuh.yml et docker-compose.yml.

Pour enroller le serveur il suffit de suivre le procédure classique.

Installation et configuration de firewalld pour seulement autoriser les connexions au dashboard :
```
sudo apt install firewalld -y
sudo firewall-cmd --add-port=443/tcp --permanent
sudo firewall-cmd --reload
```

Puis reboot le système (ça marche surement aussi en relançant les conteneurs docker mais pas testé)


# PROBLÈMES RENCONTRÉS

Debian 12 n'utilise plus rsyslog mais journalctl, donc il faut réinstaller rsyslog et le configurer pour le faire marcher avec wazuh => chiant donc préfère down grade à debian 11 pour que ça marche "out of the box"


# Configuration de wazuh

/!\ Ignorer les alertes sur /bin/diff, c'est un faux positif connu /!\

- ## Changer le niveau d'alerte de déconnexion, arrêt et suppression de l'agent wazuh de 3 à 12

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

- ## Détecter SSH brute-force /!\ PROBLEME RESOLU /!\

Sur debian 12 rsyslog n'est pas installé par défaut, il faut donc l'installer sinon pas de fichiers de log et tout sera sur journalctl

- ## Active-response SSH brute-force

Ajouter ça dans la partie active response de /var/ossec/etc/ossec.conf, dans le conteneurs de wazuh manager :
```
<command>firewall-drop</command>
<location>local</location>
<rules_id>5710, 5760</rules_id>
<timeout>180</timeout>
```

- ## Ajout de NGINX

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

- ## Vulnerability detection /!\ EN COURS /!\

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

PAS FINI, SEVERITÉ EN "UNTRIAGED"
https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html


- Mettre en place les alertes par mail /!\ EN COURS /!\



- Intégration suricata => fuzzing, directory brute-force, etc...