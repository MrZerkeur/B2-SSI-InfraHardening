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


# Configuration de wazuh

- Ignorer les alertes sur /bin/diff, c'est un faux positif connu
- Changer le niveau d'alerte de déconnexion, arrêt et suppression de l'agent wazuh de 3 à 12

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

- Détecter SSH brute-force /!\ EN COURS /!\

- Mettre en place les alertes par mail /!\ EN COURS /!\