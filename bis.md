```
sudo apt install suricata
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl start suricata
```

Modifier /etc/suricata/suricata.yaml pour mettre ces paramètres correctements :

Ligne 581
```
af-packet:
  - interface: ens3
```

Ligne 1861
Mettre ici tous les fichiers de règles qui existent (ils sont par défaut dans /etc/suricata/rules)
Oui il manque dnp3-events.rules et modbus-events.rules car dnp3 et modbus sont désactivés par défaut donc je préfère ne pas les mettre
/!\ PEUT-ETRE PAS BESOIN EN FAIT /!\
En fait si ?
```
rule-files:
  - app-layer-events.rules
  - decoder-events.rules
  - dhcp-events.rules
  - dns-events.rules
  - files.rules
  - http-events.rules
  - ipsec-events.rules
  - kerberos-events.rules
  - nfs-events.rules
  - ntp-events.rules
  - smb-events.rules
  - smtp-events.rules
  - stream-events.rules
  - tls-events.rules

```


```
sudo suricata-update
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

Suricata utilise src_ip mais le script firewall-drop d'active response attend srcip donc il faut ajouter un decodeur dans /var/ossec/etc/decoders/local_decoder.xml du conteneur wazuh manager
```
<decoder name="json">
  <prematch>^{\s*"</prematch>
</decoder>

<decoder name="json_child">
  <parent>json</parent>
  <regex type="pcre2">"src_ip":"([^"]+)"</regex>
  <order>srcip</order>
</decoder>

<decoder name="json_child">
  <parent>json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

```
service wazuh-manager restart
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

```
service wazuh-manager restart
```