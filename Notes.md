Installation wazuh server, dashboard et manager dans des conteneurs docker :

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

Pour enroller le serveur il suffit de suivre le procédure classique.

Installation et configuration de firewalld pour seulement autoriser les connexions au dashboard :
```
sudo apt install firewalld -y
sudo firewall-cmd --add-port=443/tcp --permanent
sudo firewall-cmd --reload
```

Puis reboot le système (ça marche surement aussi en relançant les conteneurs docker mais pas testé)