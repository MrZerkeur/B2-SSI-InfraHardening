## Sécurité application web

### Système d'authenfication et d'autorisation

Sessions basées sur des cookies : 

[Iron-Session](https://github.com/vvo/iron-session) : une librairie de session sécurisée, stateless et basée sur des cookies pour JavaScript

Cookie : 
```ts
{
    password: process.env.SECRET_KEY!,
    cookieName: "user-session",
    cookieOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
    }
}
```

| Attribut | Valeur | Explication |
| -------- | ------ | ----------- |
| password | process.env.SECRET_KEY! | Définit une clé secrète stockée dans un fichier local .env  et utilisée pour signer les cookies, assurant leur intégrité et empêchant leur altération |
| cookieName | "user-session" | Définit le nom du cookie de la session |
| httpOnly | true | Indique aux navigateurs Web de ne pas autoriser les scripts (par ex. JavaScript ou VBscript) à accéder aux cookies via l’objet document.cookie du DOM. Aide à prévenir les attaques de type XSS (Cross Site Scripting) |
| secure | process.env.NODE_ENV === "production" (équivaut à true) | Indique aux navigateurs Web de n’envoyer le cookie que via une connexion HTTPS (SSL/TLS) chiffrée. Ici la variable d'environnement NODE_ENV est toujours "production" activant l'attribut secure. Il protège uniquement la confidentialité d’un cookie contre les attaquants MitM |
| sameSite | 'strict' | Définit un attribut du cookie empêchant les navigateurs d’envoyer un cookie signalé par SameSite avec des requêtes intersites. L’objectif principal est d’atténuer le risque de fuite d’informations d’origine croisée et de fournir une certaine protection contre les attaques de falsification de demandes intersites. Ici `strict`, signifie que le navigateur n’envoie le cookie que pour les requêtes du même site, c’est-à-dire les requêtes provenant du même site qui a défini le cookie. Si une requête provient d’une URL différente de la précédente, aucun cookie avec l’attribut `SameSite=Strict` n’est envoyé. |
| maxAge | 24 * 60 * 60 | Spécifie la durée de validité du cookie en millisecondes. Ici, elle est égale à 24 heures |  

L’attribut `Domain` définit l’hôte auquel le cookie sera envoyé. Il n'est pas spécifié ici car il est défini par défaut sur l’hôte de l’emplacement actuel du document, à l’exclusion des sous-domaines.

Sources : 
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#
- https://0xn3va.gitbook.io/cheat-sheets/web-application/cookie-security


### Vérification et validation des entrées utilisateurs

`Règle n°1 : Ne pas faire confiance aux entrées utilisateurs !`   

En effet, les risques liés aux attaques de type injections SQL et XSS sont légion :  

- Injection de code malveillant
- Prise de contrôle et/ou corruption d'une infrastructure
- Vol de données sensibles
- etc...

Pour prémunir de ces failles de sécurité, il est nécessaire d'appliquer des mesures de sécurité fiables et concrètes.  

**Important : Toutes ces mesures sont réalisées côté serveur car un utilisateur malveillant peut contourner les vérifications côté client** 

#### Nettoyage des entrées utilisateurs

Utilisation d'expressions régulières (ou Regex) :

Une expression régulière décrit un motif, un pattern que nous souhaitons rechercher et localiser dans du texte.  
Ces dernières vont donc ici nous servir pour valider et filtrer les entrées utilisateur afin de détecter et bloquer les attaques par injection en limitant le nombre de caractères utilisables en fonction du champs.  

- Pseudonyme de l'utilisateur : `/^[A-Za-z][A-Za-z0-9]{0,23}$/`
  - Entre 1 et 24 caractères, composé de lettres majuscules et/ou minuscules et de chiffres (excepté pour le premier caractère)
- Prénom et nom : `/^[a-zA-Z]+([ \-']{0,1}[a-zA-Z]+){0,2}$/`
  - Valide des noms (prénom et noms si plusieurs) simples ou composés
- Adresse Mail : `/^([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,5})$/`
  - Exemples de correspondance avec cette regex :
    - john.doe@example.com
    - user123@mail-server.co.uk
    - jane_doe123@sub.domain.com
  - Exemples de non-correspondance :
    - not_an_email (pas de @)
    - john@doe (manque l'extension de domaine)
    - invalid@domain.invalid-extension (l'extension de domaine est trop longue)
- Numéro de téléphone : `/^\b\d{3}[-.]?\d{3}[-.]?\d{4}\b$/`  
  - Valide des numéros de téléphones selon l'une de ces trois formes :
    - 0123456789
    - 012-345-6789
    - 012.345.6789

Sources :  
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

#### Téléchargement de fichiers  

Validation du fichier avant téléchargement  

- Vérification de l'extension du fichier
  - N'accepte que des images
- Limitation de la taille du fichier
  - N'accepte que les fichiers aillant une taille inférieure à 3 MB

Renommage du fichier avant téléchargement  

- Génération d'un identifiant unique UUIDv4
  - ma_photo.jpg -> a600bc3f-3ff2-452c-a0fa-3cd4945d8c72.jpg

#### Requêtes à la base de données

Utilisation de requêtes préparées (avec requêtes paramétrées)

```ts
# Exemple de code
const query = await conn.prepare("INSERT INTO users (username, hashed_password, salt, is_admin) VALUES (?, ?, ?, FALSE)");
await query.execute([username, hashedPassword, salt]);
```

Dans ce cas, si l'utilisateur devait entrer comme nom d'utilisateur `toto' or 1=1;--`, la requête paramétrée interprètera un nom d’utilisateur qui correspond littéralement à la chaîne de caractères entière `toto' or 1=1;--`. Ainsi, la base de données serait protégée contre les injections de code SQL malveillant.

Sources :
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html