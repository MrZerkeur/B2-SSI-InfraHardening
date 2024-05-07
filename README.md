# Projet fil-rouge SSI | Hardening infra web

docker compose up -d --build



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

Règle n°1 : 