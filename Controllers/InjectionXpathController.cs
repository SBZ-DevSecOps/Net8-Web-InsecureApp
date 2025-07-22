using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Xml;
using System.Xml.XPath;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionXpathController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly XmlDocument _usersXml;

        public InjectionXpathController()
        {
            // Initialiser les données XML simulées
            _usersXml = InitializeXmlData();

            _attackInfos = new()
            {
                ["basic"] = new AttackInfo
                {
                    Description = "Injection XPath basique exploitant les opérateurs de comparaison et les fonctions XPath pour extraire des données non autorisées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "High",
                    PayloadExample = "admin' or '1'='1",
                    ErrorExplanation = "L'injection XPath basique peut échouer si les guillemets ne sont pas correctement gérés ou si la syntaxe XPath est invalide."
                },
                ["union"] = new AttackInfo
                {
                    Description = "Utilisation de l'opérateur union (|) pour combiner plusieurs requêtes XPath et extraire des données de différents nœuds.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "High",
                    PayloadExample = "'] | //user/password | //user[username='",
                    ErrorExplanation = "L'opérateur union peut échouer si les nœuds ciblés n'existent pas ou si la syntaxe est incorrecte."
                },
                ["position"] = new AttackInfo
                {
                    Description = "Exploitation des fonctions position() et last() pour itérer sur les nœuds et extraire des données séquentiellement.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "admin' and position()=1 and '1'='1",
                    ErrorExplanation = "Les fonctions de position peuvent ne pas fonctionner si le contexte XPath n'est pas celui attendu."
                },
                ["string"] = new AttackInfo
                {
                    Description = "Utilisation des fonctions de manipulation de chaînes (substring, contains, string-length) pour extraire des informations caractère par caractère.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "' or substring(//user[1]/password,1,1)='a",
                    ErrorExplanation = "Les fonctions de chaînes peuvent échouer si les données ne sont pas du type attendu."
                },
                ["count"] = new AttackInfo
                {
                    Description = "Exploitation de la fonction count() pour déterminer le nombre d'éléments et structurer des attaques plus ciblées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "' or count(//user)>0 or '1'='1",
                    ErrorExplanation = "La fonction count() peut retourner des résultats inattendus selon la structure XML."
                },
                ["comment"] = new AttackInfo
                {
                    Description = "Injection utilisant les commentaires XPath pour tronquer la requête et injecter du code malicieux.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "admin'--",
                    ErrorExplanation = "Les commentaires XPath ne fonctionnent pas de la même manière que SQL et peuvent causer des erreurs de syntaxe."
                },
                ["boolean"] = new AttackInfo
                {
                    Description = "Injection booléenne exploitant les opérateurs logiques (and, or) pour extraire des informations sans retour direct.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "High",
                    PayloadExample = "admin' or name(//user[1])='user' or 'a'='b",
                    ErrorExplanation = "Les opérateurs booléens mal formés peuvent causer des erreurs de parsing XPath."
                },
                ["wildcard"] = new AttackInfo
                {
                    Description = "Utilisation des wildcards (* et //) pour naviguer dans toute la structure XML et accéder à des nœuds non autorisés.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/XPATH_Injection",
                    RiskLevel = "High",
                    PayloadExample = "' or //* or '1'='1",
                    ErrorExplanation = "Les wildcards peuvent causer des performances dégradées ou des timeouts sur de gros documents XML."
                }
            };
        }

        private XmlDocument InitializeXmlData()
        {
            var xml = @"<?xml version='1.0' encoding='UTF-8'?>
<users>
    <user id='1' role='admin'>
        <username>admin</username>
        <password>P@ssw0rd123!</password>
        <email>admin@example.com</email>
        <fullname>Administrator</fullname>
        <lastlogin>2024-01-15</lastlogin>
        <secretkey>SK-ADMIN-2024-SECRET</secretkey>
    </user>
    <user id='2' role='user'>
        <username>john.doe</username>
        <password>john123</password>
        <email>john.doe@example.com</email>
        <fullname>John Doe</fullname>
        <lastlogin>2024-01-14</lastlogin>
        <creditcard>4111-1111-1111-1111</creditcard>
    </user>
    <user id='3' role='user'>
        <username>jane.smith</username>
        <password>jane456</password>
        <email>jane.smith@example.com</email>
        <fullname>Jane Smith</fullname>
        <lastlogin>2024-01-13</lastlogin>
        <ssn>123-45-6789</ssn>
    </user>
    <user id='4' role='guest'>
        <username>guest</username>
        <password>guest</password>
        <email>guest@example.com</email>
        <fullname>Guest User</fullname>
        <lastlogin>2024-01-10</lastlogin>
    </user>
    <config>
        <dbconnection>Server=db.internal;Database=prod;User=sa;Password=SecretDB123</dbconnection>
        <apikey>API-KEY-PROD-2024</apikey>
        <environment>production</environment>
    </config>
</users>";

            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<XPathResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<XPathResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<XPathResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<XPathResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<XPathResult>();
                string xpathQuery = BuildXPathQuery(attackType, payload);

                // Exécution de la requête XPath vulnérable
                results = ExecuteXPathQuery(xpathQuery);

                var model = VulnerabilityViewModel<XPathResult>.WithResults(payload, attackType, results, xpathQuery);
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<XPathResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur XPath : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private string BuildXPathQuery(string attackType, string payload)
        {
            // Construction de requêtes XPath vulnérables selon le type d'attaque
            return attackType switch
            {
                "basic" => $"//user[username='{payload}' and password='password']",
                "union" => $"//user[username='{payload}']",
                "position" => $"//user[username='{payload}']",
                "string" => $"//user[username='{payload}']",
                "count" => $"//user[username='{payload}']",
                "comment" => $"//user[username='{payload}' and password='password']",
                "boolean" => $"//user[username='{payload}']",
                "wildcard" => $"//user[username='{payload}']",
                _ => throw new ArgumentException("Type d'attaque inconnu")
            };
        }

        private List<XPathResult> ExecuteXPathQuery(string xpathQuery)
        {
            var results = new List<XPathResult>();

            try
            {
                // Navigateur XPath
                var navigator = _usersXml.CreateNavigator();

                // Exécuter la requête XPath vulnérable
                var nodeIterator = navigator.Select(xpathQuery);

                while (nodeIterator.MoveNext())
                {
                    var current = nodeIterator.Current;
                    var result = new XPathResult
                    {
                        NodePath = current.Name,
                        NodeType = current.NodeType.ToString()
                    };

                    // Extraire les attributs
                    if (current.HasAttributes)
                    {
                        current.MoveToFirstAttribute();
                        do
                        {
                            result.Attributes[current.Name] = current.Value;
                        } while (current.MoveToNextAttribute());
                        current.MoveToParent();
                    }

                    // Extraire les éléments enfants
                    if (current.HasChildren)
                    {
                        var childNav = current.Clone();
                        childNav.MoveToFirstChild();
                        do
                        {
                            if (childNav.NodeType == XPathNodeType.Element)
                            {
                                result.Elements[childNav.Name] = childNav.Value;
                            }
                        } while (childNav.MoveToNext());
                    }

                    results.Add(result);
                }

                // Si la requête retourne un booléen ou une valeur scalaire
                if (results.Count == 0)
                {
                    try
                    {
                        var scalarResult = navigator.Evaluate(xpathQuery);
                        if (scalarResult != null)
                        {
                            results.Add(new XPathResult
                            {
                                NodePath = "XPath Result",
                                NodeType = "Scalar",
                                Elements = new Dictionary<string, string>
                                {
                                    ["Value"] = scalarResult.ToString(),
                                    ["Type"] = scalarResult.GetType().Name
                                }
                            });
                        }
                    }
                    catch
                    {
                        // Ignorer les erreurs d'évaluation scalaire
                    }
                }
            }
            catch (XPathException ex)
            {
                // Pour les injections qui causent des erreurs XPath
                throw new Exception($"Erreur de syntaxe XPath : {ex.Message}");
            }

            return results;
        }
    }

    // Modèle pour les résultats XPath
    public class XPathResult
    {
        public string NodePath { get; set; } = string.Empty;
        public string NodeType { get; set; } = string.Empty;
        public Dictionary<string, string> Attributes { get; set; } = new();
        public Dictionary<string, string> Elements { get; set; } = new();
    }
}