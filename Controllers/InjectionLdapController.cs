using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionLdapController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        public InjectionLdapController()
        {
            _attackInfos = new()
            {
                ["basic"] = new AttackInfo
                {
                    Description = "Injection LDAP basique exploitant les opérateurs de filtre LDAP comme '*' (wildcard) et les parenthèses pour modifier la logique de recherche.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "High",
                    PayloadExample = "*)(uid=*))(|(uid=*",
                    ErrorExplanation = "L'injection LDAP basique peut échouer si les parenthèses ne sont pas équilibrées ou si la syntaxe du filtre est invalide."
                },
                ["wildcard"] = new AttackInfo
                {
                    Description = "Utilisation de wildcards (*) pour extraire tous les enregistrements ou contourner les restrictions de recherche.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "*",
                    ErrorExplanation = "Les wildcards peuvent être bloqués ou limités par la configuration du serveur LDAP."
                },
                ["boolean"] = new AttackInfo
                {
                    Description = "Injection booléenne utilisant les opérateurs logiques LDAP (&, |, !) pour modifier les conditions de recherche.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "High",
                    PayloadExample = "admin)(&(password=*))",
                    ErrorExplanation = "Les opérateurs booléens mal formés peuvent causer des erreurs de syntaxe LDAP."
                },
                ["null"] = new AttackInfo
                {
                    Description = "Injection exploitant les valeurs NULL ou les bypass d'authentification en fermant prématurément les filtres.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "High",
                    PayloadExample = "admin))(|(password=*",
                    ErrorExplanation = "Les tentatives de bypass peuvent échouer si le serveur valide strictement la syntaxe des filtres."
                },
                ["attributes"] = new AttackInfo
                {
                    Description = "Extraction d'attributs sensibles en injectant des requêtes pour révéler des champs cachés comme userPassword, mail, etc.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "High",
                    PayloadExample = "*)(mail=*))(&(mail=*",
                    ErrorExplanation = "L'accès aux attributs sensibles peut être restreint par les ACL du serveur LDAP."
                },
                ["blind"] = new AttackInfo
                {
                    Description = "Injection LDAP aveugle exploitant les différences de comportement pour extraire des informations sans retour direct.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "admin)(|(uid=a*",
                    ErrorExplanation = "L'injection aveugle nécessite des observations subtiles du comportement de l'application."
                },
                ["escape"] = new AttackInfo
                {
                    Description = "Contournement des mécanismes d'échappement en utilisant des caractères spéciaux LDAP ou des encodages.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "\\2a\\29\\28\\7c\\28uid\\3d\\2a",
                    ErrorExplanation = "Les tentatives d'échappement peuvent échouer si l'application utilise une validation appropriée."
                },
                ["dn"] = new AttackInfo
                {
                    Description = "Injection dans le Distinguished Name (DN) pour accéder à différentes branches de l'arbre LDAP.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/LDAP_Injection",
                    RiskLevel = "High",
                    PayloadExample = "cn=admin,dc=*,dc=*",
                    ErrorExplanation = "L'injection DN peut échouer si le serveur valide strictement le format des DN."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<LdapResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<LdapResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<LdapResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<LdapResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<LdapResult>();
                string ldapFilter = BuildLdapFilter(attackType, payload);

                // Simulation d'une recherche LDAP vulnérable
                // Dans un environnement réel, ceci se connecterait à un serveur LDAP
                results = SimulateLdapSearch(ldapFilter, attackType, payload);

                var model = VulnerabilityViewModel<LdapResult>.WithResults(payload, attackType, results, ldapFilter);
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<LdapResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur LDAP : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private string BuildLdapFilter(string attackType, string payload)
        {
            // Construction de filtres LDAP vulnérables selon le type d'attaque
            return attackType switch
            {
                "basic" => $"(&(uid={payload})(objectClass=person))",
                "wildcard" => $"(uid={payload})",
                "boolean" => $"(&(uid={payload})(userPassword=*))",
                "null" => $"(&(uid={payload})(objectClass=*))",
                "attributes" => $"(&(uid={payload})(mail=*))",
                "blind" => $"(&(uid={payload})(objectClass=user))",
                "escape" => $"(uid={payload})",
                "dn" => $"(&(cn={payload})(objectClass=*))",
                _ => throw new ArgumentException("Type d'attaque inconnu")
            };
        }

        private List<LdapResult> SimulateLdapSearch(string ldapFilter, string attackType, string payload)
        {
            var results = new List<LdapResult>();

            // Simulation de données LDAP
            var ldapEntries = new List<LdapResult>
            {
                new LdapResult
                {
                    Dn = "cn=admin,dc=example,dc=com",
                    Attributes = new Dictionary<string, string>
                    {
                        ["uid"] = "admin",
                        ["cn"] = "Administrator",
                        ["mail"] = "admin@example.com",
                        ["userPassword"] = "{SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
                    }
                },
                new LdapResult
                {
                    Dn = "cn=john.doe,dc=example,dc=com",
                    Attributes = new Dictionary<string, string>
                    {
                        ["uid"] = "jdoe",
                        ["cn"] = "John Doe",
                        ["mail"] = "john.doe@example.com",
                        ["department"] = "IT"
                    }
                },
                new LdapResult
                {
                    Dn = "cn=jane.smith,dc=example,dc=com",
                    Attributes = new Dictionary<string, string>
                    {
                        ["uid"] = "jsmith",
                        ["cn"] = "Jane Smith",
                        ["mail"] = "jane.smith@example.com",
                        ["department"] = "HR"
                    }
                },
                new LdapResult
                {
                    Dn = "cn=test.user,dc=example,dc=com",
                    Attributes = new Dictionary<string, string>
                    {
                        ["uid"] = "testuser",
                        ["cn"] = "Test User",
                        ["mail"] = "test@example.com",
                        ["accountStatus"] = "disabled"
                    }
                }
            };

            // Simulation de différents comportements selon le payload
            if (payload.Contains("*") || payload.Contains("admin") || payload.Contains(")("))
            {
                // Injection réussie - retourne tous les résultats
                results = ldapEntries;
            }
            else if (payload.Contains("=") || payload.Contains("|") || payload.Contains("&"))
            {
                // Injection partielle - retourne quelques résultats
                results = ldapEntries.Take(2).ToList();
            }
            else if (string.IsNullOrEmpty(payload))
            {
                // Pas de résultats
                results = new List<LdapResult>();
            }
            else
            {
                // Recherche normale - retourne un résultat
                results = ldapEntries.Where(e =>
                    e.Attributes.Values.Any(v => v.Contains(payload, StringComparison.OrdinalIgnoreCase))
                ).ToList();
            }

            // Pour les injections temporelles, ajouter un délai simulé
            if (attackType == "blind" && payload.Contains("*"))
            {
                System.Threading.Thread.Sleep(2000); // Simule un délai
            }

            return results;
        }
    }

    // Modèle pour les résultats LDAP
    public class LdapResult
    {
        public string Dn { get; set; } = string.Empty;
        public Dictionary<string, string> Attributes { get; set; } = new();
    }
}