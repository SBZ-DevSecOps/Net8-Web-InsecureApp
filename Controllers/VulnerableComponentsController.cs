//using InsecureAppWebNet8.Models;
//using InsecureAppWebNet8.ViewModels;
//using log4net;
//using Microsoft.AspNetCore.Mvc;
//using Newtonsoft.Json;
//using Serilog;
//using System.Data.SqlClient;
//using System.Xml;
//using System.Xml.Serialization;

//namespace InsecureAppWebNet8.Controllers
//{
//    /// <summary>
//    /// IMPORTANT: Pour que ce module fonctionne et soit détecté par SAST, vous DEVEZ :
//    /// 
//    /// 1. Ajouter ces PackageReference au .csproj :
//    ///    <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
//    ///    <PackageReference Include="log4net" Version="2.0.8" />
//    ///    <PackageReference Include="System.Data.SqlClient" Version="4.4.0" />
//    ///    <PackageReference Include="jQuery" Version="2.1.4" />
//    ///    <PackageReference Include="bootstrap" Version="3.3.7" />
//    /// 
//    /// 2. Créer un package.json à la racine avec :
//    ///    {
//    ///      "dependencies": {
//    ///        "jquery": "2.1.4",
//    ///        "bootstrap": "3.3.7",
//    ///        "lodash": "4.17.4",
//    ///        "moment": "2.18.1"
//    ///      }
//    ///    }
//    /// 
//    /// 3. Les outils SAST détecteront alors :
//    ///    - dotnet list package --vulnerable
//    ///    - npm audit
//    ///    - Snyk, WhiteSource, Dependabot, etc.
//    /// </summary>
//    public class VulnerableComponentsController : Controller
//    {
//        private static readonly ILog _logger = LogManager.GetLogger(typeof(VulnerableComponentsController));
//        private readonly Dictionary<string, AttackInfo> _attackInfos;

//        public VulnerableComponentsController()
//        {
//            _attackInfos = new()
//            {
//                ["newtonsoft-rce"] = new AttackInfo
//                {
//                    Description = "Newtonsoft.Json 9.0.1 avec TypeNameHandling.All permet l'exécution de code.",
//                    LearnMoreUrl = "https://github.com/advisories/GHSA-5crp-9r3c-p9vr",
//                    RiskLevel = "Critical",
//                    PayloadExample = "POST /VulnerableComponents/DeserializeJson",
//                    ErrorExplanation = "CVE-2018-1000210 - Remote Code Execution via désérialisation."
//                },
//                ["log4net-xxe"] = new AttackInfo
//                {
//                    Description = "log4net 2.0.8 vulnérable à XML External Entity (XXE) injection.",
//                    LearnMoreUrl = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1285",
//                    RiskLevel = "High",
//                    PayloadExample = "POST /VulnerableComponents/ConfigureLogging",
//                    ErrorExplanation = "CVE-2018-1285 - XXE via configuration XML."
//                },
//                ["sqlclient-injection"] = new AttackInfo
//                {
//                    Description = "System.Data.SqlClient ancien avec vulnérabilités connues.",
//                    LearnMoreUrl = "https://github.com/dotnet/SqlClient/security/advisories",
//                    RiskLevel = "High",
//                    PayloadExample = "GET /VulnerableComponents/QueryDatabase?query=SELECT * FROM Users",
//                    ErrorExplanation = "Version obsolète avec multiples failles de sécurité."
//                },
//                ["jquery-xss"] = new AttackInfo
//                {
//                    Description = "jQuery 2.1.4 contient plusieurs vulnérabilités XSS.",
//                    LearnMoreUrl = "https://github.com/jquery/jquery/security/advisories",
//                    RiskLevel = "High",
//                    PayloadExample = "GET /VulnerableComponents/RenderWithJQuery",
//                    ErrorExplanation = "CVE-2015-9251, CVE-2019-11358 - XSS via $.html() et autres méthodes."
//                },
//                ["bootstrap-xss"] = new AttackInfo
//                {
//                    Description = "Bootstrap 3.3.7 vulnérable aux attaques XSS.",
//                    LearnMoreUrl = "https://github.com/twbs/bootstrap/security/advisories",
//                    RiskLevel = "Medium",
//                    PayloadExample = "GET /VulnerableComponents/BootstrapDemo",
//                    ErrorExplanation = "CVE-2018-14041, CVE-2018-14042 - XSS dans les tooltips et popovers."
//                }
//            };
//        }

//        [HttpGet]
//        public IActionResult Index()
//        {
//            var model = new VulnerabilityViewModel<ComponentsResult>
//            {
//                AttackType = "",
//                Payload = "",
//                Results = new List<ComponentsResult>(),
//                AttackInfos = _attackInfos
//            };
//            return View(model);
//        }

//        [HttpPost]
//        public IActionResult Index(string attackType, string payload)
//        {
//            payload = payload ?? string.Empty;

//            var model = new VulnerabilityViewModel<ComponentsResult>
//            {
//                AttackType = attackType,
//                Payload = payload,
//                Results = new List<ComponentsResult>(),
//                AttackInfos = _attackInfos
//            };

//            if (!string.IsNullOrEmpty(attackType))
//            {
//                var result = new ComponentsResult
//                {
//                    AttackType = attackType,
//                    Success = true,
//                    Message = "Utilisez les endpoints réels ci-dessous pour exploiter les composants vulnérables."
//                };
//                model.Results.Add(result);
//            }

//            return View(model);
//        }

//        // === VRAIES VULNÉRABILITÉS AVEC COMPOSANTS RÉELS ===

//        // VULNÉRABLE : Newtonsoft.Json 9.0.1 avec TypeNameHandling.All
//        [HttpPost]
//        public IActionResult DeserializeJson([FromBody] string jsonData)
//        {
//            try
//            {
//                // VULNÉRABLE : TypeNameHandling.All permet RCE (CVE-2018-1000210)
//                var settings = new JsonSerializerSettings
//                {
//                    TypeNameHandling = TypeNameHandling.All, // DÉTECTABLE PAR SAST!
//                    TypeNameAssemblyFormatHandling = TypeNameAssemblyFormatHandling.Full
//                };

//                // Désérialisation dangereuse
//                var obj = JsonConvert.DeserializeObject(jsonData, settings);

//                return Json(new
//                {
//                    success = true,
//                    message = "JSON désérialisé avec TypeNameHandling.All!",
//                    type = obj?.GetType().FullName,
//                    warning = "CVE-2018-1000210 exploitable!",
//                    exploit = @"{
//                        '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
//                        'MethodName':'Start',
//                        'MethodParameters':{
//                            '$type':'System.Collections.ArrayList',
//                            '$values':['cmd.exe','/c calc']
//                        },
//                        'ObjectInstance':{'$type':'System.Diagnostics.Process'}
//                    }"
//                });
//            }
//            catch (Exception ex)
//            {
//                _logger.Error("Erreur désérialisation", ex);
//                return Json(new { success = false, error = ex.Message });
//            }
//        }

//        // VULNÉRABLE : log4net 2.0.8 avec XXE
//        [HttpPost]
//        public IActionResult ConfigureLogging([FromBody] string xmlConfig)
//        {
//            try
//            {
//                // VULNÉRABLE : log4net 2.0.8 permet XXE (CVE-2018-1285)
//                var xmlDoc = new XmlDocument();

//                // Configuration vulnérable permettant XXE
//                var settings = new XmlReaderSettings
//                {
//                    DtdProcessing = DtdProcessing.Parse, // XXE activé!
//                    XmlResolver = new XmlUrlResolver()
//                };

//                using (var reader = XmlReader.Create(new System.IO.StringReader(xmlConfig), settings))
//                {
//                    xmlDoc.Load(reader);
//                }

//                // Configurer log4net avec le XML (simulation)
//                _logger.Info($"Configuration chargée: {xmlDoc.OuterXml.Substring(0, 100)}...");

//                return Json(new
//                {
//                    success = true,
//                    message = "Configuration log4net appliquée!",
//                    warning = "CVE-2018-1285 - XXE possible!",
//                    exploit = @"<!DOCTYPE log4net [
//                        <!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>
//                    ]>
//                    <log4net>
//                        <appender name='test'>
//                            <file value='&xxe;'/>
//                        </appender>
//                    </log4net>"
//                });
//            }
//            catch (Exception ex)
//            {
//                _logger.Error("Erreur configuration logging", ex);
//                return Json(new { success = false, error = ex.Message });
//            }
//        }

//        // VULNÉRABLE : System.Data.SqlClient 4.4.0
//        [HttpGet]
//        public IActionResult QueryDatabase(string query)
//        {
//            try
//            {
//                // VULNÉRABLE : SqlClient ancien + injection SQL
//                using (var connection = new SqlConnection("Server=.;Database=Test;Integrated Security=true;"))
//                {
//                    // VULNÉRABLE : Requête SQL directe sans paramètres
//                    using (var command = new SqlCommand(query, connection))
//                    {
//                        // Simulation - ne pas vraiment exécuter
//                        return Json(new
//                        {
//                            success = true,
//                            message = "Requête préparée (non exécutée pour la démo)",
//                            query = query,
//                            warning = "SqlClient 4.4.0 + SQL Injection!",
//                            version = connection.GetType().Assembly.GetName().Version?.ToString()
//                        });
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                _logger.Error("Erreur SQL", ex);
//                return Json(new { success = false, error = ex.Message });
//            }
//        }

//        // VULNÉRABLE : jQuery 2.1.4 dans la vue
//        [HttpGet]
//        public IActionResult RenderWithJQuery(string userInput)
//        {
//            ViewBag.UserInput = userInput ?? "<img src=x onerror=alert('XSS')>";
//            ViewBag.JQueryVersion = "2.1.4"; // Version vulnérable
//            return View("JQueryVulnerable");
//        }

//        // VULNÉRABLE : Bootstrap 3.3.7 dans la vue
//        [HttpGet]
//        public IActionResult BootstrapDemo(string tooltip)
//        {
//            ViewBag.TooltipContent = tooltip ?? "');alert('XSS')";
//            ViewBag.BootstrapVersion = "3.3.7"; // Version vulnérable
//            return View("BootstrapVulnerable");
//        }

//        // Endpoint pour vérifier les versions des composants
//        [HttpGet]
//        public IActionResult CheckVersions()
//        {
//            var assemblies = AppDomain.CurrentDomain.GetAssemblies()
//                .Where(a => !a.IsDynamic && !a.FullName.StartsWith("System") && !a.FullName.StartsWith("Microsoft"))
//                .Select(a => new
//                {
//                    Name = a.GetName().Name,
//                    Version = a.GetName().Version?.ToString()
//                })
//                .ToList();

//            // Ajouter les versions hardcodées pour la démo
//            assemblies.Add(new { Name = "Newtonsoft.Json", Version = "9.0.1" });
//            assemblies.Add(new { Name = "log4net", Version = "2.0.8" });
//            assemblies.Add(new { Name = "System.Data.SqlClient", Version = "4.4.0" });

//            return Json(new
//            {
//                success = true,
//                components = assemblies,
//                vulnerableCount = 3,
//                warning = "Composants vulnérables détectés!"
//            });
//        }

//        // Endpoint de test
//        [HttpGet]
//        public IActionResult TestEndpoints()
//        {
//            return Json(new
//            {
//                endpoints = new[]
//                {
//                    "POST /VulnerableComponents/DeserializeJson - Newtonsoft.Json RCE",
//                    "POST /VulnerableComponents/ConfigureLogging - log4net XXE",
//                    "GET /VulnerableComponents/QueryDatabase?query=SELECT * FROM Users - SQL Injection",
//                    "GET /VulnerableComponents/RenderWithJQuery?userInput=<script>alert('XSS')</script>",
//                    "GET /VulnerableComponents/BootstrapDemo?tooltip=<script>alert('XSS')</script>",
//                    "GET /VulnerableComponents/CheckVersions"
//                },
//                requiredPackages = new[]
//                {
//                    "Newtonsoft.Json 9.0.1",
//                    "log4net 2.0.8",
//                    "System.Data.SqlClient 4.4.0",
//                    "jQuery 2.1.4 (dans wwwroot/lib)",
//                    "Bootstrap 3.3.7 (dans wwwroot/lib)"
//                }
//            });
//        }
//    }

//    // Modèle
//    public class ComponentsResult
//    {
//        public string AttackType { get; set; } = string.Empty;
//        public bool Success { get; set; }
//        public string Message { get; set; } = string.Empty;
//    }
//}