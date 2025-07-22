using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Serialization;
using System.Diagnostics;

namespace InsecureAppWebNet8.Controllers
{
    public class SecurityMisconfigurationController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _env;
        private readonly IConfiguration _configuration;

        public SecurityMisconfigurationController(IWebHostEnvironment env, IConfiguration configuration)
        {
            _env = env;
            _configuration = configuration;

            _attackInfos = new()
            {
                ["debug-enabled"] = new AttackInfo
                {
                    Description = "Mode debug activé en production exposant des informations sensibles.",
                    LearnMoreUrl = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    RiskLevel = "High",
                    PayloadExample = "GET /SecurityMisconfiguration/GenerateError",
                    ErrorExplanation = "Les pages d'erreur détaillées exposent la stack trace et les informations système."
                },
                ["default-creds"] = new AttackInfo
                {
                    Description = "Utilisation de credentials par défaut non modifiés.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Use_of_Default_Credentials",
                    RiskLevel = "Critical",
                    PayloadExample = "POST /SecurityMisconfiguration/AdminLogin avec admin/admin",
                    ErrorExplanation = "Les mots de passe par défaut permettent un accès non autorisé."
                },
                ["directory-listing"] = new AttackInfo
                {
                    Description = "Directory listing activé exposant la structure des fichiers.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Directory_Listing",
                    RiskLevel = "Medium",
                    PayloadExample = "GET /SecurityMisconfiguration/ListFiles?path=wwwroot",
                    ErrorExplanation = "L'énumération des répertoires révèle des fichiers sensibles."
                },
                ["xxe-enabled"] = new AttackInfo
                {
                    Description = "XML External Entity (XXE) processing activé.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    RiskLevel = "Critical",
                    PayloadExample = "POST /SecurityMisconfiguration/ProcessXml avec DTD externe",
                    ErrorExplanation = "XXE permet la lecture de fichiers locaux et SSRF."
                },
                ["weak-crypto"] = new AttackInfo
                {
                    Description = "Utilisation d'algorithmes cryptographiques faibles.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Weak_Cryptography",
                    RiskLevel = "High",
                    PayloadExample = "GET /SecurityMisconfiguration/EncryptData?data=secret",
                    ErrorExplanation = "MD5 et DES sont obsolètes et vulnérables."
                },
                ["cors-misconfigured"] = new AttackInfo
                {
                    Description = "CORS mal configuré avec '*' permettant toutes les origines.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    RiskLevel = "High",
                    PayloadExample = "GET /SecurityMisconfiguration/ApiData avec Origin: evil.com",
                    ErrorExplanation = "CORS permissif permet les requêtes cross-origin malveillantes."
                },
                ["headers-missing"] = new AttackInfo
                {
                    Description = "Headers de sécurité manquants ou mal configurés.",
                    LearnMoreUrl = "https://owasp.org/www-project-secure-headers/",
                    RiskLevel = "Medium",
                    PayloadExample = "GET /SecurityMisconfiguration/CheckHeaders",
                    ErrorExplanation = "Headers manquants exposent aux attaques XSS, clickjacking, etc."
                },
                ["sensitive-data-exposure"] = new AttackInfo
                {
                    Description = "Exposition de données sensibles dans les réponses.",
                    LearnMoreUrl = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    RiskLevel = "High",
                    PayloadExample = "GET /SecurityMisconfiguration/GetConfig",
                    ErrorExplanation = "Les configurations exposent des secrets et informations système."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<MisconfigurationResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<MisconfigurationResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<MisconfigurationResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<MisconfigurationResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new MisconfigurationResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints réels ci-dessous pour tester les mauvaises configurations."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // Vulnérable : Mode debug exposant la stack trace complète
        [HttpGet]
        public IActionResult GenerateError()
        {
            try
            {
                // VULNÉRABLE : Génère une erreur intentionnelle
                throw new InvalidOperationException("Erreur de test avec informations sensibles");
            }
            catch (Exception ex)
            {
                // VULNÉRABLE : Expose la stack trace complète
                return Json(new
                {
                    success = false,
                    error = ex.Message,
                    stackTrace = ex.StackTrace, // Ne jamais exposer en production!
                    innerException = ex.InnerException?.Message,
                    source = ex.Source,
                    targetSite = ex.TargetSite?.ToString(),
                    environment = _env.EnvironmentName,
                    machineName = Environment.MachineName,
                    osVersion = Environment.OSVersion.ToString(),
                    processId = Environment.ProcessId,
                    warning = "Stack trace et informations système exposées!"
                });
            }
        }

        // Vulnérable : Credentials par défaut
        [HttpPost]
        public IActionResult AdminLogin(string username, string password)
        {
            // VULNÉRABLE : Credentials codés en dur
            var defaultCredentials = new Dictionary<string, string>
            {
                ["admin"] = "admin",      // Mot de passe par défaut!
                ["root"] = "root123",     // Autre credential par défaut
                ["sa"] = "password",      // SQL Server default
                ["test"] = "test"         // Compte de test
            };

            if (defaultCredentials.ContainsKey(username) && defaultCredentials[username] == password)
            {
                return Json(new
                {
                    success = true,
                    message = "Connexion réussie avec credentials par défaut!",
                    token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:admin")), // Token faible
                    permissions = new[] { "read", "write", "delete", "admin" },
                    warning = "Credentials par défaut acceptés!"
                });
            }

            return Json(new { success = false, error = "Credentials invalides" });
        }

        // Vulnérable : Directory listing
        [HttpGet]
        public IActionResult ListFiles(string path)
        {
            try
            {
                // VULNÉRABLE : Énumération de répertoire sans restriction
                var basePath = Path.Combine(_env.ContentRootPath, path ?? "");

                if (Directory.Exists(basePath))
                {
                    var files = Directory.GetFiles(basePath)
                        .Select(f => new
                        {
                            name = Path.GetFileName(f),
                            size = new FileInfo(f).Length,
                            modified = System.IO.File.GetLastWriteTime(f)
                        });

                    var directories = Directory.GetDirectories(basePath)
                        .Select(d => Path.GetFileName(d));

                    return Json(new
                    {
                        success = true,
                        path = path,
                        files = files,
                        directories = directories,
                        warning = "Directory listing activé - fichiers sensibles exposés!"
                    });
                }

                return Json(new { success = false, error = "Répertoire non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : XXE (XML External Entity)
        [HttpPost]
        public IActionResult ProcessXml([FromBody] string xmlData)
        {
            try
            {
                // VULNÉRABLE : XXE activé
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Parse,        // XXE activé!
                    XmlResolver = new XmlUrlResolver()          // Résout les entités externes!
                };

                using (var reader = XmlReader.Create(new StringReader(xmlData), settings))
                {
                    var doc = new XmlDocument();
                    doc.Load(reader); // Charge le XML avec XXE activé

                    return Json(new
                    {
                        success = true,
                        processed = doc.OuterXml,
                        warning = "XXE activé - fichiers locaux peuvent être lus!",
                        example = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Cryptographie faible
        [HttpGet]
        public IActionResult EncryptData(string data)
        {
            if (string.IsNullOrEmpty(data))
                return Json(new { success = false, error = "Données requises" });

            // VULNÉRABLE : MD5 pour le hashing (obsolète)
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(data));
                var md5Hash = BitConverter.ToString(hash).Replace("-", "");

                // VULNÉRABLE : DES pour le chiffrement (obsolète)
                using (var des = DES.Create())
                {
                    des.Key = Encoding.UTF8.GetBytes("12345678"); // Clé faible!
                    des.IV = Encoding.UTF8.GetBytes("87654321");

                    using (var encryptor = des.CreateEncryptor())
                    {
                        var dataBytes = Encoding.UTF8.GetBytes(data);
                        var encrypted = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

                        return Json(new
                        {
                            success = true,
                            original = data,
                            md5Hash = md5Hash,
                            desEncrypted = Convert.ToBase64String(encrypted),
                            weakKey = "12345678", // Exposition de la clé!
                            warning = "MD5 et DES sont obsolètes et cassables!"
                        });
                    }
                }
            }
        }

        // Vulnérable : CORS mal configuré
        [HttpGet]
        public IActionResult ApiData()
        {
            // VULNÉRABLE : CORS trop permissif
            Response.Headers.Add("Access-Control-Allow-Origin", "*"); // Accepte toutes les origines!
            Response.Headers.Add("Access-Control-Allow-Credentials", "true"); // Avec credentials!
            Response.Headers.Add("Access-Control-Allow-Methods", "*"); // Toutes les méthodes!

            return Json(new
            {
                success = true,
                sensitiveData = new
                {
                    apiKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
                    users = new[] { "admin", "user1", "user2" },
                    internalEndpoints = new[] { "/api/internal/users", "/api/internal/secrets" }
                },
                warning = "CORS mal configuré - accessible depuis n'importe quel domaine!"
            });
        }

        // Vulnérable : Headers de sécurité manquants
        [HttpGet]
        public IActionResult CheckHeaders()
        {
            // VULNÉRABLE : Aucun header de sécurité configuré
            var missingHeaders = new[]
            {
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Permissions-Policy"
            };

            var currentHeaders = Response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());

            return Json(new
            {
                success = true,
                missingSecurityHeaders = missingHeaders.Where(h => !currentHeaders.ContainsKey(h)),
                currentHeaders = currentHeaders,
                vulnerabilities = new[]
                {
                    "XSS possible sans X-XSS-Protection",
                    "Clickjacking possible sans X-Frame-Options",
                    "MIME sniffing sans X-Content-Type-Options",
                    "Man-in-the-middle sans HSTS"
                },
                warning = "Headers de sécurité manquants!"
            });
        }

        // Vulnérable : Exposition de configuration
        [HttpGet]
        public IActionResult GetConfig()
        {
            // VULNÉRABLE : Expose toute la configuration
            var config = new Dictionary<string, object>
            {
                ["ConnectionStrings"] = new
                {
                    DefaultConnection = _configuration["ConnectionStrings:DefaultConnection"],
                    Redis = _configuration["ConnectionStrings:Redis"]
                },
                ["ApiKeys"] = new
                {
                    Stripe = _configuration["ApiKeys:Stripe"],
                    SendGrid = _configuration["ApiKeys:SendGrid"],
                    GoogleMaps = _configuration["ApiKeys:GoogleMaps"]
                },
                ["Environment"] = new
                {
                    Name = _env.EnvironmentName,
                    ContentRoot = _env.ContentRootPath,
                    WebRoot = _env.WebRootPath
                },
                ["System"] = new
                {
                    Version = Environment.Version.ToString(),
                    MachineName = Environment.MachineName,
                    ProcessorCount = Environment.ProcessorCount,
                    UserName = Environment.UserName
                }
            };

            return Json(new
            {
                success = true,
                configuration = config,
                warning = "Configuration sensible exposée!",
                allSettings = _configuration.AsEnumerable() // Expose TOUT!
            });
        }

        // Vulnérable : Fichiers de sauvegarde accessibles
        [HttpGet]
        public IActionResult GetBackupFile(string filename)
        {
            // VULNÉRABLE : Accès aux fichiers de backup sans restriction
            var backupExtensions = new[] { ".bak", ".old", ".backup", ".tmp", "~" };

            if (string.IsNullOrEmpty(filename) || !backupExtensions.Any(ext => filename.EndsWith(ext)))
            {
                return Json(new { success = false, error = "Fichier de backup invalide" });
            }

            var path = Path.Combine(_env.ContentRootPath, filename);

            if (System.IO.File.Exists(path))
            {
                var content = System.IO.File.ReadAllText(path);
                return Json(new
                {
                    success = true,
                    filename = filename,
                    content = content.Substring(0, Math.Min(content.Length, 1000)) + "...",
                    size = new FileInfo(path).Length,
                    warning = "Fichiers de backup exposés!"
                });
            }

            return Json(new { success = false, error = "Fichier non trouvé" });
        }

        // Vulnérable : Verbose logging
        [HttpGet]
        public IActionResult GetLogs()
        {
            // VULNÉRABLE : Logs détaillés avec informations sensibles
            var logs = new[]
            {
                $"[{DateTime.Now}] User admin logged in with password: admin123",
                $"[{DateTime.Now}] Database connection: Server=prod-db;User=sa;Password=P@ssw0rd!",
                $"[{DateTime.Now}] API call to https://api.payment.com with key: sk_live_xxx",
                $"[{DateTime.Now}] Credit card processed: 4111-1111-1111-1111",
                $"[{DateTime.Now}] Session token generated: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            };

            return Json(new
            {
                success = true,
                logs = logs,
                logLevel = "DEBUG", // Trop verbeux!
                warning = "Logs exposant des données sensibles!"
            });
        }

        // Endpoint de test
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "GET /SecurityMisconfiguration/GenerateError",
                    "POST /SecurityMisconfiguration/AdminLogin",
                    "GET /SecurityMisconfiguration/ListFiles?path=wwwroot",
                    "POST /SecurityMisconfiguration/ProcessXml",
                    "GET /SecurityMisconfiguration/EncryptData?data=secret",
                    "GET /SecurityMisconfiguration/ApiData",
                    "GET /SecurityMisconfiguration/CheckHeaders",
                    "GET /SecurityMisconfiguration/GetConfig",
                    "GET /SecurityMisconfiguration/GetBackupFile?filename=web.config.bak",
                    "GET /SecurityMisconfiguration/GetLogs"
                },
                vulnerabilities = new[]
                {
                    "Debug mode enabled",
                    "Default credentials",
                    "Directory listing",
                    "XXE processing",
                    "Weak cryptography",
                    "CORS misconfiguration",
                    "Missing security headers",
                    "Configuration exposure",
                    "Backup files accessible",
                    "Verbose logging"
                }
            });
        }
    }

    // Modèle
    public class MisconfigurationResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}