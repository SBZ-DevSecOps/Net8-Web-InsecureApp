using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Serialization;

namespace InsecureAppWebNet8.Controllers
{
    public class SoftwareIntegrityController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _env;
        private readonly string _updatePath;
        private readonly string _pluginPath;
        private static readonly Dictionary<string, object> _cache = new();

        public SoftwareIntegrityController(IWebHostEnvironment env)
        {
            _env = env;
            _updatePath = Path.Combine(_env.WebRootPath, "updates");
            _pluginPath = Path.Combine(_env.WebRootPath, "plugins");

            // Créer les répertoires s'ils n'existent pas
            Directory.CreateDirectory(_updatePath);
            Directory.CreateDirectory(_pluginPath);

            _attackInfos = new()
            {
                ["insecure-deserialization"] = new AttackInfo
                {
                    Description = "Désérialisation d'objets non fiables permettant l'exécution de code.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                    RiskLevel = "Critical",
                    PayloadExample = "Base64 de BinaryFormatter avec gadget chain",
                    ErrorExplanation = "La désérialisation peut exécuter du code arbitraire."
                },
                ["unsigned-updates"] = new AttackInfo
                {
                    Description = "Mises à jour sans signature numérique ni vérification d'intégrité.",
                    LearnMoreUrl = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                    RiskLevel = "Critical",
                    PayloadExample = "Update.exe malveillant sans signature",
                    ErrorExplanation = "Les mises à jour non signées peuvent être remplacées."
                },
                ["untrusted-sources"] = new AttackInfo
                {
                    Description = "Téléchargement de code depuis des sources non vérifiées (CDN, npm, etc).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Content_Spoofing",
                    RiskLevel = "High",
                    PayloadExample = "https://cdnjs.cloudflare.com/malicious.js",
                    ErrorExplanation = "Les CDN et dépôts peuvent être compromis."
                },
                ["weak-integrity"] = new AttackInfo
                {
                    Description = "Vérification d'intégrité faible (MD5, SHA1) ou absente.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html",
                    RiskLevel = "High",
                    PayloadExample = "MD5 collision pour remplacer un fichier",
                    ErrorExplanation = "MD5 et SHA1 sont cassés et permettent des collisions."
                },
                ["insecure-ci-cd"] = new AttackInfo
                {
                    Description = "Pipeline CI/CD sans vérification permettant l'injection de code.",
                    LearnMoreUrl = "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
                    RiskLevel = "High",
                    PayloadExample = "Injection dans build.yml ou Dockerfile",
                    ErrorExplanation = "Les pipelines non sécurisés peuvent être compromis."
                },
                ["plugin-upload"] = new AttackInfo
                {
                    Description = "Upload de plugins/extensions sans validation ni sandboxing.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    RiskLevel = "High",
                    PayloadExample = "Plugin.dll avec code malveillant",
                    ErrorExplanation = "Les plugins peuvent contenir du code arbitraire."
                },
                ["auto-update"] = new AttackInfo
                {
                    Description = "Mise à jour automatique via HTTP sans chiffrement ni authentification.",
                    LearnMoreUrl = "https://capec.mitre.org/data/definitions/187.html",
                    RiskLevel = "High",
                    PayloadExample = "http://update.server/latest.exe",
                    ErrorExplanation = "HTTP permet les attaques man-in-the-middle."
                },
                ["cache-poisoning"] = new AttackInfo
                {
                    Description = "Empoisonnement du cache avec des données malveillantes.",
                    LearnMoreUrl = "https://portswigger.net/web-security/web-cache-poisoning",
                    RiskLevel = "Medium",
                    PayloadExample = "Cache-Control: malicious-value",
                    ErrorExplanation = "Le cache peut servir du contenu malveillant."
                },
                ["yaml-injection"] = new AttackInfo
                {
                    Description = "Injection via désérialisation YAML non sécurisée.",
                    LearnMoreUrl = "https://blog.securelayer7.net/yaml-deserialization-attack-in-python/",
                    RiskLevel = "High",
                    PayloadExample = "!!python/object/apply:os.system ['calc.exe']",
                    ErrorExplanation = "YAML peut exécuter du code lors de la désérialisation."
                },
                ["supply-chain"] = new AttackInfo
                {
                    Description = "Attaque de la chaîne d'approvisionnement via dépendances compromises.",
                    LearnMoreUrl = "https://www.sonatype.com/resources/state-of-the-software-supply-chain-2021",
                    RiskLevel = "Critical",
                    PayloadExample = "Package npm avec backdoor",
                    ErrorExplanation = "Les dépendances tierces peuvent être malveillantes."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<IntegrityFailureResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<IntegrityFailureResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<IntegrityFailureResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<IntegrityFailureResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new IntegrityFailureResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les vulnérabilités d'intégrité."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Désérialisation non sécurisée avec BinaryFormatter
        [HttpPost]
        [Obsolete("BinaryFormatter is obsolete and should not be used")]
        public IActionResult DeserializeObject(string serializedData)
        {
            if (string.IsNullOrEmpty(serializedData))
                return Json(new { success = false, error = "Données sérialisées requises" });

            try
            {
                // VULNÉRABLE : BinaryFormatter est dangereux
                var bytes = Convert.FromBase64String(serializedData);
                using (var stream = new MemoryStream(bytes))
                {
                    // VULNÉRABLE : Désérialisation sans validation
#pragma warning disable SYSLIB0011 // Type or member is obsolete
                    var formatter = new BinaryFormatter();
                    var obj = formatter.Deserialize(stream);
#pragma warning restore SYSLIB0011 // Type or member is obsolete

                    return Json(new
                    {
                        success = true,
                        deserializedType = obj?.GetType().FullName,
                        value = obj?.ToString(),
                        warning = "BinaryFormatter permet l'exécution de code arbitraire!",
                        exploit = "Utiliser ysoserial.net pour générer des payloads",
                        gadgetChains = new[]
                        {
                            "TypeConfuseDelegate",
                            "WindowsIdentity",
                            "DataSet",
                            "ObjectDataProvider"
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    error = ex.Message,
                    warning = "La désérialisation a échoué mais reste vulnérable!"
                });
            }
        }

        // VULNÉRABLE : Désérialisation JSON avec TypeNameHandling
        [HttpPost]
        public IActionResult DeserializeJson(string jsonData)
        {
            if (string.IsNullOrEmpty(jsonData))
                return Json(new { success = false, error = "JSON requis" });

            try
            {
                // VULNÉRABLE : TypeNameHandling.All permet l'injection de types
                var settings = new Newtonsoft.Json.JsonSerializerSettings
                {
                    TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All // VULNÉRABLE !
                };

                dynamic obj = Newtonsoft.Json.JsonConvert.DeserializeObject(jsonData, settings);

                return Json(new
                {
                    success = true,
                    deserializedType = obj?.GetType().FullName,
                    warning = "TypeNameHandling.All permet l'injection de types malveillants!",
                    exploit = @"{
                        '$type': 'System.Windows.Data.ObjectDataProvider, PresentationFramework',
                        'MethodName': 'Start',
                        'MethodParameters': {
                            '$type': 'System.Collections.ArrayList',
                            '$values': ['calc.exe']
                        },
                        'ObjectInstance': {
                            '$type': 'System.Diagnostics.Process, System'
                        }
                    }"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Téléchargement de mise à jour sans vérification
        [HttpPost]
        public async Task<IActionResult> DownloadUpdate(string updateUrl)
        {
            if (string.IsNullOrEmpty(updateUrl))
                return Json(new { success = false, error = "URL de mise à jour requise" });

            try
            {
                // VULNÉRABLE : Pas de vérification HTTPS
                if (!updateUrl.StartsWith("https://") && !updateUrl.StartsWith("http://"))
                {
                    updateUrl = "http://" + updateUrl; // VULNÉRABLE : Force HTTP
                }

                using (var client = new HttpClient())
                {
                    // VULNÉRABLE : Pas de vérification du certificat
                    var response = await client.GetAsync(updateUrl);
                    var content = await response.Content.ReadAsByteArrayAsync();

                    // VULNÉRABLE : Pas de vérification de signature
                    var fileName = Path.GetFileName(new Uri(updateUrl).LocalPath);
                    var updatePath = Path.Combine(_updatePath, fileName);

                    await System.IO.File.WriteAllBytesAsync(updatePath, content);

                    // VULNÉRABLE : Calcul MD5 (cassé)
                    using (var md5 = MD5.Create())
                    {
                        var hash = md5.ComputeHash(content);
                        var md5Hash = BitConverter.ToString(hash).Replace("-", "");

                        return Json(new
                        {
                            success = true,
                            fileName = fileName,
                            size = content.Length,
                            md5 = md5Hash,
                            warning = "Mise à jour téléchargée sans vérification!",
                            vulnerabilities = new[]
                            {
                                "Pas de signature numérique",
                                "HTTP autorisé (MITM possible)",
                                "MD5 pour l'intégrité (collision possible)",
                                "Pas de vérification de l'éditeur",
                                "Exécution automatique possible"
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Chargement de plugin sans validation
        [HttpPost]
        public async Task<IActionResult> LoadPlugin(IFormFile pluginFile)
        {
            if (pluginFile == null || pluginFile.Length == 0)
                return Json(new { success = false, error = "Fichier plugin requis" });

            try
            {
                // VULNÉRABLE : Pas de validation du type de fichier
                var pluginPath = Path.Combine(_pluginPath, pluginFile.FileName);

                using (var stream = new FileStream(pluginPath, FileMode.Create))
                {
                    await pluginFile.CopyToAsync(stream);
                }

                // VULNÉRABLE : Chargement dynamique d'assembly
                if (pluginFile.FileName.EndsWith(".dll"))
                {
                    try
                    {
                        // VULNÉRABLE : Charge n'importe quelle DLL
                        var assembly = Assembly.LoadFrom(pluginPath);
                        var types = assembly.GetTypes();

                        return Json(new
                        {
                            success = true,
                            fileName = pluginFile.FileName,
                            assemblyName = assembly.FullName,
                            typesCount = types.Length,
                            types = types.Select(t => t.FullName).Take(10),
                            warning = "Plugin chargé sans validation - Code arbitraire possible!",
                            risks = new[]
                            {
                                "Exécution de code arbitraire",
                                "Pas de sandboxing",
                                "Pas de vérification de signature",
                                "Accès complet au système",
                                "Persistance possible"
                            }
                        });
                    }
                    catch (Exception ex)
                    {
                        return Json(new
                        {
                            success = false,
                            error = $"Erreur chargement DLL: {ex.Message}",
                            warning = "Même en cas d'erreur, le fichier reste sur le serveur!"
                        });
                    }
                }

                return Json(new
                {
                    success = true,
                    fileName = pluginFile.FileName,
                    uploaded = true,
                    warning = "Fichier plugin uploadé sans validation!"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Vérification d'intégrité faible
        [HttpPost]
        public IActionResult VerifyIntegrity(string filePath, string expectedHash, string algorithm = "MD5")
        {
            if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(expectedHash))
                return Json(new { success = false, error = "Chemin et hash requis" });

            try
            {
                var fullPath = Path.Combine(_updatePath, filePath);
                if (!System.IO.File.Exists(fullPath))
                    return Json(new { success = false, error = "Fichier non trouvé" });

                var fileBytes = System.IO.File.ReadAllBytes(fullPath);
                string computedHash = "";

                // VULNÉRABLE : Utilise des algorithmes cassés
                switch (algorithm.ToUpper())
                {
                    case "MD5":
                        using (var md5 = MD5.Create())
                        {
                            var hash = md5.ComputeHash(fileBytes);
                            computedHash = BitConverter.ToString(hash).Replace("-", "");
                        }
                        break;
                    case "SHA1":
                        using (var sha1 = SHA1.Create())
                        {
                            var hash = sha1.ComputeHash(fileBytes);
                            computedHash = BitConverter.ToString(hash).Replace("-", "");
                        }
                        break;
                    default:
                        computedHash = "UNSUPPORTED";
                        break;
                }

                var isValid = computedHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);

                return Json(new
                {
                    success = true,
                    algorithm = algorithm,
                    expectedHash = expectedHash,
                    computedHash = computedHash,
                    isValid = isValid,
                    warning = $"{algorithm} est vulnérable aux collisions!",
                    vulnerabilities = new[]
                    {
                        "MD5: Collisions en quelques secondes",
                        "SHA1: Collisions démontrées (SHAttered)",
                        "Pas de signature numérique",
                        "Hash peut être forgé",
                        "TOCTOU possible"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Pipeline CI/CD non sécurisé
        [HttpPost]
        public IActionResult ExecutePipeline(string pipelineConfig)
        {
            if (string.IsNullOrEmpty(pipelineConfig))
                return Json(new { success = false, error = "Configuration requise" });

            try
            {
                // VULNÉRABLE : Parse YAML sans validation
                // Simulation d'un parser YAML vulnérable
                if (pipelineConfig.Contains("!!") || pipelineConfig.Contains("!ruby") || pipelineConfig.Contains("!python"))
                {
                    return Json(new
                    {
                        success = true,
                        warning = "YAML injection détectée - Code arbitraire possible!",
                        detected = "Tags YAML dangereux",
                        examples = new[]
                        {
                            "!!python/object/apply:os.system ['calc.exe']",
                            "!ruby/object:Gem::Requirement",
                            "!!javax.script.ScriptEngineManager",
                            "!com.sun.rowset.JdbcRowSetImpl"
                        }
                    });
                }

                // VULNÉRABLE : Exécution directe de commandes
                var commands = new List<string>();
                var lines = pipelineConfig.Split('\n');
                foreach (var line in lines)
                {
                    if (line.TrimStart().StartsWith("- run:") || line.TrimStart().StartsWith("script:"))
                    {
                        var command = line.Substring(line.IndexOf(':') + 1).Trim();
                        commands.Add(command);
                    }
                }

                return Json(new
                {
                    success = true,
                    commands = commands,
                    warning = "Commandes exécutées sans validation!",
                    risks = new[]
                    {
                        "Injection de commandes",
                        "Pas de sandboxing",
                        "Secrets exposés",
                        "Modification du build",
                        "Backdoor dans les artifacts"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : CDN non vérifié
        [HttpPost]
        public IActionResult LoadFromCDN(string cdnUrl)
        {
            if (string.IsNullOrEmpty(cdnUrl))
                return Json(new { success = false, error = "URL CDN requise" });

            try
            {
                // VULNÉRABLE : Pas de vérification de l'intégrité SRI
                var hasIntegrity = cdnUrl.Contains("integrity=") || cdnUrl.Contains("sri=");
                var isHttps = cdnUrl.StartsWith("https://");

                // Parse pour extraire des infos
                Uri uri;
                try
                {
                    uri = new Uri(cdnUrl);
                }
                catch
                {
                    uri = new Uri("http://" + cdnUrl);
                }

                return Json(new
                {
                    success = true,
                    url = cdnUrl,
                    host = uri.Host,
                    isHttps = isHttps,
                    hasIntegrity = hasIntegrity,
                    warning = "CDN sans vérification d'intégrité!",
                    vulnerabilities = new[]
                    {
                        hasIntegrity ? null : "Pas de Subresource Integrity (SRI)",
                        isHttps ? null : "HTTP permet le MITM",
                        "CDN peut être compromis",
                        "Pas de vérification du contenu",
                        "Code tiers non audité"
                    }.Where(v => v != null),
                    recommendation = "<script src='https://cdn.com/lib.js' integrity='sha384-...' crossorigin='anonymous'></script>"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Cache poisoning
        [HttpPost]
        public IActionResult PoisonCache(string key, string value)
        {
            if (string.IsNullOrEmpty(key))
                return Json(new { success = false, error = "Clé requise" });

            try
            {
                // VULNÉRABLE : Stocke n'importe quoi dans le cache
                _cache[key] = value;

                // VULNÉRABLE : Désérialise si c'est du JSON
                if (value?.StartsWith("{") == true || value?.StartsWith("[") == true)
                {
                    try
                    {
                        // VULNÉRABLE : Désérialisation sans validation
                        var obj = JsonSerializer.Deserialize<dynamic>(value);
                        _cache[key + "_parsed"] = obj;
                    }
                    catch { }
                }

                return Json(new
                {
                    success = true,
                    key = key,
                    value = value,
                    cacheSize = _cache.Count,
                    warning = "Cache empoisonné - Données non validées!",
                    poisonedKeys = _cache.Keys.Take(10),
                    risks = new[]
                    {
                        "XSS stocké via cache",
                        "Désérialisation non sécurisée",
                        "Déni de service (remplissage)",
                        "Fuite d'informations",
                        "Persistence d'attaque"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Auto-update via HTTP
        [HttpGet]
        public IActionResult CheckForUpdates(string updateServer = "http://update.insecure-app.com")
        {
            try
            {
                // VULNÉRABLE : HTTP par défaut
                var updateUrl = $"{updateServer}/latest-version.json";
                var currentVersion = "1.0.0";

                return Json(new
                {
                    success = true,
                    currentVersion = currentVersion,
                    updateUrl = updateUrl,
                    protocol = new Uri(updateUrl).Scheme,
                    warning = "Vérification de mise à jour via HTTP!",
                    vulnerabilities = new[]
                    {
                        "HTTP permet MITM",
                        "Pas d'authentification du serveur",
                        "Version peut être falsifiée",
                        "Téléchargement automatique dangereux",
                        "Pas de rollback"
                    },
                    updateProcess = new[]
                    {
                        "1. Check version (HTTP)",
                        "2. Download update (HTTP)",
                        "3. No signature verification",
                        "4. Execute update",
                        "5. System compromised!"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Sérialisation XML non sécurisée
        [HttpPost]
        public IActionResult DeserializeXml(string xmlData)
        {
            if (string.IsNullOrEmpty(xmlData))
                return Json(new { success = false, error = "XML requis" });

            try
            {
                // VULNÉRABLE : XmlSerializer avec types non validés
                var serializer = new XmlSerializer(typeof(object));

                using (var reader = new StringReader(xmlData))
                {
                    // VULNÉRABLE : Pas de validation du XML
                    var obj = serializer.Deserialize(reader);

                    return Json(new
                    {
                        success = true,
                        deserializedType = obj?.GetType().FullName,
                        warning = "XML désérialisé sans validation!",
                        vulnerabilities = new[]
                        {
                            "Types arbitraires",
                            "XXE possible",
                            "Expansion d'entités",
                            "SSRF via DTD",
                            "DoS via billion laughs"
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    error = ex.Message,
                    hint = "Essayez avec des types malveillants"
                });
            }
        }

        // Endpoint de test
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "POST /IntegrityFailures/DeserializeObject - BinaryFormatter vulnérable",
                    "POST /IntegrityFailures/DeserializeJson - JSON.NET TypeNameHandling.All",
                    "POST /IntegrityFailures/DownloadUpdate - Téléchargement sans vérification",
                    "POST /IntegrityFailures/LoadPlugin - Chargement de DLL arbitraire",
                    "POST /IntegrityFailures/VerifyIntegrity - Hash MD5/SHA1 faible",
                    "POST /IntegrityFailures/ExecutePipeline - CI/CD injection",
                    "POST /IntegrityFailures/LoadFromCDN - CDN sans SRI",
                    "POST /IntegrityFailures/PoisonCache - Cache poisoning",
                    "GET /IntegrityFailures/CheckForUpdates - Auto-update HTTP",
                    "POST /IntegrityFailures/DeserializeXml - XML non sécurisé"
                },
                vulnerabilities = new[]
                {
                    "Insecure deserialization (BinaryFormatter)",
                    "No signature verification",
                    "Weak hash algorithms (MD5/SHA1)",
                    "Untrusted code execution",
                    "HTTP for updates (MITM)",
                    "No integrity checks (SRI)",
                    "YAML/JSON injection",
                    "Supply chain attacks",
                    "Plugin system bypass",
                    "Cache poisoning"
                },
                payloadExamples = new
                {
                    binaryFormatter = "Use ysoserial.net for gadget chains",
                    jsonNet = "{'$type':'System.Diagnostics.Process','StartInfo':{'FileName':'calc.exe'}}",
                    yamlInjection = "!!python/object/apply:os.system ['whoami']",
                    updateUrl = "http://evil.com/malicious-update.exe",
                    cdnUrl = "http://malicious-cdn.com/jquery.js"
                }
            });
        }
    }

    // Modèle
    public class IntegrityFailureResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}