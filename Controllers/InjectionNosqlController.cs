using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionNosqlController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly List<MongoDocument> _usersCollection;

        public InjectionNosqlController()
        {
            // Initialiser la collection simulée
            _usersCollection = InitializeMongoData();

            _attackInfos = new()
            {
                ["basic"] = new AttackInfo
                {
                    Description = "Injection NoSQL basique exploitant la syntaxe JSON pour modifier les requêtes MongoDB, permettant de contourner l'authentification.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "High",
                    PayloadExample = @"{""username"": ""admin"", ""password"": {""$ne"": null}}",
                    ErrorExplanation = "L'injection basique peut échouer si le parseur JSON est strict ou si les opérateurs MongoDB sont filtrés."
                },
                ["operator"] = new AttackInfo
                {
                    Description = "Utilisation d'opérateurs MongoDB ($ne, $gt, $regex, etc.) pour extraire des données ou contourner la logique.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "High",
                    PayloadExample = @"{""username"": {""$regex"": "".*""}, ""password"": {""$ne"": 1}}",
                    ErrorExplanation = "Les opérateurs peuvent être bloqués par une validation côté serveur ou des listes blanches."
                },
                ["where"] = new AttackInfo
                {
                    Description = "Injection JavaScript via l'opérateur $where permettant l'exécution de code arbitraire dans le contexte MongoDB.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "Critical",
                    PayloadExample = @"{""$where"": ""this.password.match(/.*/);""}",
                    ErrorExplanation = "L'opérateur $where peut être désactivé dans la configuration MongoDB pour des raisons de sécurité."
                },
                ["javascript"] = new AttackInfo
                {
                    Description = "Injection de code JavaScript dans les requêtes MongoDB permettant d'exécuter de la logique complexe côté base de données.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "Critical",
                    PayloadExample = @"{""username"": ""admin"", ""password"": {""$where"": ""return true""}}",
                    ErrorExplanation = "L'exécution JavaScript peut être désactivée ou limitée par les paramètres de sécurité MongoDB."
                },
                ["timing"] = new AttackInfo
                {
                    Description = "Attaque temporelle (Time-based) utilisant des fonctions sleep pour extraire des informations caractère par caractère.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "Medium",
                    PayloadExample = @"{""$where"": ""sleep(5000) || this.username == 'admin'""}",
                    ErrorExplanation = "Les fonctions de temporisation peuvent être bloquées ou générer des timeouts."
                },
                ["aggregation"] = new AttackInfo
                {
                    Description = "Exploitation du pipeline d'agrégation MongoDB pour accéder à des collections ou données non autorisées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "High",
                    PayloadExample = @"[{""$lookup"": {""from"": ""system.users"", ""localField"": ""user"", ""foreignField"": ""user"", ""as"": ""userdata""}}]",
                    ErrorExplanation = "Le pipeline d'agrégation peut avoir des restrictions sur les collections accessibles."
                },
                ["type"] = new AttackInfo
                {
                    Description = "Confusion de types exploitant la flexibilité de MongoDB pour comparer différents types de données.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "Medium",
                    PayloadExample = @"{""age"": {""$type"": ""string""}}",
                    ErrorExplanation = "La confusion de types peut ne pas fonctionner si l'application valide strictement les types."
                },
                ["array"] = new AttackInfo
                {
                    Description = "Manipulation d'arrays et d'objets imbriqués pour contourner les validations et accéder à des données cachées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/NoSQL_injection",
                    RiskLevel = "Medium",
                    PayloadExample = @"{""roles"": {""$in"": [""admin"", ""user""]}}",
                    ErrorExplanation = "Les opérateurs d'array peuvent être limités ou filtrés par l'application."
                }
            };
        }

        private List<MongoDocument> InitializeMongoData()
        {
            return new List<MongoDocument>
            {
                new MongoDocument
                {
                    Id = "507f1f77bcf86cd799439011",
                    Data = new Dictionary<string, object>
                    {
                        ["username"] = "admin",
                        ["password"] = "SuperSecret123!",
                        ["email"] = "admin@company.com",
                        ["roles"] = new List<string> { "admin", "user" },
                        ["age"] = 35,
                        ["lastLogin"] = DateTime.Now.AddDays(-1),
                        ["apiKeys"] = new List<string> { "sk_live_admin_key_2024" },
                        ["salary"] = 150000
                    }
                },
                new MongoDocument
                {
                    Id = "507f1f77bcf86cd799439012",
                    Data = new Dictionary<string, object>
                    {
                        ["username"] = "john.doe",
                        ["password"] = "john123456",
                        ["email"] = "john.doe@company.com",
                        ["roles"] = new List<string> { "user" },
                        ["age"] = 28,
                        ["lastLogin"] = DateTime.Now.AddDays(-5),
                        ["creditCard"] = "4111-1111-1111-1111",
                        ["salary"] = 75000
                    }
                },
                new MongoDocument
                {
                    Id = "507f1f77bcf86cd799439013",
                    Data = new Dictionary<string, object>
                    {
                        ["username"] = "jane.smith",
                        ["password"] = "janeSecure789",
                        ["email"] = "jane.smith@company.com",
                        ["roles"] = new List<string> { "user", "moderator" },
                        ["age"] = "32", // Intentionnellement string pour démontrer la confusion de types
                        ["lastLogin"] = DateTime.Now.AddDays(-2),
                        ["ssn"] = "123-45-6789",
                        ["salary"] = 85000
                    }
                },
                new MongoDocument
                {
                    Id = "507f1f77bcf86cd799439014",
                    Data = new Dictionary<string, object>
                    {
                        ["username"] = "test",
                        ["password"] = "test",
                        ["email"] = "test@test.com",
                        ["roles"] = new List<string> { "guest" },
                        ["age"] = 25,
                        ["disabled"] = true
                    }
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<NoSqlResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<NoSqlResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<NoSqlResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<NoSqlResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<NoSqlResult>();
                string mongoQuery = BuildMongoQuery(attackType, payload);

                // Exécuter la requête NoSQL simulée
                var queryResult = ExecuteNoSqlQuery(mongoQuery, payload, attackType);
                results.Add(queryResult);

                var model = VulnerabilityViewModel<NoSqlResult>.WithResults(payload, attackType, results, mongoQuery);
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<NoSqlResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur NoSQL : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private string BuildMongoQuery(string attackType, string payload)
        {
            // Construire la requête MongoDB simulée selon le type d'attaque
            return attackType switch
            {
                "basic" or "operator" or "type" or "array" => $"db.users.find({payload})",
                "where" or "javascript" or "timing" => $"db.users.find({payload})",
                "aggregation" => $"db.users.aggregate({payload})",
                _ => throw new ArgumentException("Type d'attaque inconnu")
            };
        }

        private NoSqlResult ExecuteNoSqlQuery(string query, string payload, string attackType)
        {
            var result = new NoSqlResult
            {
                Query = query,
                ExecutionTime = 0,
                MatchedDocuments = new List<MongoDocument>()
            };

            var startTime = DateTime.Now;

            try
            {
                // Parser le payload JSON
                var queryObj = ParsePayload(payload);

                // Simuler différents types d'attaques
                switch (attackType)
                {
                    case "basic":
                    case "operator":
                        result.MatchedDocuments = SimulateOperatorInjection(queryObj);
                        break;

                    case "where":
                    case "javascript":
                        result.MatchedDocuments = SimulateJavaScriptInjection(payload);
                        result.JavaScriptExecuted = true;
                        break;

                    case "timing":
                        System.Threading.Thread.Sleep(2000); // Simuler le délai
                        result.MatchedDocuments = _usersCollection.Take(1).ToList();
                        break;

                    case "aggregation":
                        result.MatchedDocuments = SimulateAggregationPipeline(payload);
                        result.PipelineStages = ExtractPipelineStages(payload);
                        break;

                    case "type":
                        result.MatchedDocuments = SimulateTypeConfusion(queryObj);
                        break;

                    case "array":
                        result.MatchedDocuments = SimulateArrayOperators(queryObj);
                        break;
                }

                // Détecter les données sensibles exposées
                foreach (var doc in result.MatchedDocuments)
                {
                    if (doc.Data.ContainsKey("password") || doc.Data.ContainsKey("apiKeys") ||
                        doc.Data.ContainsKey("creditCard") || doc.Data.ContainsKey("ssn"))
                    {
                        result.SensitiveDataExposed = true;
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            result.ExecutionTime = (DateTime.Now - startTime).TotalMilliseconds;
            return result;
        }

        private Dictionary<string, object> ParsePayload(string payload)
        {
            try
            {
                // Parser le JSON de manière flexible pour supporter les injections
                return JsonSerializer.Deserialize<Dictionary<string, object>>(payload) ?? new Dictionary<string, object>();
            }
            catch
            {
                // Si le parsing échoue, essayer d'extraire les patterns d'injection
                return new Dictionary<string, object>();
            }
        }

        private List<MongoDocument> SimulateOperatorInjection(Dictionary<string, object> query)
        {
            // Simuler les opérateurs MongoDB comme $ne, $gt, $regex
            var results = new List<MongoDocument>();

            // Si la requête contient des opérateurs d'injection
            if (query.Values.Any(v => v?.ToString()?.Contains("$ne") == true ||
                                     v?.ToString()?.Contains("$gt") == true ||
                                     v?.ToString()?.Contains("$regex") == true))
            {
                // Retourner tous les documents (bypass d'authentification réussi)
                return _usersCollection.ToList();
            }

            // Sinon, recherche normale
            foreach (var doc in _usersCollection)
            {
                bool matches = true;
                foreach (var kvp in query)
                {
                    if (doc.Data.ContainsKey(kvp.Key) && doc.Data[kvp.Key]?.ToString() != kvp.Value?.ToString())
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches) results.Add(doc);
            }

            return results;
        }

        private List<MongoDocument> SimulateJavaScriptInjection(string payload)
        {
            // Si le payload contient $where ou du JavaScript
            if (payload.Contains("$where") || payload.Contains("return true") || payload.Contains("function"))
            {
                // Vulnérabilité : retourner tous les documents
                return _usersCollection.ToList();
            }

            return new List<MongoDocument>();
        }

        private List<MongoDocument> SimulateAggregationPipeline(string payload)
        {
            // Si le payload contient $lookup vers des collections système
            if (payload.Contains("system.users") || payload.Contains("$lookup"))
            {
                // Ajouter des données système simulées
                var systemDoc = new MongoDocument
                {
                    Id = "system_user_1",
                    Data = new Dictionary<string, object>
                    {
                        ["_id"] = "system.admin",
                        ["user"] = "root",
                        ["pwd"] = "5f4dcc3b5aa765d61d8327deb882cf99", // hash MD5
                        ["customData"] = "MongoDB root user",
                        ["roles"] = new List<string> { "root", "admin", "readWriteAnyDatabase" }
                    }
                };
                return new List<MongoDocument> { systemDoc };
            }

            return _usersCollection.Take(2).ToList();
        }

        private List<MongoDocument> SimulateTypeConfusion(Dictionary<string, object> query)
        {
            // Démontrer la confusion de types (age stocké comme string vs number)
            if (query.ContainsKey("age") && query["age"]?.ToString()?.Contains("$type") == true)
            {
                return _usersCollection.Where(d => d.Data.ContainsKey("age") && d.Data["age"] is string).ToList();
            }

            return new List<MongoDocument>();
        }

        private List<MongoDocument> SimulateArrayOperators(Dictionary<string, object> query)
        {
            // Simuler les opérateurs $in, $all, etc.
            if (query.Values.Any(v => v?.ToString()?.Contains("$in") == true))
            {
                // Retourner les documents avec le rôle admin
                return _usersCollection.Where(d =>
                    d.Data.ContainsKey("roles") &&
                    d.Data["roles"] is List<string> roles &&
                    roles.Contains("admin")
                ).ToList();
            }

            return new List<MongoDocument>();
        }

        private List<string> ExtractPipelineStages(string payload)
        {
            var stages = new List<string>();

            if (payload.Contains("$lookup")) stages.Add("$lookup - Join avec une autre collection");
            if (payload.Contains("$match")) stages.Add("$match - Filtrage des documents");
            if (payload.Contains("$project")) stages.Add("$project - Projection des champs");
            if (payload.Contains("$group")) stages.Add("$group - Agrégation des données");

            return stages;
        }
    }

    // Modèles pour NoSQL
    public class MongoDocument
    {
        public string Id { get; set; } = string.Empty;
        public Dictionary<string, object> Data { get; set; } = new();
    }

    public class NoSqlResult
    {
        public string Query { get; set; } = string.Empty;
        public List<MongoDocument> MatchedDocuments { get; set; } = new();
        public double ExecutionTime { get; set; }
        public bool JavaScriptExecuted { get; set; }
        public bool SensitiveDataExposed { get; set; }
        public List<string> PipelineStages { get; set; } = new();
        public string? Error { get; set; }
    }
}