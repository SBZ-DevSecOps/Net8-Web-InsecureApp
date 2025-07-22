using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace InsecureAppWebNet8.Controllers
{
    public class InsecureDesignController : Controller
    {
        private static Dictionary<string, AttackInfo> _attackInfos = new()
        {
            ["delete-order"] = new AttackInfo
            {
                Description = "Tout utilisateur peut supprimer une commande (pas seulement les siennes).",
                RiskLevel = "Medium",
                PayloadExample = "POST /InsecureDesign/DeleteOrder?orderId=2",
                ErrorExplanation = "Pas de contrôle d'accès métier.",
                LearnMoreUrl = "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
            },
            ["admin-panel"] = new AttackInfo
            {
                Description = "N'importe qui peut accéder au panneau admin via l'URL.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/AdminPanel",
                ErrorExplanation = "Pas de contrôle de rôle.",
                LearnMoreUrl = "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
            },
            ["add-product"] = new AttackInfo
            {
                Description = "Produit avec prix négatif accepté car la validation est absente côté serveur.",
                RiskLevel = "Medium",
                PayloadExample = "POST /InsecureDesign/AddProduct?name=TV&price=-1000",
                ErrorExplanation = "Aucune validation serveur, l'utilisateur peut abuser du workflow.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Business_Logic"
            },
            ["reset-password"] = new AttackInfo
            {
                Description = "Réinitialisation de mot de passe sans challenge ni lien sécurisé.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/ResetPassword?username=alice",
                ErrorExplanation = "Lien de reset utilisable sans contrôle.",
                LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
            },
            ["update-user"] = new AttackInfo
            {
                Description = "On peut modifier le profil d'un autre utilisateur via son userId.",
                RiskLevel = "Medium",
                PayloadExample = "POST /InsecureDesign/UpdateUser?userId=101&username=pwned",
                ErrorExplanation = "Aucun contrôle sur l'appartenance de l'objet modifié.",
                LearnMoreUrl = "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
            },
            ["mass-assignment"] = new AttackInfo
            {
                Description = "Le champ 'role' peut être modifié en même temps que les autres champs.",
                RiskLevel = "High",
                PayloadExample = "POST /InsecureDesign/UpdateProfile avec role=Admin dans le body",
                ErrorExplanation = "Un utilisateur lambda peut devenir admin.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Mass_Assignment"
            },
            ["command-exec"] = new AttackInfo
            {
                Description = "Exécution de commandes système via des paramètres non validés.",
                RiskLevel = "Critical",
                PayloadExample = "GET /InsecureDesign/Ping?host=8.8.8.8;ls -la",
                ErrorExplanation = "Injection de commandes OS possible.",
                LearnMoreUrl = "https://owasp.org/www-community/attacks/Command_Injection"
            },
            ["xxe-parse"] = new AttackInfo
            {
                Description = "Parser XML vulnérable aux attaques XXE.",
                RiskLevel = "High",
                PayloadExample = "POST /InsecureDesign/ParseXml avec payload XXE",
                ErrorExplanation = "Entities externes activées dans le parser XML.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
            },
            ["sql-concat"] = new AttackInfo
            {
                Description = "Construction de requête SQL par concaténation.",
                RiskLevel = "Critical",
                PayloadExample = "GET /InsecureDesign/SearchUser?name=admin' OR '1'='1",
                ErrorExplanation = "SQL Injection via concaténation de strings.",
                LearnMoreUrl = "https://owasp.org/www-community/attacks/SQL_Injection"
            },
            ["hardcoded-secrets"] = new AttackInfo
            {
                Description = "Secrets et mots de passe hardcodés dans le code.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/GetConfig",
                ErrorExplanation = "Credentials en dur dans le code source.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
            },
            ["path-traversal"] = new AttackInfo
            {
                Description = "Accès à des fichiers arbitraires via path traversal.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/DownloadFile?filename=../../../../etc/passwd",
                ErrorExplanation = "Pas de validation du chemin de fichier.",
                LearnMoreUrl = "https://owasp.org/www-community/attacks/Path_Traversal"
            },
            ["weak-crypto"] = new AttackInfo
            {
                Description = "Utilisation d'algorithmes de cryptographie faibles (MD5, SHA1).",
                RiskLevel = "Medium",
                PayloadExample = "POST /InsecureDesign/HashPassword?password=test123",
                ErrorExplanation = "MD5 est obsolète et vulnérable.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Using_a_broken_or_risky_cryptographic_algorithm"
            },
            ["open-redirect"] = new AttackInfo
            {
                Description = "Redirection ouverte permettant le phishing.",
                RiskLevel = "Medium",
                PayloadExample = "GET /InsecureDesign/Redirect?url=http://evil.com",
                ErrorExplanation = "URL de redirection non validée.",
                LearnMoreUrl = "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"
            },
            ["debug-enabled"] = new AttackInfo
            {
                Description = "Mode debug activé en production avec stacktraces.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/Error",
                ErrorExplanation = "Information disclosure via stacktraces.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_error_messages"
            },
            ["insecure-random"] = new AttackInfo
            {
                Description = "Utilisation de Random() pour générer des tokens de sécurité.",
                RiskLevel = "High",
                PayloadExample = "GET /InsecureDesign/GenerateToken",
                ErrorExplanation = "Random() n'est pas cryptographiquement sûr.",
                LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"
            }
        };

        // Données en mémoire (vulnérables)
        private static readonly Dictionary<int, Order> _orders = new()
        {
            [1] = new Order { Id = 1, UserId = 100, Product = "Laptop", Amount = 1200, Status = "Delivered" },
            [2] = new Order { Id = 2, UserId = 101, Product = "Phone", Amount = 800, Status = "Processing" },
            [3] = new Order { Id = 3, UserId = 102, Product = "Tablet", Amount = 500, Status = "Pending" }
        };

        private static readonly Dictionary<int, User> _users = new()
        {
            [100] = new User { Id = 100, Username = "alice", Email = "alice@example.com", Role = "User", Password = "password123" },
            [101] = new User { Id = 101, Username = "bob", Email = "bob@example.com", Role = "User", Password = "qwerty" },
            [102] = new User { Id = 102, Username = "admin", Email = "admin@example.com", Role = "Admin", Password = "admin123" }
        };

        // Secrets hardcodés (vulnérable - sera détecté par SAST)
        private const string API_KEY = "sk_live_4242424242424242";
        private const string DB_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "my-super-secret-key-123";

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<InsecureDesignResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<InsecureDesignResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<InsecureDesignResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<InsecureDesignResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new InsecureDesignResult
                {
                    AttackType = attackType,
                    OriginalPayload = payload,
                    Success = true,
                    Timestamp = DateTime.Now,
                    ExploitedData = new List<string> { "Utiliser les vrais endpoints listés dans les exemples pour tester les vulnérabilités réelles." }
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // Vulnérable : Pas d'autorisation (sera détecté par SAST)
        [HttpGet]
        public IActionResult AdminPanel()
        {
            // VULNÉRABLE : Aucun contrôle d'accès - [Authorize] manquant
            var adminData = new
            {
                users = _users.Values.ToList(),
                orders = _orders.Values.ToList(),
                apiKey = API_KEY, // Secret exposé
                dbPassword = DB_PASSWORD // Mot de passe exposé
            };
            return Json(adminData);
        }

        // Vulnérable : IDOR - Suppression sans vérification
        [HttpPost]
        public IActionResult DeleteOrder(int orderId)
        {
            // VULNÉRABLE : Pas de vérification que l'utilisateur possède la commande
            if (_orders.ContainsKey(orderId))
            {
                _orders.Remove(orderId);
                return Json(new { success = true, message = $"Commande {orderId} supprimée" });
            }
            return Json(new { success = false });
        }

        // Vulnérable : Validation métier absente
        [HttpPost]
        public IActionResult AddProduct(string name, decimal price)
        {
            // VULNÉRABLE : Accepte des prix négatifs
            var product = new ProductItem
            {
                Id = new Random().Next(1000, 9999),
                Name = name,
                Price = price // Pas de validation price > 0
            };
            return Json(new { success = true, product });
        }

        // Vulnérable : Reset de mot de passe sans vérification
        [HttpGet]
        public IActionResult ResetPassword(string username)
        {
            // VULNÉRABLE : Reset sans token ni vérification d'identité
            var user = _users.Values.FirstOrDefault(u => u.Username == username);
            if (user != null)
            {
                user.Password = "Password123!"; // Nouveau mot de passe en clair
                return Json(new { success = true, message = $"Mot de passe réinitialisé pour {username}" });
            }
            return Json(new { success = false });
        }

        // Vulnérable : Mass Assignment
        [HttpPost]
        public IActionResult UpdateProfile(User userUpdate)
        {
            // VULNÉRABLE : Binding de tous les champs incluant Role
            if (_users.ContainsKey(userUpdate.Id))
            {
                _users[userUpdate.Id] = userUpdate; // Mass assignment du rôle possible
                return Json(new { success = true, user = userUpdate });
            }
            return Json(new { success = false });
        }

        // Vulnérable : Command Injection
        [HttpGet]
        public IActionResult Ping(string host)
        {
            // VULNÉRABLE : Injection de commande OS
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c ping {host}", // Injection possible ici
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            return Content(output);
        }

        // Vulnérable : XXE
        [HttpPost]
        public IActionResult ParseXml([FromBody] string xmlContent)
        {
            // VULNÉRABLE : DTD et entités externes activées
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse, // Vulnérable
                XmlResolver = new XmlUrlResolver() // Vulnérable
            };

            using (var reader = XmlReader.Create(new StringReader(xmlContent), settings))
            {
                var doc = new XmlDocument();
                doc.Load(reader);
                return Json(new { success = true, content = doc.InnerText });
            }
        }

        // Vulnérable : SQL Injection
        [HttpGet]
        public IActionResult SearchUser(string name)
        {
            // VULNÉRABLE : Concaténation SQL
            var query = $"SELECT * FROM Users WHERE Username = '{name}'"; // SQL Injection

            // Simulation d'exécution (en vrai ce serait une vraie DB)
            var results = _users.Values.Where(u => u.Username.Contains(name)).ToList();

            return Json(new { query, results });
        }

        // Vulnérable : Path Traversal
        [HttpGet]
        public IActionResult DownloadFile(string filename)
        {
            // VULNÉRABLE : Pas de validation du chemin
            var path = Path.Combine("wwwroot/files/", filename); // Path traversal possible

            if (System.IO.File.Exists(path))
            {
                var content = System.IO.File.ReadAllText(path);
                return Content(content);
            }
            return NotFound();
        }

        // Vulnérable : Weak Crypto
        [HttpPost]
        public IActionResult HashPassword(string password)
        {
            // VULNÉRABLE : Utilisation de MD5
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                var hashString = BitConverter.ToString(hash).Replace("-", "");
                return Json(new { hash = hashString, algorithm = "MD5" });
            }
        }

        // Vulnérable : Open Redirect
        [HttpGet]
        public IActionResult Redirect(string url)
        {
            // VULNÉRABLE : Redirection sans validation
            return Redirect(url); // Open redirect
        }

        // Vulnérable : Information Disclosure
        [HttpGet]
        public IActionResult Error()
        {
            try
            {
                throw new Exception("Erreur intentionnelle pour test");
            }
            catch (Exception ex)
            {
                // VULNÉRABLE : Stacktrace exposée
                return Json(new
                {
                    error = ex.Message,
                    stackTrace = ex.StackTrace, // Information disclosure
                    innerException = ex.InnerException?.Message
                });
            }
        }

        // Vulnérable : Insecure Random
        [HttpGet]
        public IActionResult GenerateToken()
        {
            // VULNÉRABLE : Random() au lieu de cryptographically secure random
            var random = new Random();
            var token = "";
            for (int i = 0; i < 16; i++)
            {
                token += random.Next(0, 10).ToString();
            }
            return Json(new { token, warning = "Token généré avec Random() non sécurisé" });
        }

        // Vulnérable : Hardcoded Secrets
        [HttpGet]
        public IActionResult GetConfig()
        {
            // VULNÉRABLE : Secrets hardcodés exposés
            return Json(new
            {
                apiKey = API_KEY,
                jwtSecret = JWT_SECRET,
                dbPassword = DB_PASSWORD,
                connectionString = $"Server=localhost;Database=InsecureApp;User Id=sa;Password={DB_PASSWORD};"
            });
        }

        // Vulnérable : IDOR sur update
        [HttpPost]
        public IActionResult UpdateUser(int userId, string username)
        {
            // VULNÉRABLE : Pas de vérification que l'utilisateur peut modifier ce profil
            if (_users.ContainsKey(userId))
            {
                _users[userId].Username = username;
                return Json(new { success = true, user = _users[userId] });
            }
            return Json(new { success = false });
        }
    }

    // Modèles
    public class InsecureDesignResult
    {
        public string AttackType { get; set; } = string.Empty;
        public string OriginalPayload { get; set; } = string.Empty;
        public bool Success { get; set; }
        public DateTime Timestamp { get; set; }
        public List<string> ExploitedData { get; set; } = new();
    }

    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Product { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty; // Vulnérable : mot de passe en clair
    }

    public class ProductItem
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public decimal Price { get; set; }
    }
}