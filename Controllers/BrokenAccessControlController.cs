using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace InsecureAppWebNet8.Controllers
{
    public class BrokenAccessControlController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // Simulation de données sensibles
        private static readonly Dictionary<int, UserProfile> _users = new()
        {
            [1] = new UserProfile
            {
                Id = 1,
                Username = "alice",
                Email = "alice@example.com",
                Role = "user",
                Salary = 45000,
                SocialSecurityNumber = "123-45-6789",
                CreditCardNumber = "4111-1111-1111-1111"
            },
            [2] = new UserProfile
            {
                Id = 2,
                Username = "bob",
                Email = "bob@example.com",
                Role = "user",
                Salary = 52000,
                SocialSecurityNumber = "987-65-4321",
                CreditCardNumber = "5500-0000-0000-0004"
            },
            [3] = new UserProfile
            {
                Id = 3,
                Username = "admin",
                Email = "admin@example.com",
                Role = "admin",
                Salary = 95000,
                SocialSecurityNumber = "555-55-5555",
                CreditCardNumber = "3400-0000-0000-009"
            }
        };

        private static readonly Dictionary<int, Document> _documents = new()
        {
            [1] = new Document { Id = 1, Title = "Rapport Q1 2024", OwnerId = 1, Content = "Résultats confidentiels Q1...", IsConfidential = true },
            [2] = new Document { Id = 2, Title = "Notes de réunion", OwnerId = 2, Content = "Discussion stratégie produit...", IsConfidential = false },
            [3] = new Document { Id = 3, Title = "Salaires 2024", OwnerId = 3, Content = "Liste des salaires de tous les employés...", IsConfidential = true }
        };

        public BrokenAccessControlController()
        {
            _attackInfos = new()
            {
                ["idor"] = new AttackInfo
                {
                    Description = "IDOR (Insecure Direct Object Reference) - Accès direct aux objets sans vérification.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                    RiskLevel = "High",
                    PayloadExample = "GET /BrokenAccessControl/GetProfile?userId=2",
                    ErrorExplanation = "L'application ne vérifie pas si l'utilisateur a le droit d'accéder à cette ressource."
                },
                ["missing-auth"] = new AttackInfo
                {
                    Description = "Endpoints sensibles sans authentification.",
                    LearnMoreUrl = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /BrokenAccessControl/AdminDashboard",
                    ErrorExplanation = "Les endpoints sensibles ne vérifient pas si l'utilisateur est authentifié."
                },
                ["privilege-escalation"] = new AttackInfo
                {
                    Description = "Élévation de privilèges via modification directe du rôle.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Privilege_Escalation",
                    RiskLevel = "Critical",
                    PayloadExample = "POST /BrokenAccessControl/UpdateProfile avec role=admin",
                    ErrorExplanation = "L'application accepte le paramètre role depuis le client."
                },
                ["forced-browsing"] = new AttackInfo
                {
                    Description = "Accès à des ressources cachées via manipulation d'URL.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Forced_browsing",
                    RiskLevel = "Medium",
                    PayloadExample = "GET /BrokenAccessControl/BackupData",
                    ErrorExplanation = "Les ressources sensibles sont accessibles si on devine leur URL."
                },
                ["path-traversal"] = new AttackInfo
                {
                    Description = "Accès à des fichiers arbitraires via path traversal.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Path_Traversal",
                    RiskLevel = "High",
                    PayloadExample = "GET /BrokenAccessControl/DownloadFile?path=../../../../etc/passwd",
                    ErrorExplanation = "Les chemins de fichiers ne sont pas validés."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<AccessControlResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<AccessControlResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<AccessControlResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<AccessControlResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new AccessControlResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints réels ci-dessous pour tester les vulnérabilités."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // Vulnérable : IDOR - Pas de vérification de propriété
        [HttpGet]
        public IActionResult GetProfile(int userId)
        {
            // VULNÉRABLE : Aucune vérification que l'utilisateur peut accéder à ce profil
            if (_users.ContainsKey(userId))
            {
                var user = _users[userId];
                return Json(new
                {
                    success = true,
                    user = user, // Expose toutes les données sensibles
                    warning = "IDOR exploité - accès non autorisé!"
                });
            }

            return Json(new { success = false, error = "Utilisateur non trouvé" });
        }

        // Vulnérable : Pas d'attribut [Authorize]
        [HttpGet]
        public IActionResult AdminDashboard()
        {
            // VULNÉRABLE : Aucun contrôle d'authentification/autorisation
            return Json(new
            {
                success = true,
                message = "Panneau admin accessible sans authentification!",
                users = _users.Values.ToList(),
                documents = _documents.Values.Where(d => d.IsConfidential).ToList(),
                systemInfo = new
                {
                    version = "1.0.0",
                    database = "SQL Server 2022",
                    apiKeys = "sk_live_secret_key_123"
                }
            });
        }

        // Vulnérable : Mass assignment avec élévation de privilège
        [HttpPost]
        public IActionResult UpdateProfile([FromBody] UserProfile userUpdate)
        {
            // VULNÉRABLE : Binding de tous les champs incluant le rôle
            if (userUpdate != null && _users.ContainsKey(userUpdate.Id))
            {
                _users[userUpdate.Id] = userUpdate; // Mass assignment vulnérable

                return Json(new
                {
                    success = true,
                    message = "Profil mis à jour avec tous les champs!",
                    updatedUser = userUpdate,
                    warning = userUpdate.Role == "admin" ? "Élévation de privilège réussie!" : null
                });
            }

            return Json(new { success = false, error = "Mise à jour échouée" });
        }

        // Vulnérable : Suppression sans vérification de propriété
        [HttpPost]
        public IActionResult DeleteDocument(int documentId)
        {
            // VULNÉRABLE : Pas de vérification que l'utilisateur possède le document
            if (_documents.ContainsKey(documentId))
            {
                var doc = _documents[documentId];
                _documents.Remove(documentId);

                return Json(new
                {
                    success = true,
                    message = $"Document '{doc.Title}' supprimé!",
                    deletedDocument = doc,
                    warning = "Aucune vérification de propriété!"
                });
            }

            return Json(new { success = false, error = "Document non trouvé" });
        }

        // Vulnérable : Endpoint caché mais accessible
        [HttpGet]
        public IActionResult BackupData()
        {
            // VULNÉRABLE : Endpoint sensible sans protection
            return Json(new
            {
                success = true,
                message = "Données de backup exposées!",
                backup = new
                {
                    users = _users,
                    documents = _documents,
                    timestamp = DateTime.Now,
                    connectionString = "Server=prod;Database=App;User=sa;Password=P@ssw0rd123!"
                }
            });
        }

        // Vulnérable : Path traversal
        [HttpGet]
        public IActionResult DownloadFile(string path)
        {
            try
            {
                // VULNÉRABLE : Path traversal possible
                var fullPath = Path.Combine(Directory.GetCurrentDirectory(), path);

                if (System.IO.File.Exists(fullPath))
                {
                    var content = System.IO.File.ReadAllText(fullPath);
                    return Json(new
                    {
                        success = true,
                        path = path,
                        content = content.Substring(0, Math.Min(content.Length, 500)) + "...",
                        warning = "Path traversal exploité!"
                    });
                }

                return Json(new { success = false, error = "Fichier non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Modification de données d'autres utilisateurs
        [HttpPost]
        public IActionResult TransferFunds(int fromUserId, int toUserId, decimal amount)
        {
            // VULNÉRABLE : Aucune vérification que fromUserId est l'utilisateur actuel
            if (_users.ContainsKey(fromUserId) && _users.ContainsKey(toUserId))
            {
                // Simulation de transfert (sans vraie logique bancaire)
                return Json(new
                {
                    success = true,
                    message = $"Transfert de {amount}€ effectué!",
                    from = _users[fromUserId].Username,
                    to = _users[toUserId].Username,
                    warning = "Aucune vérification d'identité sur le compte source!"
                });
            }

            return Json(new { success = false, error = "Utilisateurs non trouvés" });
        }

        // Vulnérable : Export de données sans restriction
        [HttpGet]
        public IActionResult ExportAllUsers()
        {
            // VULNÉRABLE : Export complet sans vérification de rôle
            return Json(new
            {
                success = true,
                message = "Export complet des utilisateurs!",
                users = _users.Values.Select(u => new
                {
                    u.Id,
                    u.Username,
                    u.Email,
                    u.Role,
                    u.Salary,
                    u.SocialSecurityNumber,
                    u.CreditCardNumber
                }),
                warning = "Données sensibles exposées sans autorisation!"
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
                    "GET /BrokenAccessControl/GetProfile?userId=2",
                    "GET /BrokenAccessControl/AdminDashboard",
                    "POST /BrokenAccessControl/UpdateProfile",
                    "POST /BrokenAccessControl/DeleteDocument?documentId=1",
                    "GET /BrokenAccessControl/BackupData",
                    "GET /BrokenAccessControl/DownloadFile?path=../../appsettings.json",
                    "POST /BrokenAccessControl/TransferFunds",
                    "GET /BrokenAccessControl/ExportAllUsers"
                },
                vulnerabilities = new[]
                {
                    "IDOR (Insecure Direct Object Reference)",
                    "Missing [Authorize] attribute",
                    "Mass Assignment",
                    "Path Traversal",
                    "Forced Browsing",
                    "No ownership verification"
                }
            });
        }
    }

    // Modèles
    public class AccessControlResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class UserProfile
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public decimal Salary { get; set; }
        public string SocialSecurityNumber { get; set; } = string.Empty;
        public string CreditCardNumber { get; set; } = string.Empty;
    }

    public class Document
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public int OwnerId { get; set; }
        public string Content { get; set; } = string.Empty;
        public bool IsConfidential { get; set; }
    }
}