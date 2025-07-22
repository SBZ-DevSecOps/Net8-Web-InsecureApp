using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Antiforgery;

namespace InsecureAppWebNet8.Controllers
{
    public class CSRFController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IAntiforgery _antiforgery;

        // Simulation de données utilisateur
        private static readonly Dictionary<int, BankAccount> _accounts = new()
        {
            [1] = new BankAccount
            {
                Id = 1,
                Username = "alice",
                Balance = 5000m,
                Email = "alice@example.com"
            },
            [2] = new BankAccount
            {
                Id = 2,
                Username = "bob",
                Balance = 3000m,
                Email = "bob@example.com"
            }
        };

        private static readonly List<Transaction> _transactions = new();
        private static CSRFUserProfile _currentUserProfile = new()
        {
            Username = "alice",
            Email = "alice@example.com",
            Phone = "555-0123",
            Address = "123 Main St"
        };

        public CSRFController(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;

            _attackInfos = new()
            {
                ["no-token"] = new AttackInfo
                {
                    Description = "Formulaires sans token CSRF permettant des actions non autorisées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/csrf",
                    RiskLevel = "High",
                    PayloadExample = "POST /CSRF/TransferMoney sans token",
                    ErrorExplanation = "L'absence de token CSRF permet de forger des requêtes."
                },
                ["get-state-change"] = new AttackInfo
                {
                    Description = "Opérations sensibles via GET permettant CSRF par simple lien.",
                    LearnMoreUrl = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /CSRF/DeleteAccount?id=1",
                    ErrorExplanation = "Les requêtes GET ne devraient jamais modifier l'état."
                },
                ["cors-wildcard"] = new AttackInfo
                {
                    Description = "CORS mal configuré permettant les requêtes cross-origin.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cors",
                    RiskLevel = "High",
                    PayloadExample = "POST avec Origin: http://evil.com",
                    ErrorExplanation = "CORS avec * permet les attaques depuis n'importe quel domaine."
                },
                ["no-samesite"] = new AttackInfo
                {
                    Description = "Cookies sans attribut SameSite vulnérables au CSRF.",
                    LearnMoreUrl = "https://web.dev/samesite-cookies-explained/",
                    RiskLevel = "Medium",
                    PayloadExample = "Cookie de session sans SameSite=Strict",
                    ErrorExplanation = "Les cookies sont envoyés même depuis des sites tiers."
                },
                ["json-csrf"] = new AttackInfo
                {
                    Description = "Endpoints JSON sans vérification Content-Type appropriée.",
                    LearnMoreUrl = "https://www.acunetix.com/blog/web-security-zone/json-csrf-csrf-attacks-via-json/",
                    RiskLevel = "High",
                    PayloadExample = "POST /CSRF/UpdateProfileJson avec form-data",
                    ErrorExplanation = "Les endpoints JSON peuvent être ciblés via formulaires."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<CSRFResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<CSRFResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<CSRFResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<CSRFResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new CSRFResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints réels ci-dessous pour tester les vulnérabilités CSRF."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : POST sans ValidateAntiForgeryToken
        [HttpPost]
        [IgnoreAntiforgeryToken] // VULNÉRABLE : Désactive explicitement la protection CSRF
        public IActionResult TransferMoney(string toAccount, decimal amount)
        {
            // VULNÉRABLE : Pas de vérification CSRF token
            if (string.IsNullOrEmpty(toAccount) || amount <= 0)
            {
                return Json(new { success = false, error = "Paramètres invalides" });
            }

            var transaction = new Transaction
            {
                Id = _transactions.Count + 1,
                From = "alice",
                To = toAccount,
                Amount = amount,
                Date = DateTime.Now
            };

            _transactions.Add(transaction);

            // Simuler le débit
            if (_accounts.ContainsKey(1))
            {
                _accounts[1].Balance -= amount;
            }

            return Json(new
            {
                success = true,
                message = $"Transfert de {amount}€ effectué vers {toAccount}!",
                newBalance = _accounts[1].Balance,
                warning = "CSRF exploité - Aucun token vérifié!",
                transactionId = transaction.Id
            });
        }

        // VULNÉRABLE : GET pour modifier l'état
        [HttpGet]
        public IActionResult DeleteAccount(int id)
        {
            // VULNÉRABLE : Opération destructive via GET
            if (_accounts.ContainsKey(id))
            {
                var account = _accounts[id];
                _accounts.Remove(id);

                return Json(new
                {
                    success = true,
                    message = $"Compte {account.Username} supprimé!",
                    deletedAccount = account,
                    warning = "CSRF via GET - État modifié par simple lien!"
                });
            }

            return Json(new { success = false, error = "Compte non trouvé" });
        }

        // VULNÉRABLE : Changement d'email sans protection
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public IActionResult ChangeEmail(string newEmail)
        {
            // VULNÉRABLE : Pas de token CSRF
            var oldEmail = _currentUserProfile.Email;
            _currentUserProfile.Email = newEmail;

            return Json(new
            {
                success = true,
                message = "Email modifié avec succès!",
                oldEmail = oldEmail,
                newEmail = newEmail,
                warning = "CSRF exploité - Email changé sans autorisation!"
            });
        }

        // VULNÉRABLE : Endpoint JSON sans vérification Content-Type stricte
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public IActionResult UpdateProfileJson([FromBody] CSRFUserProfile profile)
        {
            // VULNÉRABLE : Accepte JSON mais ne vérifie pas strictement Content-Type
            if (profile != null)
            {
                _currentUserProfile = profile;

                return Json(new
                {
                    success = true,
                    message = "Profil mis à jour!",
                    updatedProfile = profile,
                    warning = "JSON CSRF - Profil modifié via formulaire!"
                });
            }

            return Json(new { success = false, error = "Données invalides" });
        }

        // VULNÉRABLE : API avec CORS mal configuré
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public IActionResult ApiTransfer(string recipient, decimal amount)
        {
            // VULNÉRABLE : CORS permet toutes les origines
            Response.Headers.Append("Access-Control-Allow-Origin", "*");
            Response.Headers.Append("Access-Control-Allow-Credentials", "true");

            var transaction = new Transaction
            {
                Id = _transactions.Count + 1,
                From = "current_user",
                To = recipient,
                Amount = amount,
                Date = DateTime.Now
            };

            _transactions.Add(transaction);

            return Json(new
            {
                success = true,
                transaction = transaction,
                warning = "CORS wildcard + credentials = CSRF possible!"
            });
        }

        // VULNÉRABLE : Souscription via GET
        [HttpGet]
        public IActionResult Subscribe(string plan, decimal monthlyFee)
        {
            // VULNÉRABLE : Souscription financière via GET
            return Json(new
            {
                success = true,
                message = $"Souscrit au plan {plan} pour {monthlyFee}€/mois",
                warning = "État modifié via GET - CSRF par image/link!",
                subscriptionId = Guid.NewGuid()
            });
        }

        // VULNÉRABLE : Formulaire avec token mais mal implémenté
        [HttpPost]
        public IActionResult TransferWithWeakToken(string token, string toAccount, decimal amount)
        {
            // VULNÉRABLE : Token prévisible/statique
            if (token != "csrf_token_123") // Token codé en dur!
            {
                return Json(new { success = false, error = "Token invalide" });
            }

            return Json(new
            {
                success = true,
                message = $"Transfert de {amount}€ effectué!",
                warning = "Token CSRF prévisible/statique!"
            });
        }

        // Page de démonstration d'attaque CSRF
        [HttpGet]
        public IActionResult AttackDemo()
        {
            return View();
        }

        // Endpoint pour vérifier l'état actuel
        [HttpGet]
        public IActionResult CheckStatus()
        {
            return Json(new
            {
                accounts = _accounts.Values,
                transactions = _transactions.OrderByDescending(t => t.Date).Take(5),
                currentProfile = _currentUserProfile,
                cookieInfo = new
                {
                    sessionCookie = Request.Cookies[".AspNetCore.Session"] != null,
                    sameSite = "None (vulnérable!)"
                }
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
                    "POST /CSRF/TransferMoney - Sans token CSRF",
                    "GET /CSRF/DeleteAccount?id=1 - État modifié via GET",
                    "POST /CSRF/ChangeEmail - Changement d'email sans protection",
                    "POST /CSRF/UpdateProfileJson - JSON CSRF",
                    "POST /CSRF/ApiTransfer - CORS mal configuré",
                    "GET /CSRF/Subscribe?plan=premium&monthlyFee=99 - Souscription via GET",
                    "POST /CSRF/TransferWithWeakToken - Token prévisible",
                    "GET /CSRF/AttackDemo - Page de démonstration d'attaque"
                },
                vulnerabilities = new[]
                {
                    "Missing [ValidateAntiForgeryToken]",
                    "State-changing GET requests",
                    "CORS misconfiguration with credentials",
                    "No SameSite cookie attribute",
                    "Predictable CSRF tokens",
                    "JSON endpoints without Content-Type validation"
                }
            });
        }
    }

    // Modèles
    public class CSRFResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class BankAccount
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public decimal Balance { get; set; }
        public string Email { get; set; } = string.Empty;
    }

    public class Transaction
    {
        public int Id { get; set; }
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public DateTime Date { get; set; }
    }

    public class CSRFUserProfile
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
    }
}