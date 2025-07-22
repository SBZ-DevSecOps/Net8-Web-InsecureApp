using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace InsecureAppWebNet8.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // VULNÉRABLE : Stockage en mémoire des utilisateurs (pour la démo)
        private static readonly Dictionary<string, UserAccount> _users = new()
        {
            ["admin"] = new UserAccount { Username = "admin", Password = "admin123", Email = "admin@test.com", IsAdmin = true },
            ["user1"] = new UserAccount { Username = "user1", Password = "password", Email = "user1@test.com", IsAdmin = false },
            ["test"] = new UserAccount { Username = "test", Password = "123456", Email = "test@test.com", IsAdmin = false }
        };

        // VULNÉRABLE : Stockage des sessions en mémoire sans expiration
        private static readonly Dictionary<string, SessionInfo> _sessions = new();

        // VULNÉRABLE : Codes de réinitialisation sans expiration
        private static readonly Dictionary<string, PasswordResetToken> _resetTokens = new();

        public AuthenticationController()
        {
            _attackInfos = new()
            {
                ["weak-credentials"] = new AttackInfo
                {
                    Description = "Accepte des mots de passe faibles et des credentials par défaut.",
                    LearnMoreUrl = "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                    RiskLevel = "Critical",
                    PayloadExample = "admin/admin123, user1/password, test/123456",
                    ErrorExplanation = "Aucune politique de mot de passe fort n'est appliquée."
                },
                ["user-enumeration"] = new AttackInfo
                {
                    Description = "Messages d'erreur différents permettant l'énumération d'utilisateurs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Username_Enumeration",
                    RiskLevel = "High",
                    PayloadExample = "Testez 'admin' vs 'userquinexistepas'",
                    ErrorExplanation = "Messages différents révèlent si un utilisateur existe."
                },
                ["timing-attack"] = new AttackInfo
                {
                    Description = "Temps de réponse différents selon l'existence de l'utilisateur.",
                    LearnMoreUrl = "https://cwe.mitre.org/data/definitions/208.html",
                    RiskLevel = "Medium",
                    PayloadExample = "Mesurez le temps: admin vs inexistant",
                    ErrorExplanation = "Le timing révèle des informations sur l'existence des comptes."
                },
                ["weak-session"] = new AttackInfo
                {
                    Description = "Sessions prévisibles et sans expiration appropriée.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Session_fixation",
                    RiskLevel = "High",
                    PayloadExample = "SessionID séquentiel: 1, 2, 3...",
                    ErrorExplanation = "Les identifiants de session sont prévisibles."
                },
                ["insecure-storage"] = new AttackInfo
                {
                    Description = "Stockage des mots de passe en clair ou avec hash faible.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                    RiskLevel = "Critical",
                    PayloadExample = "Mots de passe stockés: MD5 ou plaintext",
                    ErrorExplanation = "Les mots de passe ne sont pas correctement hashés."
                },
                ["no-account-lockout"] = new AttackInfo
                {
                    Description = "Pas de verrouillage après tentatives échouées permettant brute force.",
                    LearnMoreUrl = "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    RiskLevel = "High",
                    PayloadExample = "Essais illimités sur /Authentication/Login",
                    ErrorExplanation = "Aucune protection contre le brute force."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<AuthenticationResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<AuthenticationResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<AuthenticationResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<AuthenticationResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new AuthenticationResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les formulaires ci-dessous pour tester les vulnérabilités d'authentification."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Authentification avec credentials faibles
        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var startTime = DateTime.UtcNow;

            try
            {
                // VULNÉRABLE : Pas de validation de la force du mot de passe
                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    return Json(new
                    {
                        success = false,
                        error = "Nom d'utilisateur et mot de passe requis",
                        timing = "immediate"
                    });
                }

                // VULNÉRABLE : User enumeration - message différent si l'utilisateur n'existe pas
                if (!_users.ContainsKey(username))
                {
                    // VULNÉRABLE : Timing attack - retour immédiat
                    return Json(new
                    {
                        success = false,
                        error = "Utilisateur non trouvé", // VULNÉRABLE : Révèle l'existence
                        timing = (DateTime.UtcNow - startTime).TotalMilliseconds
                    });
                }

                var user = _users[username];

                // VULNÉRABLE : Comparaison simple du mot de passe
                if (user.Password != password)
                {
                    // VULNÉRABLE : Timing différent après vérification utilisateur
                    await Task.Delay(100); // Simule hash verification
                    return Json(new
                    {
                        success = false,
                        error = "Mot de passe incorrect", // VULNÉRABLE : Message différent
                        timing = (DateTime.UtcNow - startTime).TotalMilliseconds,
                        hint = "Le timing révèle que l'utilisateur existe!"
                    });
                }

                // VULNÉRABLE : Session ID prévisible
                var sessionId = (_sessions.Count + 1).ToString();
                var sessionInfo = new SessionInfo
                {
                    SessionId = sessionId,
                    Username = username,
                    CreatedAt = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow,
                    IsAdmin = user.IsAdmin
                };
                _sessions[sessionId] = sessionInfo;

                // VULNÉRABLE : Cookie de session sans flags de sécurité
                Response.Cookies.Append("SessionId", sessionId);
                Response.Cookies.Append("Username", username); // VULNÉRABLE : Info sensible en cookie

                return Json(new
                {
                    success = true,
                    message = "Connexion réussie!",
                    username = username,
                    sessionId = sessionId,
                    isAdmin = user.IsAdmin,
                    warning = "Session ID prévisible, pas de HttpOnly/Secure!",
                    vulnerabilities = new[]
                    {
                        "Mot de passe faible accepté",
                        "Session ID séquentiel: " + sessionId,
                        "Pas de protection CSRF",
                        "Cookies sans HttpOnly/Secure"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Stockage des mots de passe
        [HttpPost]
        public IActionResult Register(string username, string password, string email)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return Json(new { success = false, error = "Données manquantes" });
            }

            // VULNÉRABLE : Révèle si l'utilisateur existe déjà
            if (_users.ContainsKey(username))
            {
                return Json(new
                {
                    success = false,
                    error = "Cet utilisateur existe déjà!", // VULNÉRABLE : User enumeration
                    hint = "Cela confirme l'existence du compte"
                });
            }

            // VULNÉRABLE : Aucune validation de la force du mot de passe
            if (password.Length < 3)
            {
                return Json(new
                {
                    success = false,
                    error = "Mot de passe trop court (min 3 caractères)",
                    warning = "Politique de mot de passe très faible!"
                });
            }

            // VULNÉRABLE : Stockage avec hash MD5 (obsolète)
            var md5Hash = GetMD5Hash(password);

            var newUser = new UserAccount
            {
                Username = username,
                Password = password, // VULNÉRABLE : Stockage en clair aussi!
                PasswordHash = md5Hash,
                Email = email,
                IsAdmin = false
            };

            _users[username] = newUser;

            return Json(new
            {
                success = true,
                message = "Compte créé avec succès!",
                username = username,
                vulnerabilities = new[]
                {
                    "Mot de passe stocké en clair",
                    "Hash MD5 utilisé (cassable)",
                    "Pas de validation email",
                    "Politique mot de passe faible"
                },
                storedData = new
                {
                    plainPassword = password, // VULNÉRABLE : Ne jamais exposer!
                    md5Hash = md5Hash,
                    warning = "Mot de passe visible en base!"
                }
            });
        }

        // VULNÉRABLE : Reset password sans validation
        [HttpPost]
        public IActionResult ForgotPassword(string email)
        {
            // VULNÉRABLE : Confirme l'existence de l'email
            var user = _users.Values.FirstOrDefault(u => u.Email == email);

            if (user == null)
            {
                return Json(new
                {
                    success = false,
                    error = "Aucun compte associé à cet email", // VULNÉRABLE : User enumeration
                    hint = "Cela révèle quels emails sont enregistrés"
                });
            }

            // VULNÉRABLE : Token prévisible
            var resetToken = DateTime.Now.Ticks.ToString();
            _resetTokens[resetToken] = new PasswordResetToken
            {
                Token = resetToken,
                Username = user.Username,
                CreatedAt = DateTime.UtcNow,
                // VULNÉRABLE : Pas d'expiration
                ExpiresAt = DateTime.UtcNow.AddYears(10)
            };

            return Json(new
            {
                success = true,
                message = "Token de réinitialisation créé",
                resetToken = resetToken, // VULNÉRABLE : Token exposé
                resetUrl = $"/Authentication/ResetPassword?token={resetToken}",
                vulnerabilities = new[]
                {
                    "Token prévisible (timestamp)",
                    "Token sans expiration réelle",
                    "Token envoyé dans la réponse",
                    "User enumeration possible"
                }
            });
        }

        // VULNÉRABLE : Reset sans validation du token
        [HttpPost]
        public IActionResult ResetPassword(string token, string newPassword)
        {
            // VULNÉRABLE : Pas de validation de l'ancien mot de passe
            if (!_resetTokens.ContainsKey(token))
            {
                // VULNÉRABLE : Permet de tester des tokens
                return Json(new
                {
                    success = false,
                    error = "Token invalide",
                    hint = "Essayez des timestamps récents!"
                });
            }

            var resetToken = _resetTokens[token];
            var user = _users[resetToken.Username];

            // VULNÉRABLE : Pas de validation de force
            user.Password = newPassword;
            user.PasswordHash = GetMD5Hash(newPassword);

            // VULNÉRABLE : Token réutilisable
            // _resetTokens.Remove(token); // NON FAIT!

            return Json(new
            {
                success = true,
                message = "Mot de passe réinitialisé!",
                username = user.Username,
                newPassword = newPassword, // VULNÉRABLE : Exposé!
                warning = "Token toujours valide pour réutilisation!",
                vulnerabilities = new[]
                {
                    "Token réutilisable",
                    "Pas de validation de l'identité",
                    "Nouveau mot de passe exposé",
                    "Pas de notification à l'utilisateur"
                }
            });
        }

        // VULNÉRABLE : Pas de rate limiting
        [HttpPost]
        public IActionResult BruteForceTest(string username, string[] passwords)
        {
            var attempts = new List<object>();
            var found = false;

            // VULNÉRABLE : Permet des essais illimités
            foreach (var password in passwords.Take(100)) // Limite à 100 pour la démo
            {
                var success = false;
                var message = "";

                if (_users.ContainsKey(username))
                {
                    success = _users[username].Password == password;
                    message = success ? "Mot de passe trouvé!" : "Incorrect";
                    if (success) found = true;
                }
                else
                {
                    message = "Utilisateur inconnu";
                }

                attempts.Add(new
                {
                    password = password,
                    success = success,
                    message = message
                });

                if (found) break;
            }

            return Json(new
            {
                success = true,
                totalAttempts = attempts.Count,
                passwordFound = found,
                attempts = attempts,
                warning = "Aucune protection contre le brute force!",
                vulnerabilities = new[]
                {
                    "Pas de rate limiting",
                    "Pas de compte lockout",
                    "Pas de CAPTCHA",
                    "Réponses immédiates"
                }
            });
        }

        // Endpoint pour vérifier les sessions actives
        [HttpGet]
        public IActionResult CheckSession(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
            {
                return Json(new { success = false, error = "Session ID requis" });
            }

            // VULNÉRABLE : Permet de vérifier n'importe quelle session
            if (!_sessions.ContainsKey(sessionId))
            {
                return Json(new
                {
                    success = false,
                    error = "Session invalide",
                    hint = "Essayez des IDs séquentiels: 1, 2, 3..."
                });
            }

            var session = _sessions[sessionId];

            // VULNÉRABLE : Expose toutes les infos de session
            return Json(new
            {
                success = true,
                session = session,
                allSessions = _sessions.Keys.ToList(), // VULNÉRABLE : Liste toutes les sessions!
                warning = "Hijacking de session possible!"
            });
        }

        // Helper methods
        private string GetMD5Hash(string input)
        {
            // VULNÉRABLE : MD5 est obsolète et cassable
            using (var md5 = MD5.Create())
            {
                var inputBytes = Encoding.ASCII.GetBytes(input);
                var hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToHexString(hashBytes);
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
                    "POST /Authentication/Login - Login avec enumeration",
                    "POST /Authentication/Register - Inscription sans validation",
                    "POST /Authentication/ForgotPassword - Reset sans sécurité",
                    "POST /Authentication/ResetPassword - Change password vulnérable",
                    "POST /Authentication/BruteForceTest - Test brute force",
                    "GET /Authentication/CheckSession - Vérifier sessions"
                },
                defaultCredentials = new[]
                {
                    "admin/admin123",
                    "user1/password",
                    "test/123456"
                },
                vulnerabilities = new[]
                {
                    "Weak password policy",
                    "User enumeration",
                    "Timing attacks",
                    "Predictable sessions",
                    "Plaintext/MD5 storage",
                    "No account lockout",
                    "No rate limiting"
                }
            });
        }
    }

    // Modèles
    public class AuthenticationResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class UserAccount
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool IsAdmin { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? LockedUntil { get; set; }
    }

    public class SessionInfo
    {
        public string SessionId { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public bool IsAdmin { get; set; }
    }

    public class PasswordResetToken
    {
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}