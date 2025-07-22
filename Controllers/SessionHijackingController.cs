using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace InsecureAppWebNet8.Controllers
{
    public class SessionHijackingController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        private static readonly Dictionary<string, SessionData> _sessions = new();
        private static readonly Dictionary<string, List<string>> _activeTokens = new();

        public SessionHijackingController(IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;

            _attackInfos = new()
            {
                ["predictable-id"] = new AttackInfo
                {
                    Description = "Session IDs prévisibles basés sur timestamp ou séquence simple.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Session_fixation",
                    RiskLevel = "Critical",
                    PayloadExample = "SessionID=12345, 12346, 12347...",
                    ErrorExplanation = "Les IDs de session doivent être aléatoires et imprévisibles."
                },
                ["session-fixation"] = new AttackInfo
                {
                    Description = "L'application accepte des session IDs fournis par l'utilisateur.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Session_fixation",
                    RiskLevel = "High",
                    PayloadExample = "?sessionId=attacker-controlled-value",
                    ErrorExplanation = "Régénérer l'ID de session après authentification."
                },
                ["exposed-tokens"] = new AttackInfo
                {
                    Description = "Tokens de session exposés dans les URLs, logs ou réponses.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    RiskLevel = "High",
                    PayloadExample = "/profile?token=abc123def456",
                    ErrorExplanation = "Les tokens ne doivent jamais apparaître dans les URLs."
                },
                ["no-httponly"] = new AttackInfo
                {
                    Description = "Cookies de session sans flag HttpOnly, accessibles via JavaScript.",
                    LearnMoreUrl = "https://owasp.org/www-community/HttpOnly",
                    RiskLevel = "High",
                    PayloadExample = "document.cookie accessible via XSS",
                    ErrorExplanation = "HttpOnly empêche l'accès JavaScript aux cookies."
                },
                ["no-secure-flag"] = new AttackInfo
                {
                    Description = "Cookies transmis en HTTP non chiffré sans flag Secure.",
                    LearnMoreUrl = "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    RiskLevel = "Medium",
                    PayloadExample = "Cookie transmis en clair sur HTTP",
                    ErrorExplanation = "Le flag Secure force HTTPS pour les cookies."
                },
                ["weak-tokens"] = new AttackInfo
                {
                    Description = "Tokens faibles utilisant MD5 ou algorithmes cassés.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                    RiskLevel = "High",
                    PayloadExample = "MD5(username+timestamp)",
                    ErrorExplanation = "Utiliser des générateurs cryptographiquement sûrs."
                },
                ["no-timeout"] = new AttackInfo
                {
                    Description = "Sessions sans expiration ou timeout trop long.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration",
                    RiskLevel = "Medium",
                    PayloadExample = "Sessions actives indéfiniment",
                    ErrorExplanation = "Les sessions doivent expirer après inactivité."
                },
                ["jwt-none-alg"] = new AttackInfo
                {
                    Description = "JWT acceptant l'algorithme 'none' permettant de forger des tokens.",
                    LearnMoreUrl = "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                    RiskLevel = "Critical",
                    PayloadExample = "{\"alg\":\"none\",\"typ\":\"JWT\"}",
                    ErrorExplanation = "Ne jamais accepter l'algorithme 'none' pour JWT."
                },
                ["session-replay"] = new AttackInfo
                {
                    Description = "Tokens réutilisables après déconnexion (pas de blacklist).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Session_replay_attack",
                    RiskLevel = "Medium",
                    PayloadExample = "Token valide même après logout",
                    ErrorExplanation = "Invalider les tokens côté serveur lors du logout."
                },
                ["concurrent-sessions"] = new AttackInfo
                {
                    Description = "Sessions multiples simultanées non contrôlées.",
                    LearnMoreUrl = "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
                    RiskLevel = "Medium",
                    PayloadExample = "Même utilisateur, sessions multiples actives",
                    ErrorExplanation = "Limiter le nombre de sessions concurrentes."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<SessionHijackingResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<SessionHijackingResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<SessionHijackingResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<SessionHijackingResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new SessionHijackingResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les vulnérabilités de session."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : IDs de session prévisibles
        [HttpPost]
        public IActionResult CreatePredictableSession(string username)
        {
            if (string.IsNullOrEmpty(username))
                return Json(new { success = false, error = "Username requis" });

            // VULNÉRABLE : ID basé sur timestamp (prévisible)
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sessionId = timestamp.ToString();

            // VULNÉRABLE : Pattern séquentiel simple
            var sequentialId = (_sessions.Count + 1000).ToString();

            // VULNÉRABLE : Hash faible et prévisible
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(username + timestamp));
                var weakToken = BitConverter.ToString(hash).Replace("-", "").ToLower();

                var sessionData = new SessionData
                {
                    SessionId = sessionId,
                    Username = username,
                    Token = weakToken,
                    CreatedAt = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };

                _sessions[sessionId] = sessionData;

                // VULNÉRABLE : Cookie sans HttpOnly ni Secure
                Response.Cookies.Append("SessionId", sessionId, new CookieOptions
                {
                    HttpOnly = false,  // VULNÉRABLE
                    Secure = false,    // VULNÉRABLE
                    SameSite = SameSiteMode.None  // VULNÉRABLE
                });

                return Json(new
                {
                    success = true,
                    sessionId = sessionId,
                    sequentialId = sequentialId,
                    weakToken = weakToken,
                    timestamp = timestamp,
                    warning = "Session ID prévisible créé!",
                    nextIds = new[]
                    {
                        (timestamp + 1).ToString(),
                        (timestamp + 2).ToString(),
                        (timestamp + 3).ToString()
                    }
                });
            }
        }

        // VULNÉRABLE : Session fixation
        [HttpPost]
        public IActionResult AcceptFixedSession(string sessionId, string username)
        {
            if (string.IsNullOrEmpty(sessionId))
                return Json(new { success = false, error = "SessionId requis" });

            // VULNÉRABLE : Accepte l'ID fourni par l'utilisateur
            var sessionData = new SessionData
            {
                SessionId = sessionId,
                Username = username ?? "guest",
                Token = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow
            };

            _sessions[sessionId] = sessionData;

            // VULNÉRABLE : Utilise l'ID fourni sans régénération
            Response.Cookies.Append("FixedSessionId", sessionId);

            return Json(new
            {
                success = true,
                acceptedSessionId = sessionId,
                username = sessionData.Username,
                warning = "Session fixation réussie - ID contrôlé par l'attaquant!",
                exploit = $"Victime utilise: /login?sessionId={sessionId}"
            });
        }

        // VULNÉRABLE : Tokens exposés dans l'URL
        [HttpGet]
        public IActionResult ProfileWithToken(string token)
        {
            // VULNÉRABLE : Token dans l'URL (apparaît dans les logs, historique, referer)
            if (string.IsNullOrEmpty(token))
            {
                return Json(new { success = false, error = "Token requis dans l'URL" });
            }

            var session = _sessions.Values.FirstOrDefault(s => s.Token == token);
            if (session != null)
            {
                // VULNÉRABLE : Retourne des infos sensibles
                return Json(new
                {
                    success = true,
                    profile = new
                    {
                        username = session.Username,
                        sessionId = session.SessionId,
                        createdAt = session.CreatedAt,
                        token = token
                    },
                    warning = "Token exposé dans l'URL - Visible dans logs/historique!",
                    risks = new[]
                    {
                        "Apparaît dans l'historique du navigateur",
                        "Loggé côté serveur",
                        "Transmis dans le header Referer",
                        "Partageable accidentellement"
                    }
                });
            }

            return Json(new { success = false, error = "Token invalide" });
        }

        // VULNÉRABLE : Cookies sans HttpOnly
        [HttpPost]
        public IActionResult SetVulnerableCookie(string name, string value)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value))
                return Json(new { success = false, error = "Name et value requis" });

            // VULNÉRABLE : Multiples problèmes de sécurité
            Response.Cookies.Append(name, value, new CookieOptions
            {
                HttpOnly = false,     // VULNÉRABLE : Accessible via JS
                Secure = false,       // VULNÉRABLE : Transmis en HTTP
                SameSite = SameSiteMode.None,  // VULNÉRABLE : CSRF possible
                Expires = DateTimeOffset.UtcNow.AddYears(1)  // VULNÉRABLE : Expiration trop longue
            });

            // VULNÉRABLE : Stocke aussi dans localStorage (mauvaise pratique)
            var jsCode = $"localStorage.setItem('{name}', '{value}');";

            return Json(new
            {
                success = true,
                cookieName = name,
                cookieValue = value,
                vulnerabilities = new[]
                {
                    "Cookie accessible via document.cookie",
                    "Transmis en clair sur HTTP",
                    "Pas de protection CSRF",
                    "Expire dans 1 an",
                    "Stocké aussi dans localStorage"
                },
                jsAccess = $"document.cookie = '{name}={value}'",
                xssPayload = "<script>alert(document.cookie)</script>",
                warning = "Cookie totalement vulnérable!"
            });
        }

        // VULNÉRABLE : Tokens faibles
        [HttpPost]
        public IActionResult GenerateWeakToken(string seed)
        {
            if (string.IsNullOrEmpty(seed))
                seed = "default";

            var tokens = new Dictionary<string, string>();

            // VULNÉRABLE : MD5 (cassé)
            using (var md5 = MD5.Create())
            {
                var md5Hash = md5.ComputeHash(Encoding.UTF8.GetBytes(seed + DateTime.Now.Ticks));
                tokens["md5"] = BitConverter.ToString(md5Hash).Replace("-", "");
            }

            // VULNÉRABLE : SHA1 (faible)
            using (var sha1 = SHA1.Create())
            {
                var sha1Hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(seed));
                tokens["sha1"] = BitConverter.ToString(sha1Hash).Replace("-", "");
            }

            // VULNÉRABLE : Base64 simple (pas de crypto)
            tokens["base64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(seed + ":session"));

            // VULNÉRABLE : Timestamp seul
            tokens["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

            // VULNÉRABLE : Incrémental
            tokens["incremental"] = (_sessions.Count + 1).ToString("D6");

            return Json(new
            {
                success = true,
                seed = seed,
                weakTokens = tokens,
                warning = "Tokens faibles générés - Facilement cassables!",
                crackTime = new Dictionary<string, string>
                {
                    ["md5"] = "Quelques secondes",
                    ["sha1"] = "Minutes avec GPU",
                    ["base64"] = "Instantané (pas de crypto)",
                    ["timestamp"] = "Prévisible",
                    ["incremental"] = "Trivial à deviner"
                }
            });
        }

        // VULNÉRABLE : Pas de timeout
        [HttpPost]
        public IActionResult CreateEternalSession(string username)
        {
            if (string.IsNullOrEmpty(username))
                return Json(new { success = false, error = "Username requis" });

            var sessionId = Guid.NewGuid().ToString();
            var session = new SessionData
            {
                SessionId = sessionId,
                Username = username,
                Token = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                // VULNÉRABLE : Pas d'expiration
                ExpiresAt = null
            };

            _sessions[sessionId] = session;

            // VULNÉRABLE : Cookie sans expiration
            Response.Cookies.Append("EternalSession", sessionId, new CookieOptions
            {
                // Pas d'Expires = cookie de session mais...
                MaxAge = TimeSpan.FromDays(365 * 10)  // VULNÉRABLE : 10 ans!
            });

            return Json(new
            {
                success = true,
                sessionId = sessionId,
                createdAt = session.CreatedAt,
                expiresAt = "JAMAIS",
                maxAge = "10 ans",
                warning = "Session éternelle créée - Aucune expiration!",
                risks = new[]
                {
                    "Session valide indéfiniment",
                    "Pas de timeout d'inactivité",
                    "Augmente la fenêtre d'attaque",
                    "Violation RGPD potentielle"
                }
            });
        }

        // VULNÉRABLE : JWT avec algorithme 'none'
        [HttpPost]
        public IActionResult CreateJWTNone(string username)
        {
            if (string.IsNullOrEmpty(username))
                return Json(new { success = false, error = "Username requis" });

            // VULNÉRABLE : Accepte l'algorithme 'none'
            var header = new
            {
                alg = "none",  // VULNÉRABLE !
                typ = "JWT"
            };

            var payload = new
            {
                sub = username,
                iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                admin = true  // VULNÉRABLE : Privilège élevé
            };

            var headerJson = JsonSerializer.Serialize(header);
            var payloadJson = JsonSerializer.Serialize(payload);

            var headerBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson));
            var payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));

            // VULNÉRABLE : Pas de signature avec 'none'
            var jwt = $"{headerBase64}.{payloadBase64}.";

            return Json(new
            {
                success = true,
                jwt = jwt,
                decoded = new { header, payload },
                warning = "JWT sans signature accepté - Token forgeable!",
                exploit = "Changer 'admin':true et retirer la signature",
                forgedExample = $"{headerBase64}.{Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"sub\":\"hacker\",\"admin\":true}"))}.".ToString()
            });
        }

        // VULNÉRABLE : Session replay
        [HttpPost]
        public IActionResult Logout(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                return Json(new { success = false, error = "SessionId requis" });

            if (_sessions.ContainsKey(sessionId))
            {
                var session = _sessions[sessionId];

                // VULNÉRABLE : Ne supprime pas vraiment la session
                // _sessions.Remove(sessionId);  // COMMENTÉ !

                // VULNÉRABLE : Le token reste valide
                return Json(new
                {
                    success = true,
                    message = "Déconnexion (mais session toujours active!)",
                    sessionStillValid = _sessions.ContainsKey(sessionId),
                    warning = "Session replay possible - Token non invalidé!",
                    exploit = $"Token {session.Token} toujours utilisable"
                });
            }

            return Json(new { success = false, error = "Session non trouvée" });
        }

        // VULNÉRABLE : Sessions concurrentes illimitées
        [HttpPost]
        public IActionResult CreateConcurrentSession(string username)
        {
            if (string.IsNullOrEmpty(username))
                return Json(new { success = false, error = "Username requis" });

            // VULNÉRABLE : Pas de limite sur le nombre de sessions
            var sessionId = Guid.NewGuid().ToString();
            var token = Guid.NewGuid().ToString();

            if (!_activeTokens.ContainsKey(username))
                _activeTokens[username] = new List<string>();

            _activeTokens[username].Add(token);

            var session = new SessionData
            {
                SessionId = sessionId,
                Username = username,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow
            };

            _sessions[sessionId] = session;

            return Json(new
            {
                success = true,
                sessionId = sessionId,
                token = token,
                activeSessions = _activeTokens[username].Count,
                allTokens = _activeTokens[username],
                warning = $"{_activeTokens[username].Count} sessions actives simultanément!",
                risks = new[]
                {
                    "Pas de limite de sessions",
                    "Difficile de détecter les compromissions",
                    "Augmente la surface d'attaque",
                    "Pas de 'kick out' des anciennes sessions"
                }
            });
        }

        // VULNÉRABLE : Session info leak
        [HttpGet]
        public IActionResult GetAllSessions()
        {
            // VULNÉRABLE : Expose toutes les sessions actives
            return Json(new
            {
                success = true,
                totalSessions = _sessions.Count,
                sessions = _sessions.Select(s => new
                {
                    sessionId = s.Key,
                    username = s.Value.Username,
                    token = s.Value.Token,  // VULNÉRABLE : Expose les tokens!
                    createdAt = s.Value.CreatedAt,
                    lastActivity = s.Value.LastActivity
                }),
                warning = "Toutes les sessions exposées - Information disclosure!",
                exploit = "Un attaquant peut voler n'importe quelle session active"
            });
        }

        // VULNÉRABLE : Validation de session faible
        [HttpPost]
        public IActionResult ValidateSession(string sessionId)
        {
            // VULNÉRABLE : Validation trop permissive
            if (string.IsNullOrEmpty(sessionId))
            {
                // VULNÉRABLE : Crée une session si elle n'existe pas
                sessionId = "guest-" + Guid.NewGuid().ToString();
                _sessions[sessionId] = new SessionData
                {
                    SessionId = sessionId,
                    Username = "anonymous",
                    Token = "public",
                    CreatedAt = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };
            }

            var session = _sessions.GetValueOrDefault(sessionId);
            if (session != null)
            {
                // VULNÉRABLE : Pas de vérification d'expiration
                session.LastActivity = DateTime.UtcNow;

                return Json(new
                {
                    success = true,
                    valid = true,
                    sessionId = sessionId,
                    username = session.Username,
                    warning = "Validation trop permissive - Sessions zombies possibles!"
                });
            }

            return Json(new { success = false, valid = false });
        }

        // VULNÉRABLE : Cross-site session transfer
        [HttpPost]
        public IActionResult TransferSession(string sessionId, string targetDomain)
        {
            if (!_sessions.ContainsKey(sessionId))
                return Json(new { success = false, error = "Session non trouvée" });

            var session = _sessions[sessionId];

            // VULNÉRABLE : Permet le transfert de session vers n'importe quel domaine
            var transferUrl = $"{targetDomain}?session={sessionId}&token={session.Token}";

            return Json(new
            {
                success = true,
                transferUrl = transferUrl,
                sessionData = new
                {
                    sessionId = session.SessionId,
                    token = session.Token,
                    username = session.Username
                },
                warning = "Session transférée vers un domaine externe!",
                risks = new[]
                {
                    "Session hijacking cross-domain",
                    "Token exposé dans l'URL",
                    "Pas de validation du domaine cible"
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
                    "POST /SessionHijacking/CreatePredictableSession - IDs prévisibles",
                    "POST /SessionHijacking/AcceptFixedSession - Session fixation",
                    "GET /SessionHijacking/ProfileWithToken?token=XXX - Token dans URL",
                    "POST /SessionHijacking/SetVulnerableCookie - Cookie sans protection",
                    "POST /SessionHijacking/GenerateWeakToken - Tokens faibles",
                    "POST /SessionHijacking/CreateEternalSession - Sans expiration",
                    "POST /SessionHijacking/CreateJWTNone - JWT algorithme 'none'",
                    "POST /SessionHijacking/Logout - Session replay",
                    "POST /SessionHijacking/CreateConcurrentSession - Sessions multiples",
                    "GET /SessionHijacking/GetAllSessions - Info disclosure",
                    "POST /SessionHijacking/ValidateSession - Validation faible",
                    "POST /SessionHijacking/TransferSession - Cross-domain transfer"
                },
                vulnerabilities = new[]
                {
                    "Predictable session IDs",
                    "Session fixation",
                    "Token exposure in URLs",
                    "Missing HttpOnly/Secure flags",
                    "Weak token generation",
                    "No session timeout",
                    "JWT 'none' algorithm",
                    "Session replay attacks",
                    "Unlimited concurrent sessions",
                    "Session information disclosure",
                    "Weak session validation",
                    "Cross-domain session transfer"
                },
                activeSessions = _sessions.Count
            });
        }
    }

    // Modèles
    public class SessionHijackingResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SessionData
    {
        public string SessionId { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }
}