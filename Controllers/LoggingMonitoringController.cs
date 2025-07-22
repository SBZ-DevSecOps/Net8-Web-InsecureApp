using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Diagnostics;

namespace InsecureAppWebNet8.Controllers
{
    public class LoggingMonitoringController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _env;
        private readonly string _logPath;
        private static readonly List<SecurityEvent> _securityEvents = new();
        private static readonly Dictionary<string, int> _failedLogins = new();
        private static readonly Dictionary<string, DateTime> _lastAlerts = new();

        public LoggingMonitoringController(IWebHostEnvironment env)
        {
            _env = env;
            _logPath = Path.Combine(_env.WebRootPath, "logs");
            Directory.CreateDirectory(_logPath);

            _attackInfos = new()
            {
                ["no-logging"] = new AttackInfo
                {
                    Description = "Absence totale de logs pour les événements de sécurité critiques.",
                    LearnMoreUrl = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                    RiskLevel = "High",
                    PayloadExample = "Tentatives de connexion, accès non autorisés non loggés",
                    ErrorExplanation = "Les attaques passent inaperçues sans logs."
                },
                ["insufficient-logging"] = new AttackInfo
                {
                    Description = "Logs incomplets manquant d'informations critiques (IP, timestamp, user).",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                    RiskLevel = "High",
                    PayloadExample = "Login failed for user: admin",
                    ErrorExplanation = "Logs sans contexte empêchent l'investigation."
                },
                ["log-injection"] = new AttackInfo
                {
                    Description = "Injection de fausses entrées dans les logs pour masquer des attaques.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "username=admin%0A%0A[INFO] Login successful for admin",
                    ErrorExplanation = "Les logs peuvent être falsifiés."
                },
                ["sensitive-data-logging"] = new AttackInfo
                {
                    Description = "Logging de données sensibles (mots de passe, tokens, cartes crédit).",
                    LearnMoreUrl = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    RiskLevel = "High",
                    PayloadExample = "Password=P@ssw0rd123 logged in plaintext",
                    ErrorExplanation = "Les logs exposent des données sensibles."
                },
                ["no-alerting"] = new AttackInfo
                {
                    Description = "Absence d'alertes pour les événements de sécurité critiques.",
                    LearnMoreUrl = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92.pdf",
                    RiskLevel = "High",
                    PayloadExample = "1000 failed logins sans alerte",
                    ErrorExplanation = "Les attaques en cours ne sont pas détectées."
                },
                ["log-tampering"] = new AttackInfo
                {
                    Description = "Logs modifiables ou supprimables par des utilisateurs non autorisés.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "High",
                    PayloadExample = "DELETE /logs/security.log",
                    ErrorExplanation = "Les preuves peuvent être effacées."
                },
                ["unencrypted-logs"] = new AttackInfo
                {
                    Description = "Logs stockés ou transmis sans chiffrement.",
                    LearnMoreUrl = "https://owasp.org/www-project-logging-cheat-sheet/",
                    RiskLevel = "Medium",
                    PayloadExample = "Logs transmis en HTTP, stockés en clair",
                    ErrorExplanation = "Les logs peuvent être interceptés."
                },
                ["no-correlation"] = new AttackInfo
                {
                    Description = "Pas de corrélation entre événements pour détecter des patterns d'attaque.",
                    LearnMoreUrl = "https://www.sans.org/white-papers/33528/",
                    RiskLevel = "Medium",
                    PayloadExample = "Brute force non détecté sur plusieurs services",
                    ErrorExplanation = "Les attaques distribuées passent inaperçues."
                },
                ["delayed-detection"] = new AttackInfo
                {
                    Description = "Détection trop tardive des incidents de sécurité.",
                    LearnMoreUrl = "https://www.ibm.com/security/data-breach",
                    RiskLevel = "High",
                    PayloadExample = "Breach détecté après 200 jours",
                    ErrorExplanation = "Le temps de réponse est critique."
                },
                ["no-integrity"] = new AttackInfo
                {
                    Description = "Absence de protection d'intégrité des logs (hash, signature).",
                    LearnMoreUrl = "https://www.nist.gov/cyberframework",
                    RiskLevel = "Medium",
                    PayloadExample = "Logs modifiés sans détection",
                    ErrorExplanation = "L'intégrité des logs n'est pas garantie."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<LoggingMonitoringResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<LoggingMonitoringResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<LoggingMonitoringResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<LoggingMonitoringResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new LoggingMonitoringResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les défaillances de logging."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Tentative de login sans logging approprié
        [HttpPost]
        public IActionResult AttemptLogin(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                return Json(new { success = false, error = "Username requis" });

            // VULNÉRABLE : Pas de logging des tentatives échouées
            if (password != "admin123")
            {
                // VULNÉRABLE : Aucun log créé !
                return Json(new
                {
                    success = false,
                    error = "Invalid credentials",
                    warning = "Échec de connexion NON loggé!",
                    issues = new[]
                    {
                        "Pas de timestamp",
                        "Pas d'IP source",
                        "Pas de user agent",
                        "Pas de compteur d'échecs",
                        "Pas d'alerte après N tentatives"
                    }
                });
            }

            // VULNÉRABLE : Succès non loggé non plus
            return Json(new
            {
                success = true,
                username = username,
                warning = "Connexion réussie NON loggée!",
                token = "fake-token-123"
            });
        }

        // VULNÉRABLE : Logging avec données sensibles
        [HttpPost]
        public IActionResult LogSensitiveData(string username, string password, string creditCard)
        {
            try
            {
                // VULNÉRABLE : Logging du mot de passe en clair !
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Login attempt: username={username}, password={password}";

                // VULNÉRABLE : Logging du numéro de carte !
                if (!string.IsNullOrEmpty(creditCard))
                {
                    logEntry += $", creditCard={creditCard}";
                }

                // VULNÉRABLE : Écriture dans un fichier accessible
                var logFile = Path.Combine(_logPath, "sensitive.log");
                System.IO.File.AppendAllText(logFile, logEntry + Environment.NewLine);

                return Json(new
                {
                    success = true,
                    logFile = "/logs/sensitive.log",
                    warning = "Données sensibles loggées en clair!",
                    loggedData = new
                    {
                        password = password,
                        creditCard = creditCard,
                        inFile = logFile
                    },
                    risks = new[]
                    {
                        "Mots de passe en clair dans les logs",
                        "Numéros de carte bancaire exposés",
                        "Logs accessibles publiquement",
                        "Pas de rotation des logs",
                        "Violation PCI-DSS et RGPD"
                    }
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE : Stack trace complète loggée
                var errorLog = Path.Combine(_logPath, "errors.log");
                System.IO.File.AppendAllText(errorLog, ex.ToString() + Environment.NewLine);

                return Json(new { success = false, error = "Logged sensitive error details!" });
            }
        }

        // VULNÉRABLE : Log injection
        [HttpPost]
        public IActionResult InjectLog(string userInput)
        {
            if (string.IsNullOrEmpty(userInput))
                return Json(new { success = false, error = "Input requis" });

            try
            {
                // VULNÉRABLE : Pas de validation/échappement de l'input
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - User action: {userInput}";
                var logFile = Path.Combine(_logPath, "application.log");

                // VULNÉRABLE : Injection possible avec retours à la ligne
                System.IO.File.AppendAllText(logFile, logEntry + Environment.NewLine);

                // Démonstration de l'injection
                var injectedLines = userInput.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                return Json(new
                {
                    success = true,
                    originalInput = userInput,
                    logFile = "/logs/application.log",
                    injectedLines = injectedLines.Length,
                    warning = "Log injection réussie!",
                    exploit = @"admin\n[INFO] Attack successful\n[INFO] User admin granted admin rights",
                    risks = new[]
                    {
                        "Fausses entrées dans les logs",
                        "Masquage d'activités malveillantes",
                        "Confusion lors des investigations",
                        "Bypass des SIEM rules"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Pas d'alerte sur événements critiques
        [HttpPost]
        public IActionResult SimulateBruteForce(string username, int attempts = 100)
        {
            if (string.IsNullOrEmpty(username))
                username = "admin";

            // VULNÉRABLE : Aucune alerte déclenchée
            if (!_failedLogins.ContainsKey(username))
                _failedLogins[username] = 0;

            _failedLogins[username] += attempts;

            // VULNÉRABLE : Seuil d'alerte trop élevé ou inexistant
            var shouldAlert = _failedLogins[username] > 10000; // Seuil absurde !

            return Json(new
            {
                success = true,
                username = username,
                totalFailedAttempts = _failedLogins[username],
                alertTriggered = shouldAlert,
                warning = "Aucune alerte malgré le brute force!",
                issues = new[]
                {
                    $"{attempts} tentatives ajoutées",
                    $"Total: {_failedLogins[username]} échecs",
                    "Pas d'alerte email",
                    "Pas de blocage IP",
                    "Pas de notification SOC",
                    "Seuil d'alerte: 10000 (absurde!)"
                }
            });
        }

        // VULNÉRABLE : Logs modifiables/supprimables
        [HttpPost]
        public IActionResult TamperLogs(string action, string logName)
        {
            if (string.IsNullOrEmpty(action) || string.IsNullOrEmpty(logName))
                return Json(new { success = false, error = "Action et logName requis" });

            var logFile = Path.Combine(_logPath, logName);

            try
            {
                switch (action.ToLower())
                {
                    case "delete":
                        // VULNÉRABLE : Suppression de logs possible !
                        if (System.IO.File.Exists(logFile))
                        {
                            System.IO.File.Delete(logFile);
                            return Json(new
                            {
                                success = true,
                                action = "deleted",
                                file = logName,
                                warning = "Logs supprimés - Preuves effacées!",
                                impact = "Impossible de faire du forensics"
                            });
                        }
                        break;

                    case "modify":
                        // VULNÉRABLE : Modification de logs possible !
                        if (System.IO.File.Exists(logFile))
                        {
                            var content = System.IO.File.ReadAllText(logFile);
                            content = content.Replace("failed", "successful");
                            content = content.Replace("unauthorized", "authorized");
                            System.IO.File.WriteAllText(logFile, content);

                            return Json(new
                            {
                                success = true,
                                action = "modified",
                                file = logName,
                                warning = "Logs modifiés - Histoire réécrite!",
                                modifications = new[] { "failed → successful", "unauthorized → authorized" }
                            });
                        }
                        break;

                    case "truncate":
                        // VULNÉRABLE : Truncate des logs
                        System.IO.File.WriteAllText(logFile, string.Empty);
                        return Json(new
                        {
                            success = true,
                            action = "truncated",
                            file = logName,
                            warning = "Logs vidés!"
                        });
                }

                return Json(new { success = false, error = "Action non reconnue" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Logs transmis sans chiffrement
        [HttpGet]
        public IActionResult TransmitLogs(string destination)
        {
            if (string.IsNullOrEmpty(destination))
                destination = "http://log-server.com/collect";

            // VULNÉRABLE : Simulation d'envoi en HTTP
            var logs = new List<string>();
            var logFiles = Directory.GetFiles(_logPath, "*.log");

            foreach (var file in logFiles.Take(5))
            {
                logs.Add(System.IO.File.ReadAllText(file));
            }

            return Json(new
            {
                success = true,
                destination = destination,
                protocol = new Uri(destination).Scheme.ToUpper(),
                logsTransmitted = logFiles.Length,
                warning = "Logs transmis sans chiffrement!",
                risks = new[]
                {
                    "Interception possible (MITM)",
                    "Logs contiennent des données sensibles",
                    "Pas d'authentification",
                    "Pas d'intégrité vérifiée",
                    "Violation de compliance"
                },
                sampleData = logs.FirstOrDefault()?.Substring(0, Math.Min(200, logs.FirstOrDefault()?.Length ?? 0))
            });
        }

        // VULNÉRABLE : Pas de corrélation d'événements
        [HttpPost]
        public IActionResult LogSecurityEvent(string eventType, string source, string target)
        {
            var secEvent = new SecurityEvent
            {
                Timestamp = DateTime.UtcNow,
                EventType = eventType ?? "unknown",
                Source = source ?? "unknown",
                Target = target ?? "unknown",
                Id = Guid.NewGuid().ToString()
            };

            _securityEvents.Add(secEvent);

            // VULNÉRABLE : Événements isolés, pas de corrélation
            var relatedEvents = new List<SecurityEvent>(); // Toujours vide !

            return Json(new
            {
                success = true,
                eventLogged = secEvent,
                correlatedEvents = relatedEvents.Count,
                warning = "Événement isolé - Pas de corrélation!",
                missedPatterns = new[]
                {
                    "Scan de ports suivi d'exploitation",
                    "Brute force multi-services",
                    "Lateral movement non détecté",
                    "Data exfiltration progressive",
                    "Kill chain non identifiée"
                }
            });
        }

        // VULNÉRABLE : Détection tardive
        [HttpGet]
        public IActionResult CheckIncidents()
        {
            // VULNÉRABLE : Vérification manuelle occasionnelle
            var oldestUnreviewed = _securityEvents
                .Where(e => !e.Reviewed)
                .OrderBy(e => e.Timestamp)
                .FirstOrDefault();

            var detectionDelay = oldestUnreviewed != null
                ? (DateTime.UtcNow - oldestUnreviewed.Timestamp).TotalDays
                : 0;

            return Json(new
            {
                success = true,
                totalEvents = _securityEvents.Count,
                unreviewedEvents = _securityEvents.Count(e => !e.Reviewed),
                oldestUnreviewedDays = detectionDelay,
                warning = "Détection manuelle tardive!",
                issues = new[]
                {
                    "Pas de monitoring temps réel",
                    "Review manuel occasionnel",
                    $"Délai moyen: {detectionDelay:F0} jours",
                    "Pas d'automatisation",
                    "Fenêtre d'attaque énorme"
                },
                industryAverage = "280 jours pour détecter une breach"
            });
        }

        // VULNÉRABLE : Pas de protection d'intégrité
        [HttpPost]
        public IActionResult VerifyLogIntegrity(string logName)
        {
            if (string.IsNullOrEmpty(logName))
                return Json(new { success = false, error = "LogName requis" });

            var logFile = Path.Combine(_logPath, logName);

            if (!System.IO.File.Exists(logFile))
                return Json(new { success = false, error = "Fichier non trouvé" });

            // VULNÉRABLE : Pas de hash/signature stocké
            var content = System.IO.File.ReadAllText(logFile);

            // VULNÉRABLE : Hash calculé à la volée (inutile)
            using (var sha256 = SHA256.Create())
            {
                var currentHash = BitConverter.ToString(
                    sha256.ComputeHash(Encoding.UTF8.GetBytes(content))
                ).Replace("-", "");

                return Json(new
                {
                    success = true,
                    file = logName,
                    currentHash = currentHash,
                    storedHash = "AUCUN", // VULNÉRABLE !
                    integrityVerified = false,
                    warning = "Aucune protection d'intégrité!",
                    issues = new[]
                    {
                        "Pas de hash stocké à la création",
                        "Pas de signature numérique",
                        "Pas de blockchain/immuabilité",
                        "Modifications non détectables",
                        "Chain of custody brisée"
                    }
                });
            }
        }

        // VULNÉRABLE : Configuration de logging inadéquate
        [HttpGet]
        public IActionResult GetLoggingConfig()
        {
            // VULNÉRABLE : Configuration exposée et insuffisante
            var config = new
            {
                logLevel = "Error", // VULNÉRABLE : Que les erreurs !
                logToFile = true,
                logToSiem = false, // VULNÉRABLE : Pas de SIEM
                logRotation = "Never", // VULNÉRABLE : Jamais roté
                maxLogSize = "Unlimited", // VULNÉRABLE : Taille illimitée
                retention = "Forever", // VULNÉRABLE : Rétention infinie
                encryption = false, // VULNÉRABLE : Pas chiffré
                compression = false,
                realTimeAlerts = false, // VULNÉRABLE : Pas d'alertes
                includeSensitiveData = true // VULNÉRABLE !
            };

            return Json(new
            {
                success = true,
                configuration = config,
                warning = "Configuration de logging inadéquate!",
                issues = new[]
                {
                    "Log level trop élevé (manque INFO/DEBUG)",
                    "Pas connecté au SIEM",
                    "Pas de rotation (disque plein)",
                    "Rétention non conforme RGPD",
                    "Données sensibles incluses"
                }
            });
        }

        // Endpoint de test
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            // Créer quelques logs de test
            var testLogs = new[] { "application.log", "security.log", "sensitive.log", "errors.log" };
            foreach (var log in testLogs)
            {
                var logFile = Path.Combine(_logPath, log);
                if (!System.IO.File.Exists(logFile))
                {
                    System.IO.File.WriteAllText(logFile, $"Test log created at {DateTime.Now}\n");
                }
            }

            return Json(new
            {
                endpoints = new[]
                {
                    "POST /LoggingMonitoring/AttemptLogin - Login sans logging",
                    "POST /LoggingMonitoring/LogSensitiveData - Logging de données sensibles",
                    "POST /LoggingMonitoring/InjectLog - Log injection",
                    "POST /LoggingMonitoring/SimulateBruteForce - Pas d'alertes",
                    "POST /LoggingMonitoring/TamperLogs - Modification de logs",
                    "GET /LoggingMonitoring/TransmitLogs - Transmission non chiffrée",
                    "POST /LoggingMonitoring/LogSecurityEvent - Pas de corrélation",
                    "GET /LoggingMonitoring/CheckIncidents - Détection tardive",
                    "POST /LoggingMonitoring/VerifyLogIntegrity - Pas d'intégrité",
                    "GET /LoggingMonitoring/GetLoggingConfig - Config inadéquate"
                },
                vulnerabilities = new[]
                {
                    "No security event logging",
                    "Sensitive data in logs",
                    "Log injection possible",
                    "No alerting thresholds",
                    "Logs can be tampered",
                    "Unencrypted transmission",
                    "No event correlation",
                    "Delayed detection",
                    "No integrity protection",
                    "Insufficient log levels"
                },
                logFiles = testLogs,
                logPath = "/logs/"
            });
        }
    }

    // Modèles
    public class LoggingMonitoringResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SecurityEvent
    {
        public string Id { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public bool Reviewed { get; set; } = false;
    }
}