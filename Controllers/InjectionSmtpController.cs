using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionSmtpController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // Configuration SMTP vulnérable (hardcodée - détectable par SAST)
        private const string SMTP_HOST = "smtp.gmail.com";
        private const string SMTP_USERNAME = "insecureapp@gmail.com";
        private const string SMTP_PASSWORD = "P@ssw0rd123!"; // Secret hardcodé - vulnérable

        public InjectionSmtpController()
        {
            _attackInfos = new()
            {
                ["header-injection"] = new AttackInfo
                {
                    Description = "Injection d'en-têtes SMTP via des retours à la ligne non filtrés dans l'adresse email.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Email_Header_Injection",
                    RiskLevel = "High",
                    PayloadExample = "victim@example.com%0ABcc: attacker@evil.com",
                    ErrorExplanation = "Les caractères \\r\\n permettent d'injecter des en-têtes supplémentaires."
                },
                ["log-injection"] = new AttackInfo
                {
                    Description = "Injection dans les logs via des entrées non sanitisées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "test@example.com%0A[ADMIN] User promoted to admin",
                    ErrorExplanation = "Les logs peuvent être falsifiés avec des entrées malveillantes."
                },
                ["command-injection"] = new AttackInfo
                {
                    Description = "Injection de commandes via l'utilisation non sécurisée de sendmail.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Command_Injection",
                    RiskLevel = "Critical",
                    PayloadExample = "test@example.com; cat /etc/passwd",
                    ErrorExplanation = "Les paramètres sont passés directement à la commande système."
                },
                ["template-injection"] = new AttackInfo
                {
                    Description = "Injection de template dans le corps de l'email permettant l'exécution de code.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
                    RiskLevel = "High",
                    PayloadExample = "Bonjour {{7*7}} - Résultat: 49",
                    ErrorExplanation = "Le template est évalué sans sanitisation."
                },
                ["open-relay"] = new AttackInfo
                {
                    Description = "Serveur mail configuré comme relais ouvert permettant l'envoi de spam.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Mail_Command_Injection",
                    RiskLevel = "High",
                    PayloadExample = "Envoyer à n'importe quelle adresse sans authentification",
                    ErrorExplanation = "Le serveur accepte de relayer des mails vers n'importe quel domaine."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<SmtpInjectionResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<SmtpInjectionResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<SmtpInjectionResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<SmtpInjectionResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new SmtpInjectionResult
                {
                    AttackType = attackType,
                    OriginalPayload = payload,
                    Success = true,
                    ExploitedEndpoints = new List<string> { "Utiliser les endpoints réels ci-dessous pour tester les vulnérabilités SMTP." }
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // Vulnérable : Injection d'en-têtes SMTP
        [HttpPost]
        public IActionResult SendEmail(string to, string subject, string body)
        {
            try
            {
                // VULNÉRABLE : Pas de validation des entrées - injection possible
                var mailMessage = new MailMessage();

                // Construction directe sans validation - VULNÉRABLE
                mailMessage.To.Add(to); // Injection d'en-têtes possible ici
                mailMessage.From = new MailAddress("noreply@insecureapp.com");
                mailMessage.Subject = subject; // Injection possible
                mailMessage.Body = body;

                // Headers personnalisés sans validation - VULNÉRABLE
                mailMessage.Headers.Add("X-Mailer", "InsecureApp v1.0");
                mailMessage.Headers.Add("X-User-Input", to); // Injection directe

                // Envoi via SMTP
                using (var smtpClient = new SmtpClient(SMTP_HOST))
                {
                    smtpClient.Port = 587;
                    smtpClient.Credentials = new NetworkCredential(SMTP_USERNAME, SMTP_PASSWORD);
                    smtpClient.EnableSsl = true;

                    // Pour la démo, on simule l'envoi
                    // smtpClient.Send(mailMessage);
                }

                // Log vulnérable - injection possible
                LogEmailActivity($"Email sent to: {to}"); // Log injection

                return Json(new { success = true, message = $"Email envoyé à {to}" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Construction manuelle des en-têtes SMTP
        [HttpPost]
        public IActionResult SendRawEmail(string recipient, string customHeaders)
        {
            // VULNÉRABLE : Construction manuelle du message SMTP
            var smtpMessage = new StringBuilder();
            smtpMessage.AppendLine($"To: {recipient}"); // Pas de validation
            smtpMessage.AppendLine("From: admin@insecureapp.com");

            // Ajout direct des en-têtes custom - VULNÉRABLE
            if (!string.IsNullOrEmpty(customHeaders))
            {
                smtpMessage.AppendLine(customHeaders); // Injection directe possible
            }

            smtpMessage.AppendLine("Subject: Test Email");
            smtpMessage.AppendLine();
            smtpMessage.AppendLine("Email body");

            return Json(new
            {
                success = true,
                rawMessage = smtpMessage.ToString(),
                warning = "En-têtes SMTP construits manuellement sans validation"
            });
        }

        // Vulnérable : Utilisation de Process.Start pour sendmail
        [HttpPost]
        public IActionResult SendViaSendmail(string email, string message)
        {
            try
            {
                // VULNÉRABLE : Command injection via Process.Start
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "/usr/sbin/sendmail",
                        Arguments = email, // Injection de commande possible
                        RedirectStandardInput = true,
                        UseShellExecute = false
                    }
                };

                // Pour la démo, on ne lance pas vraiment le process
                // process.Start();
                // process.StandardInput.WriteLine(message);
                // process.StandardInput.Close();

                return Json(new
                {
                    success = true,
                    command = $"sendmail {email}",
                    warning = "Command injection possible"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Template injection dans le corps de l'email
        [HttpPost]
        public IActionResult SendTemplatedEmail(string to, string templateBody)
        {
            try
            {
                // VULNÉRABLE : Évaluation de template sans sanitisation
                var body = templateBody
                    .Replace("{{username}}", GetUsername()) // OK
                    .Replace("{{date}}", DateTime.Now.ToString()); // OK

                // Évaluation dangereuse de code - VULNÉRABLE
                if (templateBody.Contains("{{") && templateBody.Contains("}}"))
                {
                    // Simulation d'évaluation de template (Razor, etc.)
                    body = EvaluateTemplate(templateBody); // Template injection
                }

                // Construction du mail avec le corps évalué
                var mail = new MailMessage("noreply@insecureapp.com", to)
                {
                    Subject = "Email avec template",
                    Body = body,
                    IsBodyHtml = true // XSS possible si le contenu n'est pas encodé
                };

                return Json(new
                {
                    success = true,
                    evaluatedBody = body,
                    warning = "Template évalué sans sanitisation"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Validation email incorrecte
        [HttpPost]
        public IActionResult ValidateAndSend(string emailList)
        {
            var emails = emailList.Split(',');
            var results = new List<object>();

            foreach (var email in emails)
            {
                // VULNÉRABLE : Regex insuffisante pour la validation
                var weakRegex = new Regex(@"[^@]+@[^@]+"); // Trop permissive

                if (weakRegex.IsMatch(email))
                {
                    // Accepte des emails malformés permettant l'injection
                    results.Add(new { email, valid = true });

                    // Envoi sans autre validation
                    SendEmailDirect(email);
                }
            }

            return Json(new { results, warning = "Validation email faible" });
        }

        // Vulnérable : Open relay
        [HttpPost]
        public IActionResult RelayEmail(string from, string to, string server)
        {
            try
            {
                // VULNÉRABLE : Accepte n'importe quel serveur/destinataire
                var smtpClient = new SmtpClient(server ?? SMTP_HOST) // Serveur contrôlé par l'utilisateur
                {
                    Port = 25,
                    EnableSsl = false,
                    // Pas d'authentification - VULNÉRABLE
                };

                var mail = new MailMessage(from, to) // Sources non validées
                {
                    Subject = "Relayed message",
                    Body = "This is a relayed message"
                };

                // Pour la démo, on simule
                // smtpClient.Send(mail);

                return Json(new
                {
                    success = true,
                    warning = "Open relay - accepte n'importe quelle destination"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Méthodes auxiliaires vulnérables

        private void LogEmailActivity(string message)
        {
            // VULNÉRABLE : Log injection - pas d'échappement
            var logEntry = $"[{DateTime.Now}] {message}"; // Injection possible
            System.IO.File.AppendAllText("email.log", logEntry + Environment.NewLine);
        }

        private string EvaluateTemplate(string template)
        {
            // VULNÉRABLE : Évaluation de code arbitraire
            // Simule une évaluation de template dangereuse
            if (template.Contains("{{7*7}}"))
                return template.Replace("{{7*7}}", "49");

            // Dans un vrai cas, ce serait une vraie évaluation Razor/Liquid/etc.
            return template;
        }

        private void SendEmailDirect(string email)
        {
            // VULNÉRABLE : Envoi direct sans validation supplémentaire
            // Code d'envoi ici...
        }

        private string GetUsername()
        {
            // Simule la récupération d'un username
            return "user@example.com";
        }

        // Endpoint de test pour voir les vulnérabilités
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "POST /InjectionSmtp/SendEmail",
                    "POST /InjectionSmtp/SendRawEmail",
                    "POST /InjectionSmtp/SendViaSendmail",
                    "POST /InjectionSmtp/SendTemplatedEmail",
                    "POST /InjectionSmtp/ValidateAndSend",
                    "POST /InjectionSmtp/RelayEmail"
                },
                vulnerabilities = new[]
                {
                    "Email header injection",
                    "Log injection",
                    "Command injection",
                    "Template injection",
                    "Weak email validation",
                    "Open relay",
                    "Hardcoded credentials"
                }
            });
        }
    }

    // Modèle pour les résultats
    public class SmtpInjectionResult
    {
        public string OriginalPayload { get; set; } = string.Empty;
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public List<string> ExploitedEndpoints { get; set; } = new();
    }
}