using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Web;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionCrlfController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        public InjectionCrlfController()
        {
            _attackInfos = new()
            {
                ["redirect"] = new AttackInfo
                {
                    Description = "Injection d'en-têtes HTTP pour effectuer une redirection malveillante en injectant l'en-tête Location.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                    RiskLevel = "High",
                    PayloadExample = @"test\r\nLocation: https://evil.com",
                    ErrorExplanation = "La redirection peut échouer si les caractères de retour à la ligne sont filtrés ou si l'en-tête Location est déjà défini."
                },
                ["xss"] = new AttackInfo
                {
                    Description = "Injection d'en-têtes pour exécuter du JavaScript via des en-têtes reflétés dans la réponse HTML.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                    RiskLevel = "High",
                    PayloadExample = @"test\r\n\r\n<script>alert('XSS')</script>",
                    ErrorExplanation = "L'injection XSS via headers peut échouer si la réponse n'est pas interprétée comme HTML ou si les caractères sont encodés."
                },
                ["cookie"] = new AttackInfo
                {
                    Description = "Injection de cookies malveillants via l'en-tête Set-Cookie pour voler des sessions ou tracker les utilisateurs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                    RiskLevel = "Medium",
                    PayloadExample = @"test\r\nSet-Cookie: admin=true; Path=/",
                    ErrorExplanation = "L'injection de cookies peut échouer si les cookies sont définis avec HttpOnly ou si le framework les valide."
                },
                ["cache"] = new AttackInfo
                {
                    Description = "Manipulation des en-têtes de cache pour empoisonner le cache et servir du contenu malveillant à d'autres utilisateurs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Cache_Poisoning",
                    RiskLevel = "Medium",
                    PayloadExample = @"test\r\nCache-Control: public, max-age=31536000",
                    ErrorExplanation = "L'empoisonnement du cache nécessite que le serveur ou proxy utilise les en-têtes injectés pour la mise en cache."
                },
                ["cors"] = new AttackInfo
                {
                    Description = "Injection d'en-têtes CORS pour permettre des requêtes cross-origin non autorisées.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    RiskLevel = "Medium",
                    PayloadExample = @"test\r\nAccess-Control-Allow-Origin: *",
                    ErrorExplanation = "L'injection CORS peut échouer si les en-têtes CORS sont déjà définis ou gérés par le serveur."
                },
                ["security"] = new AttackInfo
                {
                    Description = "Désactivation des en-têtes de sécurité comme X-Frame-Options ou Content-Security-Policy.",
                    LearnMoreUrl = "https://owasp.org/www-community/Security_Headers",
                    RiskLevel = "Medium",
                    PayloadExample = @"test\r\nX-Frame-Options: ALLOWALL\r\nContent-Security-Policy: default-src *",
                    ErrorExplanation = "La modification des en-têtes de sécurité peut être bloquée si ils sont définis après l'injection."
                },
                ["smuggling"] = new AttackInfo
                {
                    Description = "HTTP Request Smuggling via l'injection d'en-têtes Content-Length ou Transfer-Encoding conflictuels.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/HTTP_Request_Smuggling",
                    RiskLevel = "High",
                    PayloadExample = @"test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked",
                    ErrorExplanation = "Le request smuggling nécessite des configurations spécifiques de proxy/serveur pour réussir."
                },
                ["custom"] = new AttackInfo
                {
                    Description = "Injection d'en-têtes personnalisés pour exploiter des fonctionnalités spécifiques de l'application.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                    RiskLevel = "Low",
                    PayloadExample = @"test\r\nX-Admin: true\r\nX-Debug: enabled",
                    ErrorExplanation = "Les en-têtes personnalisés n'ont d'impact que si l'application les utilise pour la logique métier."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<HeaderInjectionResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<HeaderInjectionResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<HeaderInjectionResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<HeaderInjectionResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<HeaderInjectionResult>();

                // Simuler l'injection d'en-têtes (DANGEREUX - Ne jamais faire en production!)
                var injectionResult = SimulateHeaderInjection(payload, attackType);
                results.Add(injectionResult);

                var model = VulnerabilityViewModel<HeaderInjectionResult>.WithResults(payload, attackType, results, payload);
                model.AttackInfos = _attackInfos;

                // Si c'est une vraie redirection, l'ajouter à la réponse (DANGEREUX!)
                if (attackType == "redirect" && injectionResult.InjectedHeaders.ContainsKey("Location"))
                {
                    Response.Headers["X-Demo-Would-Redirect-To"] = injectionResult.InjectedHeaders["Location"];
                }

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<HeaderInjectionResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur d'injection : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private HeaderInjectionResult SimulateHeaderInjection(string payload, string attackType)
        {
            var result = new HeaderInjectionResult
            {
                OriginalPayload = payload,
                AttackType = attackType,
                InjectedHeaders = new Dictionary<string, string>(),
                ResponseModifications = new List<string>(),
                Success = false
            };

            try
            {
                // Traiter les séquences d'échappement littérales
                string processedPayload = payload
                    .Replace("\\r\\n", "\r\n")
                    .Replace("\\n", "\n")
                    .Replace("\\r", "\r");

                // Décoder les séquences URL-encoded
                processedPayload = System.Web.HttpUtility.UrlDecode(processedPayload);

                // Détecter les tentatives d'injection CRLF
                if (processedPayload.Contains("\r\n") || processedPayload.Contains("\n") || processedPayload.Contains("\r"))
                {
                    result.CrlfDetected = true;

                    // Parser les en-têtes injectés
                    var lines = processedPayload.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);

                    bool bodyStarted = false;
                    var bodyContent = new List<string>();

                    for (int i = 1; i < lines.Length; i++)
                    {
                        var line = lines[i];

                        if (bodyStarted)
                        {
                            bodyContent.Add(line);
                            continue;
                        }

                        if (string.IsNullOrWhiteSpace(line))
                        {
                            result.ResponseBodyInjected = true;
                            bodyStarted = true;
                            continue;
                        }

                        var colonIndex = line.IndexOf(':');
                        if (colonIndex > 0)
                        {
                            var headerName = line.Substring(0, colonIndex).Trim();
                            var headerValue = line.Substring(colonIndex + 1).Trim();
                            result.InjectedHeaders[headerName] = headerValue;
                        }
                    }

                    if (bodyContent.Any())
                    {
                        result.InjectedContent = string.Join("\r\n", bodyContent);
                    }

                    // Analyser l'impact selon le type d'attaque
                    AnalyzeImpact(result, attackType);

                    result.Success = true;
                }
                else
                {
                    result.ResponseModifications.Add("Aucune séquence CRLF détectée - l'injection a échoué");
                }

                // Calculer le score de risque
                result.RiskScore = CalculateRiskScore(result);
            }
            catch (Exception ex)
            {
                result.ResponseModifications.Add($"Erreur lors de l'analyse : {ex.Message}");
            }

            return result;
        }

        private void AnalyzeImpact(HeaderInjectionResult result, string attackType)
        {
            switch (attackType)
            {
                case "redirect":
                    if (result.InjectedHeaders.ContainsKey("Location"))
                    {
                        result.ResponseModifications.Add($"Redirection forcée vers : {result.InjectedHeaders["Location"]}");
                        result.SecurityImpact.Add("Un attaquant pourrait rediriger les utilisateurs vers un site malveillant");
                    }
                    break;

                case "xss":
                    if (result.ResponseBodyInjected && !string.IsNullOrEmpty(result.InjectedContent))
                    {
                        if (result.InjectedContent.Contains("<script>") || result.InjectedContent.Contains("javascript:"))
                        {
                            result.ResponseModifications.Add("Code JavaScript injecté dans le corps de la réponse");
                            result.SecurityImpact.Add("Exécution de code JavaScript arbitraire (XSS)");
                        }
                    }
                    break;

                case "cookie":
                    if (result.InjectedHeaders.ContainsKey("Set-Cookie"))
                    {
                        result.ResponseModifications.Add($"Cookie injecté : {result.InjectedHeaders["Set-Cookie"]}");
                        result.SecurityImpact.Add("Possibilité de vol de session ou élévation de privilèges");
                    }
                    break;

                case "cache":
                    if (result.InjectedHeaders.ContainsKey("Cache-Control"))
                    {
                        result.ResponseModifications.Add($"En-têtes de cache modifiés : {result.InjectedHeaders["Cache-Control"]}");
                        result.SecurityImpact.Add("Risque d'empoisonnement du cache affectant d'autres utilisateurs");
                    }
                    break;

                case "cors":
                    if (result.InjectedHeaders.ContainsKey("Access-Control-Allow-Origin"))
                    {
                        result.ResponseModifications.Add($"CORS modifié : {result.InjectedHeaders["Access-Control-Allow-Origin"]}");
                        result.SecurityImpact.Add("Contournement de la politique Same-Origin");
                    }
                    break;

                case "security":
                    foreach (var header in result.InjectedHeaders.Keys)
                    {
                        if (header.StartsWith("X-") || header == "Content-Security-Policy")
                        {
                            result.ResponseModifications.Add($"En-tête de sécurité modifié : {header}");
                            result.SecurityImpact.Add($"Désactivation de protection : {header}");
                        }
                    }
                    break;

                case "smuggling":
                    if (result.InjectedHeaders.ContainsKey("Content-Length") ||
                        result.InjectedHeaders.ContainsKey("Transfer-Encoding"))
                    {
                        result.ResponseModifications.Add("En-têtes de longueur/encodage conflictuels détectés");
                        result.SecurityImpact.Add("Risque de HTTP Request Smuggling");
                    }
                    break;

                case "custom":
                    foreach (var header in result.InjectedHeaders)
                    {
                        if (header.Key.StartsWith("X-"))
                        {
                            result.ResponseModifications.Add($"En-tête personnalisé injecté : {header.Key} = {header.Value}");
                            result.SecurityImpact.Add($"Impact dépendant de l'utilisation de {header.Key}");
                        }
                    }
                    break;
            }
        }

        private int CalculateRiskScore(HeaderInjectionResult result)
        {
            int score = 0;

            if (result.CrlfDetected) score += 30;
            if (result.ResponseBodyInjected) score += 20;
            if (result.InjectedHeaders.ContainsKey("Location")) score += 25;
            if (result.InjectedHeaders.ContainsKey("Set-Cookie")) score += 20;
            if (result.InjectedContent?.Contains("<script>") == true) score += 25;

            return Math.Min(score, 100);
        }
    }

    // Modèle pour les résultats d'injection d'en-têtes
    public class HeaderInjectionResult
    {
        public string OriginalPayload { get; set; } = string.Empty;
        public string AttackType { get; set; } = string.Empty;
        public bool CrlfDetected { get; set; }
        public bool ResponseBodyInjected { get; set; }
        public Dictionary<string, string> InjectedHeaders { get; set; } = new();
        public string? InjectedContent { get; set; }
        public List<string> ResponseModifications { get; set; } = new();
        public List<string> SecurityImpact { get; set; } = new();
        public int RiskScore { get; set; }
        public bool Success { get; set; }
    }
}