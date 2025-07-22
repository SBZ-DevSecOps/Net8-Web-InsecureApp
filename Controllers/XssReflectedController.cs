using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using System.Web;

namespace InsecureAppWebNet8.Controllers
{
    public class XssReflectedController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // VULNÉRABLE : Données stockées sans sanitisation
        private static readonly List<SearchResult> _searchResults = new()
        {
            new SearchResult { Id = 1, Title = "Article sécurité", Content = "Introduction à la sécurité web", Url = "/article/1" },
            new SearchResult { Id = 2, Title = "Guide XSS", Content = "Comment éviter les failles XSS", Url = "/article/2" },
            new SearchResult { Id = 3, Title = "OWASP Top 10", Content = "Les 10 principales vulnérabilités", Url = "/article/3" }
        };

        public XssReflectedController()
        {
            _attackInfos = new()
            {
                ["reflected-search"] = new AttackInfo
                {
                    Description = "XSS Reflected via paramètre de recherche non échappé.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "High",
                    PayloadExample = "<script>alert('XSS')</script>",
                    ErrorExplanation = "Le paramètre de recherche est affiché directement sans échappement."
                },
                ["reflected-error"] = new AttackInfo
                {
                    Description = "XSS Reflected via message d'erreur non sanitisé.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/reflected",
                    RiskLevel = "High",
                    PayloadExample = "<img src=x onerror=alert('Error-XSS')>",
                    ErrorExplanation = "Les messages d'erreur affichent l'input utilisateur sans échappement."
                },
                ["reflected-redirect"] = new AttackInfo
                {
                    Description = "XSS Reflected via paramètre de redirection.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    RiskLevel = "Medium",
                    PayloadExample = "javascript:alert('Redirect-XSS')",
                    ErrorExplanation = "L'URL de redirection n'est pas validée."
                },
                ["reflected-form"] = new AttackInfo
                {
                    Description = "XSS Reflected via champs de formulaire.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "High",
                    PayloadExample = "\"><script>alert('Form-XSS')</script>",
                    ErrorExplanation = "Les valeurs de formulaire sont réaffichées sans échappement."
                },
                ["reflected-url"] = new AttackInfo
                {
                    Description = "XSS Reflected via paramètres URL multiples.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/reflected",
                    RiskLevel = "High",
                    PayloadExample = "<svg onload=alert('URL-XSS')>",
                    ErrorExplanation = "Plusieurs paramètres URL sont reflétés sans validation."
                },
                ["reflected-header"] = new AttackInfo
                {
                    Description = "XSS Reflected via headers HTTP (User-Agent, Referer).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "Medium",
                    PayloadExample = "<script>alert('Header-XSS')</script>",
                    ErrorExplanation = "Les headers HTTP sont affichés sans échappement."
                },
                ["reflected-cookie"] = new AttackInfo
                {
                    Description = "XSS Reflected via valeurs de cookies.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/reflected",
                    RiskLevel = "Medium",
                    PayloadExample = "<img src=x onerror=alert('Cookie-XSS')>",
                    ErrorExplanation = "Les valeurs de cookies sont reflétées sans sanitisation."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<XssReflectedResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<XssReflectedResult>(),
                AttackInfos = _attackInfos
            };

            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<XssReflectedResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<XssReflectedResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = ExecuteReflectedXss(attackType, payload);
                model.Results.Add(result);
            }

            return View(model);
        }

        // VULNÉRABLE : Recherche avec XSS Reflected
        [HttpGet]
        public IActionResult Search(string q, string category, string sort)
        {
            var results = _searchResults.AsQueryable();

            if (!string.IsNullOrEmpty(q))
            {
                results = results.Where(r =>
                    r.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    r.Content.Contains(q, StringComparison.OrdinalIgnoreCase));
            }

            // VULNÉRABLE : Paramètres reflétés sans échappement
            ViewBag.SearchQuery = q; // VULNÉRABLE
            ViewBag.Category = category; // VULNÉRABLE  
            ViewBag.Sort = sort; // VULNÉRABLE
            ViewBag.ResultCount = results.Count();

            return View("SearchResults", results.ToList());
        }

        // VULNÉRABLE : Page d'erreur avec XSS
        [HttpGet]
        public IActionResult Error(string message, string details, string code)
        {
            // VULNÉRABLE : Messages d'erreur non échappés
            ViewBag.ErrorMessage = message ?? "Erreur inconnue"; // VULNÉRABLE
            ViewBag.ErrorDetails = details ?? "Aucun détail disponible"; // VULNÉRABLE
            ViewBag.ErrorCode = code ?? "500"; // VULNÉRABLE
            ViewBag.Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            return View("ErrorPage");
        }

        // VULNÉRABLE : Redirection avec XSS
        [HttpGet]
        public IActionResult Redirect(string url, string message)
        {
            // VULNÉRABLE : URL et message non validés
            ViewBag.RedirectUrl = url ?? "/"; // VULNÉRABLE
            ViewBag.RedirectMessage = message ?? "Redirection en cours..."; // VULNÉRABLE

            return View("RedirectPage");
        }

        // VULNÉRABLE : Formulaire de contact
        [HttpPost]
        public IActionResult Contact(string name, string email, string subject, string message)
        {
            // VULNÉRABLE : Réaffichage des données formulaire
            ViewBag.ContactName = name; // VULNÉRABLE
            ViewBag.ContactEmail = email; // VULNÉRABLE
            ViewBag.ContactSubject = subject; // VULNÉRABLE
            ViewBag.ContactMessage = message; // VULNÉRABLE
            ViewBag.IsSubmitted = true;

            return View("ContactForm");
        }

        [HttpGet]
        public IActionResult ContactForm()
        {
            ViewBag.IsSubmitted = false;
            return View();
        }

        // VULNÉRABLE : Profile avec paramètres multiples
        [HttpGet]
        public IActionResult Profile(string username, string theme, string lang, string timezone)
        {
            // VULNÉRABLE : Paramètres multiples reflétés
            ViewBag.Username = username ?? "Anonyme"; // VULNÉRABLE
            ViewBag.Theme = theme ?? "default"; // VULNÉRABLE
            ViewBag.Language = lang ?? "fr"; // VULNÉRABLE
            ViewBag.Timezone = timezone ?? "UTC"; // VULNÉRABLE

            return View("ProfilePage");
        }

        // VULNÉRABLE : API qui reflète les headers
        [HttpGet]
        public IActionResult Debug()
        {
            var headers = new Dictionary<string, string>();

            // VULNÉRABLE : Headers HTTP non échappés
            foreach (var header in Request.Headers)
            {
                headers[header.Key] = string.Join(", ", header.Value); // VULNÉRABLE
            }

            // VULNÉRABLE : Informations reflétées
            ViewBag.UserAgent = Request.Headers["User-Agent"].ToString(); // VULNÉRABLE
            ViewBag.Referer = Request.Headers["Referer"].ToString(); // VULNÉRABLE
            ViewBag.XForwardedFor = Request.Headers["X-Forwarded-For"].ToString(); // VULNÉRABLE
            ViewBag.AllHeaders = headers; // VULNÉRABLE

            return View("DebugPage");
        }

        // VULNÉRABLE : Cookies reflétés
        [HttpGet]
        public IActionResult CookieTest(string action)
        {
            if (action == "set")
            {
                // VULNÉRABLE : Valeur de cookie non validée
                var cookieValue = Request.Query["value"].ToString();
                Response.Cookies.Append("testCookie", cookieValue); // VULNÉRABLE
                ViewBag.Message = $"Cookie défini avec la valeur: {cookieValue}"; // VULNÉRABLE
            }
            else if (action == "get")
            {
                // VULNÉRABLE : Valeur de cookie reflétée
                var cookieValue = Request.Cookies["testCookie"] ?? "Aucun cookie";
                ViewBag.Message = $"Valeur du cookie: {cookieValue}"; // VULNÉRABLE
            }

            return View("CookiePage");
        }

        // VULNÉRABLE : API JSON avec XSS
        [HttpGet]
        public IActionResult Api(string callback, string data, string format)
        {
            var response = new
            {
                success = true,
                query = Request.QueryString.ToString(), // VULNÉRABLE
                callback = callback, // VULNÉRABLE
                data = data, // VULNÉRABLE
                format = format, // VULNÉRABLE
                timestamp = DateTime.Now
            };

            // VULNÉRABLE : JSONP sans validation
            if (!string.IsNullOrEmpty(callback))
            {
                var jsonp = $"{callback}({JsonSerializer.Serialize(response)});"; // VULNÉRABLE
                return Content(jsonp, "application/javascript");
            }

            return Json(response);
        }

        // VULNÉRABLE : Upload avec nom de fichier reflété
        [HttpPost]
        public IActionResult Upload(IFormFile file, string description)
        {
            if (file != null)
            {
                // VULNÉRABLE : Nom de fichier non échappé
                ViewBag.FileName = file.FileName; // VULNÉRABLE
                ViewBag.FileSize = file.Length;
                ViewBag.ContentType = file.ContentType; // VULNÉRABLE
            }

            // VULNÉRABLE : Description non échappée
            ViewBag.Description = description; // VULNÉRABLE
            ViewBag.UploadSuccess = file != null;

            return View("UploadResult");
        }

        // Helper method pour exécuter les tests XSS
        private XssReflectedResult ExecuteReflectedXss(string attackType, string payload)
        {
            return attackType switch
            {
                "reflected-search" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via recherche détecté",
                    ReflectedContent = $"Résultats pour: {payload}", // VULNÉRABLE
                    VulnerableParameter = "q",
                    TestUrl = $"/XssReflected/Search?q={payload}"
                },
                "reflected-error" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via erreur détecté",
                    ReflectedContent = $"Erreur: {payload}", // VULNÉRABLE
                    VulnerableParameter = "message",
                    TestUrl = $"/XssReflected/Error?message={payload}"
                },
                "reflected-form" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via formulaire détecté",
                    ReflectedContent = $"Nom: {payload}", // VULNÉRABLE
                    VulnerableParameter = "name",
                    TestUrl = "/XssReflected/ContactForm"
                },
                "reflected-url" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via URL détecté",
                    ReflectedContent = $"Paramètre: {payload}", // VULNÉRABLE
                    VulnerableParameter = "multiple",
                    TestUrl = $"/XssReflected/Profile?username={payload}"
                },
                "reflected-header" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via headers détecté",
                    ReflectedContent = $"User-Agent: {payload}", // VULNÉRABLE
                    VulnerableParameter = "User-Agent",
                    TestUrl = "/XssReflected/Debug"
                },
                "reflected-cookie" => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Reflected via cookie détecté",
                    ReflectedContent = $"Cookie: {payload}", // VULNÉRABLE
                    VulnerableParameter = "testCookie",
                    TestUrl = $"/XssReflected/CookieTest?action=set&value={payload}"
                },
                _ => new XssReflectedResult
                {
                    AttackType = attackType,
                    Success = false,
                    Message = "Type d'attaque non reconnu",
                    ReflectedContent = "",
                    VulnerableParameter = "",
                    TestUrl = ""
                }
            };
        }

        // Endpoint de test pour les outils SAST
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "GET /XssReflected/Search?q=<script> - Recherche vulnérable",
                    "GET /XssReflected/Error?message=<script> - Erreur XSS",
                    "GET /XssReflected/Redirect?url=javascript:alert(1) - Redirection XSS",
                    "POST /XssReflected/Contact - Formulaire vulnérable",
                    "GET /XssReflected/Profile?username=<script> - Paramètres multiples",
                    "GET /XssReflected/Debug - Headers reflétés",
                    "GET /XssReflected/CookieTest?action=set&value=<script> - Cookies XSS",
                    "GET /XssReflected/Api?callback=<script> - JSONP vulnérable",
                    "POST /XssReflected/Upload - Nom fichier XSS"
                },
                vulnerabilities = new[]
                {
                    "Reflected XSS in search parameters",
                    "Reflected XSS in error messages",
                    "Reflected XSS in form fields",
                    "Reflected XSS in URL parameters",
                    "Reflected XSS in HTTP headers",
                    "Reflected XSS in cookie values",
                    "JSONP callback injection",
                    "File upload XSS",
                    "No input validation",
                    "No output encoding",
                    "No CSP headers"
                },
                payloadExamples = new[]
                {
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "\"><script>alert(1)</script>",
                    "';alert('XSS');//",
                    "<iframe src='javascript:alert(1)'></iframe>",
                    "<details open ontoggle=alert(1)>",
                    "<marquee onstart=alert(1)>XSS</marquee>",
                    "data:text/html,<script>alert(1)</script>"
                }
            });
        }
    }

    // Modèles
    public class XssReflectedResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ReflectedContent { get; set; } = string.Empty;
        public string VulnerableParameter { get; set; } = string.Empty;
        public string TestUrl { get; set; } = string.Empty;
    }

    public class SearchResult
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
    }
}