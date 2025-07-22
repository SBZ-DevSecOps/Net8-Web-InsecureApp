using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace InsecureAppWebNet8.Controllers
{
    public class SSRFController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IWebHostEnvironment _env;

        public SSRFController(IHttpClientFactory httpClientFactory, IWebHostEnvironment env)
        {
            _httpClientFactory = httpClientFactory;
            _env = env;

            _attackInfos = new()
            {
                ["url-fetch"] = new AttackInfo
                {
                    Description = "Récupération d'URL sans validation permettant l'accès aux ressources internes.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    RiskLevel = "Critical",
                    PayloadExample = "http://localhost/admin ou http://169.254.169.254/",
                    ErrorExplanation = "L'application fait des requêtes vers n'importe quelle URL fournie."
                },
                ["cloud-metadata"] = new AttackInfo
                {
                    Description = "Accès aux métadonnées cloud (AWS, Azure, GCP) via SSRF.",
                    LearnMoreUrl = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
                    RiskLevel = "Critical",
                    PayloadExample = "http://169.254.169.254/latest/meta-data/",
                    ErrorExplanation = "Les endpoints de métadonnées exposent des credentials et secrets."
                },
                ["internal-scan"] = new AttackInfo
                {
                    Description = "Port scanning interne via SSRF pour découvrir les services.",
                    LearnMoreUrl = "https://portswigger.net/web-security/ssrf",
                    RiskLevel = "High",
                    PayloadExample = "http://192.168.1.1:22 ou http://10.0.0.1:3306",
                    ErrorExplanation = "SSRF permet de scanner les ports internes non exposés."
                },
                ["file-protocol"] = new AttackInfo
                {
                    Description = "Lecture de fichiers locaux via protocole file://.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                    RiskLevel = "Critical",
                    PayloadExample = "file:///etc/passwd ou file:///c:/windows/win.ini",
                    ErrorExplanation = "Les protocoles non-HTTP permettent l'accès au système de fichiers."
                },
                ["bypass-blacklist"] = new AttackInfo
                {
                    Description = "Contournement de blacklist avec encodage et redirections.",
                    LearnMoreUrl = "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
                    RiskLevel = "High",
                    PayloadExample = "http://127.0.0.1 → http://2130706433 ou http://localhost@evil.com",
                    ErrorExplanation = "Les filtres basiques peuvent être contournés."
                },
                ["pdf-generation"] = new AttackInfo
                {
                    Description = "SSRF via génération de PDF avec contenu externe.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#pdf-generators",
                    RiskLevel = "High",
                    PayloadExample = "<img src='http://internal-server/admin'>",
                    ErrorExplanation = "Les générateurs PDF peuvent charger des ressources externes."
                },
                ["dns-rebinding"] = new AttackInfo
                {
                    Description = "DNS rebinding pour contourner les validations.",
                    LearnMoreUrl = "https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2019/august/tifu-by-using-math.random/",
                    RiskLevel = "High",
                    PayloadExample = "http://attacker.com → résout vers IP interne",
                    ErrorExplanation = "Le DNS peut changer entre validation et requête."
                },
                ["redis-ssrf"] = new AttackInfo
                {
                    Description = "SSRF pour interagir avec Redis via gopher://.",
                    LearnMoreUrl = "https://maxchadwick.xyz/blog/ssrf-exploiting-url-parsers",
                    RiskLevel = "Critical",
                    PayloadExample = "gopher://localhost:6379/_SET%20key%20value",
                    ErrorExplanation = "Permet d'exécuter des commandes Redis."
                },
                ["blind-ssrf"] = new AttackInfo
                {
                    Description = "Blind SSRF sans retour de contenu mais avec timing.",
                    LearnMoreUrl = "https://portswigger.net/web-security/ssrf/blind",
                    RiskLevel = "Medium",
                    PayloadExample = "Mesure du temps de réponse pour détecter les services",
                    ErrorExplanation = "Même sans contenu, le timing révèle des informations."
                },
                ["webhook-ssrf"] = new AttackInfo
                {
                    Description = "SSRF via fonctionnalité webhook/callback.",
                    LearnMoreUrl = "https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/",
                    RiskLevel = "High",
                    PayloadExample = "Webhook vers services internes",
                    ErrorExplanation = "Les webhooks sont souvent moins protégés contre SSRF."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<SSRFResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<SSRFResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<SSRFResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<SSRFResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new SSRFResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les vulnérabilités SSRF."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Fetch URL sans validation
        [HttpPost]
        public async Task<IActionResult> FetchUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
                return Json(new { success = false, error = "URL requise" });

            try
            {
                // VULNÉRABLE : Aucune validation de l'URL
                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);

                // VULNÉRABLE : Suit les redirections automatiquement
                var response = await httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                // Limiter la taille pour l'affichage
                if (content.Length > 5000)
                {
                    content = content.Substring(0, 5000) + "\n\n[TRONQUÉ...]";
                }

                return Json(new
                {
                    success = true,
                    url = url,
                    statusCode = (int)response.StatusCode,
                    headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                    content = content,
                    contentLength = response.Content.Headers.ContentLength,
                    warning = "SSRF exploité - Accès à des ressources internes possible!"
                });
            }
            catch (TaskCanceledException)
            {
                return Json(new { success = false, error = "Timeout - Le serveur cible ne répond pas" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Accès aux métadonnées cloud
        [HttpGet]
        public async Task<IActionResult> CheckMetadata(string endpoint)
        {
            try
            {
                // VULNÉRABLE : Accès direct aux endpoints de métadonnées
                var metadataUrls = new Dictionary<string, string>
                {
                    ["aws"] = "http://169.254.169.254/latest/meta-data/",
                    ["azure"] = "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    ["gcp"] = "http://metadata.google.internal/computeMetadata/v1/",
                    ["digitalocean"] = "http://169.254.169.254/metadata/v1/",
                    ["custom"] = endpoint ?? ""
                };

                var url = metadataUrls.GetValueOrDefault(endpoint?.ToLower() ?? "aws", endpoint ?? "");

                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                // Headers spécifiques pour certains clouds
                if (endpoint?.ToLower() == "gcp")
                {
                    httpClient.DefaultRequestHeaders.Add("Metadata-Flavor", "Google");
                }
                else if (endpoint?.ToLower() == "azure")
                {
                    httpClient.DefaultRequestHeaders.Add("Metadata", "true");
                }

                var response = await httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                return Json(new
                {
                    success = true,
                    endpoint = url,
                    content = content,
                    warning = "Métadonnées cloud exposées - Credentials possibles!",
                    sensitiveEndpoints = new[]
                    {
                        "/latest/meta-data/iam/security-credentials/",
                        "/latest/user-data/",
                        "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Scanner de ports interne
        [HttpPost]
        public async Task<IActionResult> ScanPort(string host, int port)
        {
            if (string.IsNullOrEmpty(host))
                return Json(new { success = false, error = "Host requis" });

            try
            {
                // VULNÉRABLE : Permet le scan de n'importe quel host/port
                var url = $"http://{host}:{port}";
                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(3);

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                try
                {
                    var response = await httpClient.GetAsync(url);
                    stopwatch.Stop();

                    return Json(new
                    {
                        success = true,
                        host = host,
                        port = port,
                        status = "OUVERT",
                        responseTime = stopwatch.ElapsedMilliseconds,
                        statusCode = (int)response.StatusCode,
                        server = response.Headers.Server?.ToString(),
                        warning = "Port interne découvert via SSRF!"
                    });
                }
                catch (HttpRequestException)
                {
                    return Json(new
                    {
                        success = true,
                        host = host,
                        port = port,
                        status = "FERMÉ/FILTRÉ",
                        responseTime = stopwatch.ElapsedMilliseconds
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Support de multiples protocoles
        [HttpPost]
        public async Task<IActionResult> FetchResource(string resource)
        {
            if (string.IsNullOrEmpty(resource))
                return Json(new { success = false, error = "Ressource requise" });

            try
            {
                // VULNÉRABLE : Accepte différents protocoles
                if (resource.StartsWith("file://"))
                {
                    // VULNÉRABLE : Lecture de fichiers locaux
                    var filePath = resource.Replace("file://", "");
                    if (System.IO.File.Exists(filePath))
                    {
                        var content = System.IO.File.ReadAllText(filePath);
                        return Json(new
                        {
                            success = true,
                            protocol = "file://",
                            content = content.Substring(0, Math.Min(content.Length, 1000)),
                            warning = "Fichier local lu via SSRF!",
                            filePath = filePath
                        });
                    }
                }
                else if (resource.StartsWith("gopher://"))
                {
                    // VULNÉRABLE : Protocole Gopher pour attaques avancées
                    return Json(new
                    {
                        success = true,
                        protocol = "gopher://",
                        warning = "Protocole Gopher peut être utilisé pour SMTP, Redis, etc.",
                        example = "gopher://localhost:25/_HELO%20localhost%0d%0a"
                    });
                }
                else if (resource.StartsWith("dict://"))
                {
                    // VULNÉRABLE : Protocole DICT
                    return Json(new
                    {
                        success = true,
                        protocol = "dict://",
                        warning = "Protocole DICT pour bannières de services",
                        example = "dict://localhost:11211/stats"
                    });
                }
                else
                {
                    // HTTP/HTTPS par défaut
                    var httpClient = _httpClientFactory.CreateClient();
                    var response = await httpClient.GetAsync(resource);
                    var content = await response.Content.ReadAsStringAsync();

                    return Json(new
                    {
                        success = true,
                        protocol = new Uri(resource).Scheme,
                        statusCode = (int)response.StatusCode,
                        content = content.Substring(0, Math.Min(content.Length, 1000)),
                        warning = "Ressource récupérée sans validation!"
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }

            return Json(new { success = false, error = "Protocole non supporté" });
        }

        // VULNÉRABLE : Webhook avec SSRF
        [HttpPost]
        public async Task<IActionResult> RegisterWebhook(string callbackUrl)
        {
            if (string.IsNullOrEmpty(callbackUrl))
                return Json(new { success = false, error = "URL de callback requise" });

            try
            {
                // VULNÉRABLE : Pas de validation de l'URL de callback
                var webhookId = Guid.NewGuid().ToString();

                // Simuler un test de webhook
                var httpClient = _httpClientFactory.CreateClient();
                var testPayload = new StringContent(
                    $"{{\"event\":\"test\",\"webhookId\":\"{webhookId}\"}}",
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await httpClient.PostAsync(callbackUrl, testPayload);

                return Json(new
                {
                    success = true,
                    webhookId = webhookId,
                    callbackUrl = callbackUrl,
                    testResult = new
                    {
                        statusCode = (int)response.StatusCode,
                        responseBody = await response.Content.ReadAsStringAsync()
                    },
                    warning = "Webhook SSRF - Peut atteindre des services internes!"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Contournement de blacklist
        [HttpPost]
        public async Task<IActionResult> FetchWithBypass(string url)
        {
            if (string.IsNullOrEmpty(url))
                return Json(new { success = false, error = "URL requise" });

            try
            {
                // VULNÉRABLE : Blacklist facilement contournable
                var blacklist = new[] { "localhost", "127.0.0.1", "169.254.169.254" };

                var isBlocked = blacklist.Any(blocked => url.Contains(blocked));

                if (isBlocked)
                {
                    return Json(new
                    {
                        success = false,
                        error = "URL bloquée par la blacklist",
                        hint = "Mais essayez: 127.1, 0x7f000001, 2130706433, localtest.me"
                    });
                }

                // VULNÉRABLE : La blacklist est facilement contournable
                var httpClient = _httpClientFactory.CreateClient();
                var response = await httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                return Json(new
                {
                    success = true,
                    url = url,
                    statusCode = (int)response.StatusCode,
                    content = content.Substring(0, Math.Min(content.Length, 1000)),
                    warning = "Blacklist contournée - SSRF toujours possible!",
                    bypassTechniques = new[]
                    {
                        "127.0.0.1 → 127.1",
                        "127.0.0.1 → 0x7f000001",
                        "127.0.0.1 → 2130706433",
                        "localhost → localtest.me",
                        "URL encoding",
                        "DNS rebinding"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Image proxy avec SSRF
        [HttpGet]
        public async Task<IActionResult> ProxyImage(string imageUrl)
        {
            if (string.IsNullOrEmpty(imageUrl))
                return BadRequest("URL d'image requise");

            try
            {
                // VULNÉRABLE : Proxy d'images sans validation
                var httpClient = _httpClientFactory.CreateClient();
                var response = await httpClient.GetAsync(imageUrl);

                var contentType = response.Content.Headers.ContentType?.ToString() ?? "image/jpeg";
                var imageBytes = await response.Content.ReadAsByteArrayAsync();

                // VULNÉRABLE : Retourne le contenu même si ce n'est pas une image
                return File(imageBytes, contentType);
            }
            catch (Exception)
            {
                return BadRequest("Erreur lors de la récupération de l'image");
            }
        }

        // VULNÉRABLE : SSRF via génération de PDF
        [HttpPost]
        public async Task<IActionResult> GeneratePDF(string htmlContent)
        {
            if (string.IsNullOrEmpty(htmlContent))
                return Json(new { success = false, error = "Contenu HTML requis" });

            try
            {
                // VULNÉRABLE : Le contenu HTML peut contenir des références externes
                // Simulation d'un générateur PDF qui charge les ressources
                var regex = new Regex(@"<img\s+[^>]*src\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                var matches = regex.Matches(htmlContent);

                var loadedResources = new List<object>();

                foreach (Match match in matches)
                {
                    var imageUrl = match.Groups[1].Value;

                    // VULNÉRABLE : Charge l'image sans validation
                    var httpClient = _httpClientFactory.CreateClient();
                    httpClient.Timeout = TimeSpan.FromSeconds(5);

                    try
                    {
                        var response = await httpClient.GetAsync(imageUrl);
                        loadedResources.Add(new
                        {
                            url = imageUrl,
                            statusCode = (int)response.StatusCode,
                            contentType = response.Content.Headers.ContentType?.ToString(),
                            size = response.Content.Headers.ContentLength
                        });
                    }
                    catch (Exception ex)
                    {
                        loadedResources.Add(new
                        {
                            url = imageUrl,
                            error = ex.Message
                        });
                    }
                }

                return Json(new
                {
                    success = true,
                    message = "PDF généré (simulation)",
                    loadedResources = loadedResources,
                    warning = "SSRF via PDF - Ressources internes chargées!",
                    examplePayload = "<img src='http://localhost/admin/users.json'>"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : DNS Rebinding
        [HttpPost]
        public async Task<IActionResult> CheckDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return Json(new { success = false, error = "Domaine requis" });

            try
            {
                // VULNÉRABLE : Vérifie le domaine puis fait la requête (race condition)
                var uri = new Uri(domain);
                var hostEntry = await Dns.GetHostEntryAsync(uri.Host);
                var firstCheck = hostEntry.AddressList.FirstOrDefault()?.ToString();

                // Simulation d'un délai où le DNS pourrait changer
                await Task.Delay(100);

                // VULNÉRABLE : Le DNS peut avoir changé entre les deux requêtes
                var httpClient = _httpClientFactory.CreateClient();
                var response = await httpClient.GetAsync(domain);

                // Vérifier à nouveau l'IP après la requête
                hostEntry = await Dns.GetHostEntryAsync(uri.Host);
                var secondCheck = hostEntry.AddressList.FirstOrDefault()?.ToString();

                return Json(new
                {
                    success = true,
                    domain = domain,
                    firstDnsResolution = firstCheck,
                    secondDnsResolution = secondCheck,
                    dnsChanged = firstCheck != secondCheck,
                    responseStatus = (int)response.StatusCode,
                    warning = "DNS Rebinding possible - L'IP peut changer!",
                    content = (await response.Content.ReadAsStringAsync()).Substring(0, (int)Math.Min(500, response.Content.Headers.ContentLength ?? 0))
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Interaction avec Redis via Gopher
        [HttpPost]
        public async Task<IActionResult> TestRedis(string command)
        {
            if (string.IsNullOrEmpty(command))
                command = "INFO";

            try
            {
                // VULNÉRABLE : Construit une URL gopher pour Redis
                var gopherUrl = $"gopher://localhost:6379/_{Uri.EscapeDataString(command + "\r\n")}";

                // Note: .NET HttpClient ne supporte pas gopher:// nativement
                // Mais d'autres langages/frameworks le font
                return Json(new
                {
                    success = true,
                    protocol = "gopher://",
                    targetService = "Redis",
                    command = command,
                    gopherUrl = gopherUrl,
                    warning = "Gopher permet d'interagir avec Redis!",
                    exampleCommands = new[]
                    {
                        "SET key value",
                        "GET key",
                        "FLUSHALL",
                        "CONFIG SET dir /var/www/",
                        "CONFIG SET dbfilename shell.php"
                    },
                    note = ".NET ne supporte pas gopher:// mais d'autres frameworks oui"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Blind SSRF avec timing
        [HttpPost]
        public async Task<IActionResult> BlindCheck(string target)
        {
            if (string.IsNullOrEmpty(target))
                return Json(new { success = false, error = "Cible requise" });

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                // VULNÉRABLE : Même sans retour de contenu, le timing révèle des infos
                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);

                try
                {
                    // La requête est faite mais on ne retourne pas le contenu
                    await httpClient.GetAsync(target);
                    stopwatch.Stop();

                    return Json(new
                    {
                        success = true,
                        message = "Requête effectuée (pas de contenu retourné)",
                        responseTime = stopwatch.ElapsedMilliseconds,
                        timing = stopwatch.ElapsedMilliseconds switch
                        {
                            < 100 => "Très rapide - Service local?",
                            < 500 => "Rapide - Réseau local?",
                            < 2000 => "Normal - Internet?",
                            _ => "Lent - Timeout ou service distant?"
                        },
                        warning = "Blind SSRF - Le timing révèle l'existence du service!"
                    });
                }
                catch (TaskCanceledException)
                {
                    stopwatch.Stop();
                    return Json(new
                    {
                        success = true,
                        message = "Timeout",
                        responseTime = stopwatch.ElapsedMilliseconds,
                        inference = "Service inexistant ou filtré"
                    });
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return Json(new
                {
                    success = false,
                    error = ex.Message,
                    responseTime = stopwatch.ElapsedMilliseconds
                });
            }
        }

        // VULNÉRABLE : Parser confusion
        [HttpPost]
        public async Task<IActionResult> TestParserConfusion(string url)
        {
            if (string.IsNullOrEmpty(url))
                return Json(new { success = false, error = "URL requise" });

            try
            {
                // VULNÉRABLE : Différents parseurs peuvent interpréter l'URL différemment
                var uri = new Uri(url);

                // Parser .NET
                var dotnetParsing = new
                {
                    scheme = uri.Scheme,
                    host = uri.Host,
                    port = uri.Port,
                    path = uri.PathAndQuery,
                    userInfo = uri.UserInfo,
                    authority = uri.Authority
                };

                // Validation basique qui peut être contournée
                if (uri.Host == "localhost" || uri.Host == "127.0.0.1")
                {
                    return Json(new
                    {
                        success = false,
                        error = "localhost bloqué",
                        hint = "Essayez: http://google.com#@localhost:8080/"
                    });
                }

                // VULNÉRABLE : La requête réelle peut aller ailleurs
                var httpClient = _httpClientFactory.CreateClient();
                var response = await httpClient.GetAsync(url);

                return Json(new
                {
                    success = true,
                    parsing = dotnetParsing,
                    actualRequest = url,
                    statusCode = (int)response.StatusCode,
                    warning = "Parser confusion - L'URL peut être interprétée différemment!",
                    confusionExamples = new[]
                    {
                        "http://expected.com#@internal.com/",
                        "http://expected.com@internal.com/",
                        "http://internal.com.expected.com/",
                        "http://expected.com\\@internal.com/",
                        "http://expected.com%0d%0a%0d%0aGET%20/admin"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : SSRF via avatar/image URL
        [HttpPost]
        public async Task<IActionResult> UpdateAvatar(string avatarUrl)
        {
            if (string.IsNullOrEmpty(avatarUrl))
                return Json(new { success = false, error = "URL d'avatar requise" });

            try
            {
                // VULNÉRABLE : Télécharge l'avatar depuis n'importe quelle URL
                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(30); // Long timeout pour gros fichiers

                var response = await httpClient.GetAsync(avatarUrl);
                var contentType = response.Content.Headers.ContentType?.ToString() ?? "";

                // VULNÉRABLE : Vérifie le content-type APRÈS avoir fait la requête
                if (!contentType.StartsWith("image/"))
                {
                    return Json(new
                    {
                        success = false,
                        error = "Pas une image",
                        actualContentType = contentType,
                        hint = "Mais la requête a déjà été faite!"
                    });
                }

                var imageBytes = await response.Content.ReadAsByteArrayAsync();

                return Json(new
                {
                    success = true,
                    avatarUrl = avatarUrl,
                    size = imageBytes.Length,
                    contentType = contentType,
                    warning = "SSRF via avatar - Peut scanner/accéder aux ressources internes!",
                    metadata = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
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
                    "POST /SSRF/FetchUrl - Récupération d'URL sans validation",
                    "GET /SSRF/CheckMetadata - Accès aux métadonnées cloud",
                    "POST /SSRF/ScanPort - Scanner de ports interne",
                    "POST /SSRF/FetchResource - Support multi-protocoles (file://, gopher://)",
                    "POST /SSRF/RegisterWebhook - Webhook avec SSRF",
                    "POST /SSRF/FetchWithBypass - Contournement de blacklist",
                    "GET /SSRF/ProxyImage - Proxy d'images vulnérable",
                    "POST /SSRF/GeneratePDF - SSRF via génération PDF",
                    "POST /SSRF/CheckDomain - DNS Rebinding",
                    "POST /SSRF/TestRedis - Interaction Redis via Gopher",
                    "POST /SSRF/BlindCheck - Blind SSRF avec timing",
                    "POST /SSRF/TestParserConfusion - Confusion de parseur URL",
                    "POST /SSRF/UpdateAvatar - SSRF via URL d'avatar"
                },
                vulnerabilities = new[]
                {
                    "No URL validation",
                    "Access to internal resources",
                    "Cloud metadata exposure",
                    "Protocol smuggling",
                    "Blacklist bypass",
                    "Port scanning",
                    "File system access",
                    "PDF generator SSRF",
                    "DNS rebinding",
                    "Redis interaction via Gopher",
                    "Blind SSRF timing attacks",
                    "Parser confusion",
                    "Avatar/Image URL SSRF"
                },
                commonTargets = new[]
                {
                    "http://localhost/admin",
                    "http://127.0.0.1:8080",
                    "http://169.254.169.254/",
                    "http://192.168.1.1",
                    "http://10.0.0.1",
                    "file:///etc/passwd",
                    "file:///c:/windows/win.ini",
                    "gopher://localhost:6379/",
                    "dict://localhost:11211/",
                    "http://metadata.google.internal/",
                    "http://instance-data/latest/"
                }
            });
        }
    }

    // Modèle
    public class SSRFResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}