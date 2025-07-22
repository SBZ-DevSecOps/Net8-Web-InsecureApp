using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionCommandController : Controller
    {
        private readonly Dictionary<string, string> _attackDescriptions = new()
        {
            ["basic"] = "Injection de commande basique utilisant des séparateurs comme ';', '&&', '||' pour enchaîner des commandes. " +
                       "Permet d'exécuter des commandes arbitraires sur le système. " +
                       "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["pipe"] = "Injection utilisant des pipes ('|') pour rediriger la sortie d'une commande vers une autre, " +
                      "permettant l'exécution de commandes supplémentaires. " +
                      "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["background"] = "Injection utilisant '&' pour exécuter des commandes en arrière-plan, " +
                           "permettant l'exécution asynchrone de code malveillant. " +
                           "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["redirection"] = "Injection utilisant les redirections ('>', '>>', '<') pour lire/écrire des fichiers " +
                            "ou rediriger des flux, permettant l'accès aux données sensibles. " +
                            "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["substitution"] = "Injection utilisant la substitution de commandes ('`', '$()') pour exécuter " +
                             "des commandes dans une sous-coquille et utiliser leur résultat. " +
                             "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["escape"] = "Injection utilisant l'échappement ou des caractères spéciaux pour contourner " +
                        "les protections basiques et injecter des commandes. " +
                        "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["blind"] = "Injection aveugle où les résultats ne sont pas directement visibles, " +
                       "utilisant des techniques de temporisation ou de redirection pour confirmer l'exécution. " +
                       "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["time"] = "Injection temporelle utilisant des commandes de délai (sleep, timeout) " +
                      "pour détecter les vulnérabilités par mesure du temps de réponse. " +
                      "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>."
        };

        private readonly Dictionary<string, string> _payloadExamples = new()
        {
            // Injection basique avec séparateur de commandes
            ["basic"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt; dir" : "test.txt; ls -la",

            // Injection avec pipe
            ["pipe"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt | dir" : "test.txt | ls -la",

            // Injection avec exécution en arrière-plan
            ["background"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt & dir &" : "test.txt & ls -la &",

            // Injection avec redirection
            ["redirection"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt > output.txt & type output.txt" : "test.txt > /tmp/output.txt; cat /tmp/output.txt",

            // Injection avec substitution de commandes
            ["substitution"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "$(dir)" : "$(ls -la)",

            // Injection avec échappement
            ["escape"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt\" & dir & echo \"" : "test.txt'; ls -la; echo '",

            // Injection aveugle (création de fichier)
            ["blind"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt & echo vulnerable > proof.txt" : "test.txt; touch /tmp/proof.txt",

            // Injection temporelle
            ["time"] = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "test.txt & timeout 5" : "test.txt; sleep 5"
        };

        private readonly Dictionary<string, string> _errorExplanations = new()
        {
            ["basic"] = "L'injection basique peut échouer si les séparateurs de commandes sont filtrés ou si le shell n'est pas accessible.",
            ["pipe"] = "Les pipes peuvent être bloqués ou le système peut ne pas interpréter correctement la redirection.",
            ["background"] = "L'exécution en arrière-plan peut être bloquée par les politiques de sécurité du système ou du processus.",
            ["redirection"] = "Les redirections peuvent échouer si les permissions de fichier sont insuffisantes ou si les chemins sont restreints.",
            ["substitution"] = "La substitution de commandes peut être désactivée ou le shell peut ne pas supporter cette syntaxe.",
            ["escape"] = "L'échappement peut échouer si l'application utilise des protections ou un parsing plus robuste.",
            ["blind"] = "L'injection aveugle peut sembler échouer mais peut avoir réussi. Vérifiez la création de fichiers ou d'autres effets de bord.",
            ["time"] = "Les commandes de temporisation peuvent être bloquées ou le délai peut ne pas être perceptible selon la configuration."
        };

        private readonly Dictionary<string, AttackInfo> _attackInfos;

        public InjectionCommandController()
        {
            // Initialiser les AttackInfos après les payloadExamples pour avoir les bonnes valeurs
            _attackInfos = new()
            {
                ["basic"] = new AttackInfo
                {
                    Description = "Injection de commande basique utilisant des séparateurs comme ';', '&&', '||' pour enchaîner des commandes. Permet d'exécuter des commandes arbitraires sur le système.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "High",
                    PayloadExample = _payloadExamples["basic"],
                    ErrorExplanation = "L'injection basique peut échouer si les séparateurs de commandes sont filtrés ou si le shell n'est pas accessible."
                },
                ["pipe"] = new AttackInfo
                {
                    Description = "Injection utilisant des pipes ('|') pour rediriger la sortie d'une commande vers une autre, permettant l'exécution de commandes supplémentaires.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "High",
                    PayloadExample = _payloadExamples["pipe"],
                    ErrorExplanation = "Les pipes peuvent être bloqués ou le système peut ne pas interpréter correctement la redirection."
                },
                ["background"] = new AttackInfo
                {
                    Description = "Injection utilisant '&' pour exécuter des commandes en arrière-plan, permettant l'exécution asynchrone de code malveillant.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "High",
                    PayloadExample = _payloadExamples["background"],
                    ErrorExplanation = "L'exécution en arrière-plan peut être bloquée par les politiques de sécurité du système ou du processus."
                },
                ["redirection"] = new AttackInfo
                {
                    Description = "Injection utilisant les redirections ('>', '>>', '<') pour lire/écrire des fichiers ou rediriger des flux, permettant l'accès aux données sensibles.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "Medium",
                    PayloadExample = _payloadExamples["redirection"],
                    ErrorExplanation = "Les redirections peuvent échouer si les permissions de fichier sont insuffisantes ou si les chemins sont restreints."
                },
                ["substitution"] = new AttackInfo
                {
                    Description = "Injection utilisant la substitution de commandes ('`', '$()') pour exécuter des commandes dans une sous-coquille et utiliser leur résultat.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "High",
                    PayloadExample = _payloadExamples["substitution"],
                    ErrorExplanation = "La substitution de commandes peut être désactivée ou le shell peut ne pas supporter cette syntaxe."
                },
                ["escape"] = new AttackInfo
                {
                    Description = "Injection utilisant l'échappement ou des caractères spéciaux pour contourner les protections basiques et injecter des commandes.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "Medium",
                    PayloadExample = _payloadExamples["escape"],
                    ErrorExplanation = "L'échappement peut échouer si l'application utilise des protections ou un parsing plus robuste."
                },
                ["blind"] = new AttackInfo
                {
                    Description = "Injection aveugle où les résultats ne sont pas directement visibles, utilisant des techniques de temporisation ou de redirection pour confirmer l'exécution.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "Medium",
                    PayloadExample = _payloadExamples["blind"],
                    ErrorExplanation = "L'injection aveugle peut sembler échouer mais peut avoir réussi. Vérifiez la création de fichiers ou d'autres effets de bord."
                },
                ["time"] = new AttackInfo
                {
                    Description = "Injection temporelle utilisant des commandes de délai (sleep, timeout) pour détecter les vulnérabilités par mesure du temps de réponse.",
                    LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                    RiskLevel = "Medium",
                    PayloadExample = _payloadExamples["time"],
                    ErrorExplanation = "Les commandes de temporisation peuvent être bloquées ou le délai peut ne pas être perceptible selon la configuration."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<CommandResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<CommandResult>(),
                AttackDescriptions = _attackDescriptions,
                PayloadExamples = _payloadExamples,
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<CommandResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<CommandResult>(),
                    AttackDescriptions = _attackDescriptions,
                    PayloadExamples = _payloadExamples,
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var startTime = DateTime.Now;
                var results = new List<CommandResult>();

                // Simulation d'une fonction vulnérable qui exécute des commandes système
                // Dans un vrai scénario, cela pourrait être une fonction de ping, de recherche de fichiers, etc.
                string command = attackType switch
                {
                    "basic" or "pipe" or "background" or "redirection" or "substitution" or "escape" or "blind" =>
                        BuildCommand(payload, attackType),
                    "time" => BuildCommand(payload, attackType),
                    _ => throw new ArgumentException("Type d'attaque inconnu")
                };

                // Exécution de la commande vulnérable
                var output = ExecuteCommand(command);
                var endTime = DateTime.Now;
                var executionTime = (endTime - startTime).TotalMilliseconds;

                results.Add(new CommandResult
                {
                    Command = command,
                    Output = output,
                    ExecutionTime = executionTime,
                    Success = !string.IsNullOrEmpty(output) || executionTime > 1000 // Considère les délais comme succès
                });

                var model = VulnerabilityViewModel<CommandResult>.WithResults(payload, attackType, results, command);
                model.AttackDescriptions = _attackDescriptions;
                model.PayloadExamples = _payloadExamples;
                model.ErrorExplanations = _errorExplanations;
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<CommandResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur lors de l'exécution : {ex.Message}",
                    AttackDescriptions = _attackDescriptions,
                    PayloadExamples = _payloadExamples,
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private string BuildCommand(string payload, string attackType)
        {
            // Simulation de différents contextes d'injection
            return attackType switch
            {
                "basic" or "pipe" or "background" or "redirection" or "substitution" or "escape" or "time" =>
                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? $"type {payload}"
                        : $"cat {payload}",
                "blind" =>
                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                        ? $"type {payload}"
                        : $"cat {payload}",
                _ => throw new ArgumentException("Type d'attaque non supporté")
            };
        }

        private string ExecuteCommand(string command)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    processInfo.FileName = "cmd.exe";
                    processInfo.Arguments = $"/c {command}";
                }
                else
                {
                    processInfo.FileName = "/bin/bash";
                    processInfo.Arguments = $"-c \"{command}\"";
                }

                using var process = Process.Start(processInfo);
                if (process == null) return "Erreur: Impossible de démarrer le processus";

                process.WaitForExit(10000); // Timeout de 10 secondes

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();

                if (!string.IsNullOrEmpty(error))
                {
                    return $"Output: {output}\nError: {error}";
                }

                return output;
            }
            catch (Exception ex)
            {
                return $"Exception: {ex.Message}";
            }
        }
    }

    // Modèle pour les résultats des commandes
    public class CommandResult
    {
        public string Command { get; set; } = string.Empty;
        public string Output { get; set; } = string.Empty;
        public double ExecutionTime { get; set; }
        public bool Success { get; set; }
    }
}