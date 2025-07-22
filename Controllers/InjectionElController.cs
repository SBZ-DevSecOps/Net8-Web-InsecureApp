using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Linq.Expressions;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionElController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly Dictionary<string, object> _context;

        public InjectionElController()
        {
            // Initialiser le contexte avec des objets simulés
            _context = InitializeContext();

            _attackInfos = new()
            {
                ["basic"] = new AttackInfo
                {
                    Description = "Injection d'expressions .NET basiques permettant l'évaluation de code C# simple et l'accès aux propriétés d'objets.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/dotnet/api/system.linq.expressions",
                    RiskLevel = "Medium",
                    PayloadExample = "7*7 - User.Name.ToUpper() - DateTime.Now.Year",
                    ErrorExplanation = "L'expression peut échouer si la syntaxe C# est invalide ou si les objets référencés n'existent pas."
                },
                ["linq"] = new AttackInfo
                {
                    Description = "Injection LINQ permettant des requêtes complexes sur les collections et l'accès aux données en mémoire.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/linq/",
                    RiskLevel = "High",
                    PayloadExample = "users.Where(u => u.Role == \"Admin\").Select(u => u.Password)",
                    ErrorExplanation = "Les expressions LINQ peuvent exposer des données sensibles si le contexte n'est pas correctement isolé."
                },
                ["reflection"] = new AttackInfo
                {
                    Description = "Utilisation de la réflexion .NET pour accéder aux types, méthodes et assemblies du système.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/dotnet/framework/reflection-and-codedom/reflection",
                    RiskLevel = "Critical",
                    PayloadExample = "typeof(System.Diagnostics.Process).GetMethod(\"Start\").Invoke(null, new[] { \"calc.exe\" })",
                    ErrorExplanation = "La réflexion peut être limitée par les politiques de sécurité CAS ou les permissions du domaine d'application."
                },
                ["dynamic"] = new AttackInfo
                {
                    Description = "Compilation dynamique de code C# permettant l'exécution de code arbitraire via CSharpCodeProvider ou Roslyn.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/dotnet/api/microsoft.csharp.csharpcodeprovider",
                    RiskLevel = "Critical",
                    PayloadExample = "new CSharpCodeProvider().CompileAssemblyFromSource(parameters, \"using System; class C { public static void M() { System.Diagnostics.Process.Start(\\\"cmd\\\"); } }\")",
                    ErrorExplanation = "La compilation dynamique peut être désactivée ou restreinte dans les environnements sécurisés."
                },
                ["interpolation"] = new AttackInfo
                {
                    Description = "Exploitation de l'interpolation de chaînes C# ($\"\") pour injecter des expressions complexes.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/tokens/interpolated",
                    RiskLevel = "High",
                    PayloadExample = "$\"User: {user.Name} - Password: {user.Password} - Time: {DateTime.Now:yyyy-MM-dd}\"",
                    ErrorExplanation = "L'interpolation de chaînes peut exposer des données sensibles si les objets du contexte ne sont pas filtrés."
                },
                ["dataBinding"] = new AttackInfo
                {
                    Description = "Injection dans les expressions de data binding ASP.NET permettant l'accès aux propriétés et méthodes.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/aspnet/web-forms/overview/data-access/displaying-data/using-templatefields-in-the-gridview-control",
                    RiskLevel = "High",
                    PayloadExample = "<%# Eval(\"Password\") %> - <%# System.IO.File.ReadAllText(@\"C:\\Windows\\win.ini\") %>",
                    ErrorExplanation = "Les expressions de data binding peuvent être limitées par la configuration de trust level."
                },
                ["powershell"] = new AttackInfo
                {
                    Description = "Exécution de scripts PowerShell via System.Management.Automation permettant l'accès système complet.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/powershell/scripting/developer/hosting/adding-and-invoking-commands",
                    RiskLevel = "Critical",
                    PayloadExample = "PowerShell.Create().AddScript(\"Get-Process | Stop-Process\").Invoke()",
                    ErrorExplanation = "PowerShell peut être désactivé par les politiques d'exécution ou absent du système."
                },
                ["ironPython"] = new AttackInfo
                {
                    Description = "Injection de code Python via IronPython permettant l'exécution de scripts Python dans .NET.",
                    LearnMoreUrl = "https://ironpython.net/",
                    RiskLevel = "High",
                    PayloadExample = "engine.Execute(\"import os; os.system('calc')\")",
                    ErrorExplanation = "IronPython doit être installé et peut être restreint par les permissions du domaine d'application."
                }
            };
        }

        private Dictionary<string, object> InitializeContext()
        {
            return new Dictionary<string, object>
            {
                ["user"] = new User
                {
                    Name = "admin",
                    Email = "admin@example.com",
                    Password = "P@ssw0rd123!",
                    Role = "ROLE_ADMIN",
                    ApiKey = "sk_live_51234567890"
                },
                ["session"] = new SessionInfo
                {
                    Id = "SESSION_1234567890",
                    CreatedAt = DateTime.Now.AddMinutes(-30),
                    LastAccess = DateTime.Now,
                    Attributes = new Dictionary<string, object>
                    {
                        ["authenticated"] = true,
                        ["permissions"] = new[] { "READ", "WRITE", "DELETE" }
                    }
                },
                ["application"] = new ApplicationScope
                {
                    DatabaseUrl = "Server=localhost;Database=Production;User Id=sa;Password=P@ssw0rd123!",
                    ApiEndpoint = "https://api.internal/v1/",
                    SecretKey = "ThisIsAVerySecretKey123!",
                    Environment = "PRODUCTION"
                },
                ["request"] = new RequestInfo
                {
                    RemoteAddr = "10.0.0.100",
                    UserAgent = "Mozilla/5.0",
                    Headers = new Dictionary<string, string>
                    {
                        ["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        ["X-API-Key"] = "internal-api-key-2024"
                    }
                },
                ["system"] = new SystemInfo
                {
                    OperatingSystem = Environment.OSVersion.ToString(),
                    DotNetVersion = Environment.Version.ToString(),
                    MachineName = Environment.MachineName,
                    ProcessorCount = Environment.ProcessorCount
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<ElResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<ElResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            if (string.IsNullOrEmpty(attackType))
            {
                var emptyModel = new VulnerabilityViewModel<ElResult>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<ElResult>(),
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                var results = new List<ElResult>();

                // Évaluer l'expression EL vulnérable
                var result = EvaluateExpression(payload, attackType);
                results.Add(result);

                var model = VulnerabilityViewModel<ElResult>.WithResults(payload, attackType, results, payload);
                model.AttackInfos = _attackInfos;

                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<ElResult>
                {
                    AttackType = attackType,
                    Payload = payload,
                    ErrorMessage = $"Erreur EL : {ex.Message}",
                    AttackInfos = _attackInfos
                };
                return View(errorModel);
            }
        }

        private ElResult EvaluateExpression(string expression, string attackType)
        {
            var result = new ElResult
            {
                Expression = expression,
                EvaluationTime = 0,
                Success = false
            };

            var startTime = DateTime.Now;

            try
            {
                // Simuler l'évaluation selon le type d'attaque
                switch (attackType)
                {
                    case "basic":
                        result = EvaluateBasicExpression(expression);
                        break;

                    case "linq":
                        result = EvaluateLinqExpression(expression);
                        result.SecurityImpact = "Exposition de données via requêtes LINQ!";
                        break;

                    case "reflection":
                        result = EvaluateDotNetReflection(expression);
                        result.ReflectionUsed = true;
                        result.ClassesAccessed.Add("System.Diagnostics.Process");
                        result.ClassesAccessed.Add("System.IO.File");
                        result.SecurityImpact = "Accès réflexion .NET - Exécution de code possible!";
                        break;

                    case "dynamic":
                        result.EvaluatedValue = "Compilation dynamique C# simulée";
                        result.ExpressionType = "CSharpCodeProvider";
                        result.SecurityImpact = "Remote Code Execution via compilation dynamique!";
                        break;

                    case "interpolation":
                        result = EvaluateStringInterpolation(expression);
                        result.ExpressionType = "C# String Interpolation";
                        break;

                    case "dataBinding":
                        result.EvaluatedValue = "Data Binding ASP.NET exécuté";
                        result.ExpressionType = "ASP.NET Data Binding";
                        result.FilesAccessed.Add(@"C:\Windows\win.ini");
                        break;

                    case "powershell":
                        result.EvaluatedValue = "Script PowerShell exécuté";
                        result.ExpressionType = "PowerShell";
                        result.ProcessesStarted.Add("powershell.exe");
                        result.SecurityImpact = "Exécution PowerShell - Accès système complet!";
                        break;

                    case "ironPython":
                        result.EvaluatedValue = "Script IronPython exécuté";
                        result.ExpressionType = "IronPython";
                        result.ProcessesStarted.Add("calc.exe");
                        break;
                }

                // Détecter les patterns dangereux
                DetectDangerousPatterns(expression, result);

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.EvaluatedValue = $"Erreur: {ex.Message}";
                result.Errors.Add(ex.Message);
            }

            result.EvaluationTime = (DateTime.Now - startTime).TotalMilliseconds;
            return result;
        }

        private ElResult EvaluateBasicExpression(string expression)
        {
            var result = new ElResult { Expression = expression };

            // Simuler l'évaluation d'expressions C# basiques
            var evaluated = expression;

            // Évaluer les expressions mathématiques simples
            evaluated = Regex.Replace(evaluated, @"(\d+)\s*\*\s*(\d+)", m =>
            {
                if (int.TryParse(m.Groups[1].Value, out int a) && int.TryParse(m.Groups[2].Value, out int b))
                {
                    return (a * b).ToString();
                }
                return m.Value;
            });

            // Remplacer DateTime.Now
            evaluated = evaluated.Replace("DateTime.Now", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            evaluated = evaluated.Replace("DateTime.Now.Year", DateTime.Now.Year.ToString());

            // Évaluer les accès aux propriétés User.Name, etc.
            foreach (var ctxItem in _context)
            {
                if (ctxItem.Value is User user)
                {
                    evaluated = evaluated.Replace("User.Name", user.Name);
                    evaluated = evaluated.Replace("User.Password", user.Password);
                    evaluated = evaluated.Replace("User.Name.ToUpper()", user.Name.ToUpper());

                    if (evaluated.Contains("Password"))
                    {
                        result.SensitiveDataExposed.Add("User.Password", user.Password);
                    }
                }
            }

            result.EvaluatedValue = evaluated;
            result.ExpressionType = "C# Expression";
            return result;
        }

        private ElResult EvaluateLinqExpression(string expression)
        {
            var result = new ElResult
            {
                Expression = expression,
                ExpressionType = "LINQ"
            };

            // Simuler une requête LINQ sur les utilisateurs
            if (expression.Contains("Where") && expression.Contains("Admin"))
            {
                var adminUser = _context["user"] as User;
                result.EvaluatedValue = $"[{{ Name: '{adminUser?.Name}', Password: '{adminUser?.Password}', ApiKey: '{adminUser?.ApiKey}' }}]";
                result.SensitiveDataExposed.Add("Admin.Password", adminUser?.Password ?? "");
                result.SensitiveDataExposed.Add("Admin.ApiKey", adminUser?.ApiKey ?? "");
                result.MethodsInvoked.Add("Where()");
                result.MethodsInvoked.Add("Select()");
            }

            return result;
        }

        private ElResult EvaluateDotNetReflection(string expression)
        {
            var result = new ElResult
            {
                Expression = expression,
                ExpressionType = ".NET Reflection"
            };

            // Simuler l'utilisation de la réflexion .NET
            if (expression.Contains("Process") && expression.Contains("Start"))
            {
                result.ProcessesStarted.Add("calc.exe");
                result.EvaluatedValue = "Process started via reflection";
                result.MethodsInvoked.Add("typeof()");
                result.MethodsInvoked.Add("GetMethod()");
                result.MethodsInvoked.Add("Invoke()");
            }

            // Accès aux assemblies
            result.AssembliesLoaded.Add("System.Diagnostics");
            result.AssembliesLoaded.Add("mscorlib");

            return result;
        }

        private ElResult EvaluateStringInterpolation(string expression)
        {
            var result = new ElResult
            {
                Expression = expression,
                ExpressionType = "C# String Interpolation"
            };

            var user = _context["user"] as User;
            result.EvaluatedValue = $"User: {user?.Name} - Password: {user?.Password} - Time: {DateTime.Now:yyyy-MM-dd}";

            if (expression.Contains("Password") || expression.Contains("ApiKey"))
            {
                result.SensitiveDataExposed.Add("Password", user?.Password ?? "");
                result.SensitiveDataExposed.Add("ApiKey", user?.ApiKey ?? "");
            }

            return result;
        }



        private ElResult EvaluateMethodInvocation(string expression)
        {
            // Méthode non utilisée dans le contexte .NET
            return new ElResult { Expression = expression };
        }

        private ElResult EvaluateReflection(string expression)
        {
            // Remplacée par EvaluateDotNetReflection
            return EvaluateDotNetReflection(expression);
        }

        private ElResult EvaluateNestedExpression(string expression)
        {
            // Méthode non utilisée dans le contexte .NET
            return new ElResult { Expression = expression };
        }

        private ElResult EvaluatePolyglot(string expression)
        {
            // Méthode non utilisée dans le contexte .NET
            return new ElResult { Expression = expression };
        }

        private void DetectDangerousPatterns(string expression, ElResult result)
        {
            var patterns = new Dictionary<string, string>
            {
                [@"Process\.Start|ProcessStartInfo"] = "Exécution de processus",
                [@"Assembly\.Load|GetType|Activator"] = "Chargement dynamique",
                [@"File\.ReadAllText|Directory\.GetFiles"] = "Accès au système de fichiers",
                [@"WebClient|HttpClient|WebRequest"] = "Requêtes réseau",
                [@"CSharpCodeProvider|CompileAssemblyFromSource"] = "Compilation dynamique",
                [@"PowerShell|AddScript|Invoke"] = "Exécution PowerShell",
                [@"IronPython|Execute"] = "Exécution de scripts",
                [@"SqlCommand|ExecuteNonQuery"] = "Requêtes SQL",
                [@"reflection|GetMethod|Invoke"] = "Invocation par réflexion",
                [@"Marshal|DllImport|extern"] = "Interop non managé",
                [@"unsafe|fixed|stackalloc"] = "Code non sécurisé",
                [@"Expression\.Compile|DynamicMethod"] = "Génération de code dynamique"
            };

            foreach (var pattern in patterns)
            {
                if (Regex.IsMatch(expression, pattern.Key, RegexOptions.IgnoreCase))
                {
                    result.DangerousPatterns.Add(pattern.Value);
                }
            }
        }

        // Classes de contexte simulées
        private class User
        {
            public string Name { get; set; } = "";
            public string Email { get; set; } = "";
            public string Password { get; set; } = "";
            public string Role { get; set; } = "";
            public string ApiKey { get; set; } = "";
        }

        private class SessionInfo
        {
            public string Id { get; set; } = "";
            public DateTime CreatedAt { get; set; }
            public DateTime LastAccess { get; set; }
            public Dictionary<string, object> Attributes { get; set; } = new();
        }

        private class ApplicationScope
        {
            public string DatabaseUrl { get; set; } = "";
            public string ApiEndpoint { get; set; } = "";
            public string SecretKey { get; set; } = "";
            public string Environment { get; set; } = "";
        }

        private class RequestInfo
        {
            public string RemoteAddr { get; set; } = "";
            public string UserAgent { get; set; } = "";
            public Dictionary<string, string> Headers { get; set; } = new();
        }

        private class SystemInfo
        {
            public string OperatingSystem { get; set; } = "";
            public string DotNetVersion { get; set; } = "";
            public string MachineName { get; set; } = "";
            public int ProcessorCount { get; set; }
        }
    }

    // Modèle pour les résultats EL
    public class ElResult
    {
        public string Expression { get; set; } = string.Empty;
        public string EvaluatedValue { get; set; } = string.Empty;
        public string ExpressionType { get; set; } = string.Empty;
        public double EvaluationTime { get; set; }
        public bool Success { get; set; }
        public bool ReflectionUsed { get; set; }
        public List<string> ContextAccessed { get; set; } = new();
        public Dictionary<string, string> SensitiveDataExposed { get; set; } = new();
        public List<string> MethodsInvoked { get; set; } = new();
        public List<string> ClassesAccessed { get; set; } = new();
        public List<string> ProcessesStarted { get; set; } = new();
        public List<string> PathsAccessed { get; set; } = new();
        public List<string> FilesAccessed { get; set; } = new();
        public List<string> AssembliesLoaded { get; set; } = new();
        public Dictionary<string, string> EnvironmentVariables { get; set; } = new();
        public Dictionary<string, string> SystemProperties { get; set; } = new();
        public List<string> CompatibleEngines { get; set; } = new();
        public List<string> BypassTechniquesUsed { get; set; } = new();
        public List<string> DangerousPatterns { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public string? SecurityImpact { get; set; }
    }
}