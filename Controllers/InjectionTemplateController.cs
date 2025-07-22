using System.CodeDom.Compiler;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.CSharp;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionTemplateController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _environment;

        public InjectionTemplateController(IWebHostEnvironment environment)
        {
            _environment = environment;

            _attackInfos = new()
            {
                ["code-execution"] = new AttackInfo
                {
                    Description = "Compilation et exécution de code C# arbitraire via CSharpCodeProvider.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Code_Injection",
                    RiskLevel = "Critical",
                    PayloadExample = "System.Diagnostics.Process.Start(\"calc.exe\");",
                    ErrorExplanation = "Le code utilisateur est compilé et exécuté sans sandbox."
                },
                ["string-interpolation"] = new AttackInfo
                {
                    Description = "Interpolation de string non sécurisée permettant l'évaluation d'expressions.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
                    RiskLevel = "High",
                    PayloadExample = "${System.Environment.UserName} - ${System.Environment.MachineName}",
                    ErrorExplanation = "Les expressions dans les strings sont évaluées dynamiquement."
                },
                ["reflection-injection"] = new AttackInfo
                {
                    Description = "Utilisation de la réflexion pour invoquer des méthodes dangereuses.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
                    RiskLevel = "Critical",
                    PayloadExample = "System.Reflection.Assembly.Load(\"System.Diagnostics.Process\").GetType(\"System.Diagnostics.Process\").GetMethod(\"Start\")",
                    ErrorExplanation = "La réflexion permet d'accéder à n'importe quelle API système."
                },
                ["file-read"] = new AttackInfo
                {
                    Description = "Lecture de fichiers arbitraires et exécution comme code.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Path_Traversal",
                    RiskLevel = "High",
                    PayloadExample = "../../appsettings.json",
                    ErrorExplanation = "Permet la lecture et l'exécution de fichiers sensibles."
                },
                ["dynamic-method"] = new AttackInfo
                {
                    Description = "Création de méthodes dynamiques permettant l'exécution de code.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Code_Injection",
                    RiskLevel = "Critical",
                    PayloadExample = "new System.Reflection.Emit.DynamicMethod(\"Exploit\", typeof(void), null)",
                    ErrorExplanation = "Les méthodes dynamiques bypassent les restrictions de sécurité."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<TemplateResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<TemplateResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<TemplateResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<TemplateResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new TemplateResult
                {
                    AttackType = attackType,
                    TemplateContent = payload,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les vraies vulnérabilités."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // Vulnérable : Compilation et exécution de code C#
        [HttpPost]
        public IActionResult ExecuteCode(string code)
        {
            try
            {
                // VULNÉRABLE : Compilation de code arbitraire
                var provider = new CSharpCodeProvider();
                var parameters = new CompilerParameters
                {
                    GenerateInMemory = true,
                    GenerateExecutable = false,
                    IncludeDebugInformation = false
                };

                // Références dangereuses
                parameters.ReferencedAssemblies.Add("System.dll");
                parameters.ReferencedAssemblies.Add("System.Core.dll");
                parameters.ReferencedAssemblies.Add("mscorlib.dll");

                var source = $@"
                    using System;
                    using System.IO;
                    using System.Diagnostics;
                    using System.Reflection;
                    
                    public class DynamicCode
                    {{
                        public static string Execute()
                        {{
                            try {{
                                {code}
                                return ""Code executed successfully"";
                            }}
                            catch(Exception ex) {{
                                return ""Error: "" + ex.Message;
                            }}
                        }}
                    }}";

                var results = provider.CompileAssemblyFromSource(parameters, source);

                if (!results.Errors.HasErrors)
                {
                    var assembly = results.CompiledAssembly;
                    var type = assembly.GetType("DynamicCode");
                    var method = type.GetMethod("Execute");
                    var output = method.Invoke(null, null);

                    return Json(new
                    {
                        success = true,
                        output = output?.ToString(),
                        warning = "Code C# arbitraire compilé et exécuté!"
                    });
                }
                else
                {
                    var errors = new StringBuilder();
                    foreach (CompilerError error in results.Errors)
                    {
                        errors.AppendLine(error.ErrorText);
                    }
                    return Json(new { success = false, errors = errors.ToString() });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Évaluation d'expressions dans des strings
        [HttpPost]
        public IActionResult EvaluateExpression(string template)
        {
            try
            {
                // VULNÉRABLE : Évaluation d'expressions utilisateur
                var pattern = @"\$\{([^}]+)\}";
                var evaluatedTemplate = Regex.Replace(template, pattern, match =>
                {
                    var expression = match.Groups[1].Value;

                    // Compilation d'expression dynamique - DANGEREUX
                    var provider = new CSharpCodeProvider();
                    var parameters = new CompilerParameters { GenerateInMemory = true };

                    var evalCode = $@"
                        using System;
                        public class Eval {{
                            public static object EvaluateExpression() {{
                                return {expression};
                            }}
                        }}";

                    var results = provider.CompileAssemblyFromSource(parameters, evalCode);
                    if (!results.Errors.HasErrors)
                    {
                        var assembly = results.CompiledAssembly;
                        var type = assembly.GetType("Eval");
                        var method = type.GetMethod("EvaluateExpression");
                        var result = method.Invoke(null, null);
                        return result?.ToString() ?? "";
                    }

                    return "ERROR";
                });

                return Json(new
                {
                    success = true,
                    original = template,
                    evaluated = evaluatedTemplate,
                    warning = "Expressions évaluées dynamiquement!"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Utilisation de la réflexion
        [HttpPost]
        public IActionResult InvokeViaReflection(string typeName, string methodName, string parameters)
        {
            try
            {
                // VULNÉRABLE : Invocation de méthodes via réflexion
                var type = Type.GetType(typeName); // Dangereux - permet n'importe quel type

                if (type != null)
                {
                    var method = type.GetMethod(methodName);
                    if (method != null)
                    {
                        object result = null;
                        if (method.IsStatic)
                        {
                            // Parsing basique des paramètres (vulnérable)
                            object[] args = string.IsNullOrEmpty(parameters) ? null : new object[] { parameters };
                            result = method.Invoke(null, args);
                        }

                        return Json(new
                        {
                            success = true,
                            type = typeName,
                            method = methodName,
                            result = result?.ToString(),
                            warning = "Méthode invoquée via réflexion!"
                        });
                    }
                }

                return Json(new { success = false, error = "Type ou méthode non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Lecture et exécution de fichier
        [HttpPost]
        public IActionResult ReadAndExecute(string filePath)
        {
            try
            {
                // VULNÉRABLE : Path traversal
                var fullPath = Path.Combine(_environment.ContentRootPath, filePath);

                if (System.IO.File.Exists(fullPath))
                {
                    var content = System.IO.File.ReadAllText(fullPath); // Lecture non sécurisée

                    // Si c'est du C#, on tente de le compiler
                    if (filePath.EndsWith(".cs") || content.Contains("using System"))
                    {
                        return ExecuteCode(content);
                    }

                    return Json(new
                    {
                        success = true,
                        path = filePath,
                        content = content,
                        warning = "Fichier lu avec path traversal possible!"
                    });
                }

                return Json(new { success = false, error = "Fichier non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Création de méthode dynamique
        [HttpPost]
        public IActionResult CreateDynamicMethod(string methodCode)
        {
            try
            {
                // VULNÉRABLE : Génération de code IL dynamique
                var dynamicMethod = new System.Reflection.Emit.DynamicMethod(
                    "DynamicExploit",
                    typeof(string),
                    new Type[] { },
                    typeof(InjectionTemplateController).Module);

                var il = dynamicMethod.GetILGenerator();

                // Exemple simple mais dangereux
                il.Emit(System.Reflection.Emit.OpCodes.Ldstr, "Dynamic method executed!");
                il.Emit(System.Reflection.Emit.OpCodes.Ret);

                var func = (Func<string>)dynamicMethod.CreateDelegate(typeof(Func<string>));
                var result = func();

                return Json(new
                {
                    success = true,
                    result = result,
                    warning = "Méthode dynamique créée et exécutée!"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Vulnérable : Désérialisation non sécurisée
        [HttpPost]
        public IActionResult UnsafeDeserialize(string serializedData)
        {
            try
            {
                // VULNÉRABLE : BinaryFormatter (obsolète et dangereux)
#pragma warning disable SYSLIB0011
                var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
#pragma warning restore SYSLIB0011

                var bytes = Convert.FromBase64String(serializedData);
                using (var stream = new MemoryStream(bytes))
                {
                    var obj = formatter.Deserialize(stream); // Désérialisation dangereuse

                    return Json(new
                    {
                        success = true,
                        type = obj?.GetType().Name,
                        warning = "Objet désérialisé sans validation!"
                    });
                }
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
                    "POST /InjectionTemplate/ExecuteCode",
                    "POST /InjectionTemplate/EvaluateExpression",
                    "POST /InjectionTemplate/InvokeViaReflection",
                    "POST /InjectionTemplate/ReadAndExecute",
                    "POST /InjectionTemplate/CreateDynamicMethod",
                    "POST /InjectionTemplate/UnsafeDeserialize"
                },
                vulnerabilities = new[]
                {
                    "Code compilation (CSharpCodeProvider)",
                    "Expression evaluation",
                    "Reflection abuse",
                    "Path traversal",
                    "Dynamic method creation",
                    "Unsafe deserialization (BinaryFormatter)"
                }
            });
        }
    }

    // Modèle simplifié
    public class TemplateResult
    {
        public string AttackType { get; set; } = string.Empty;
        public string TemplateContent { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}