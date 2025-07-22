using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace InsecureAppWebNet8.Controllers
{
    public class DirectoryTraversalController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _env;
        private readonly string _uploadPath;
        private readonly string _documentsPath;

        public DirectoryTraversalController(IWebHostEnvironment env)
        {
            _env = env;
            _uploadPath = Path.Combine(_env.WebRootPath, "uploads");
            _documentsPath = Path.Combine(_env.WebRootPath, "documents");

            // Créer les répertoires s'ils n'existent pas
            Directory.CreateDirectory(_uploadPath);
            Directory.CreateDirectory(_documentsPath);

            _attackInfos = new()
            {
                ["basic-traversal"] = new AttackInfo
                {
                    Description = "Lecture de fichiers avec '../' pour remonter dans l'arborescence.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Path_Traversal",
                    RiskLevel = "Critical",
                    PayloadExample = "../../appsettings.json ou ..\\..\\Program.cs",
                    ErrorExplanation = "Aucune validation du chemin permet l'accès à tout le système."
                },
                ["download-files"] = new AttackInfo
                {
                    Description = "Téléchargement de fichiers arbitraires via paramètre non validé.",
                    LearnMoreUrl = "https://portswigger.net/web-security/file-path-traversal",
                    RiskLevel = "Critical",
                    PayloadExample = "?file=../../config/appsettings.json",
                    ErrorExplanation = "Le paramètre file permet de télécharger n'importe quel fichier."
                },
                ["include-files"] = new AttackInfo
                {
                    Description = "Inclusion de fichiers locaux permettant la lecture de code source.",
                    LearnMoreUrl = "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                    RiskLevel = "High",
                    PayloadExample = "?page=../../../../app/controllers/admin.cs",
                    ErrorExplanation = "L'inclusion de fichiers expose le code source et les secrets."
                },
                ["log-injection"] = new AttackInfo
                {
                    Description = "Injection dans les logs permettant de lire des fichiers via traversal.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Log_Injection",
                    RiskLevel = "Medium",
                    PayloadExample = "username=admin%0A../../etc/passwd",
                    ErrorExplanation = "Les logs peuvent être manipulés pour inclure d'autres fichiers."
                },
                ["zip-slip"] = new AttackInfo
                {
                    Description = "Extraction d'archives ZIP avec chemins relatifs malveillants.",
                    LearnMoreUrl = "https://snyk.io/research/zip-slip-vulnerability",
                    RiskLevel = "High",
                    PayloadExample = "Archive contenant: ../../evil.aspx",
                    ErrorExplanation = "L'extraction peut écraser des fichiers système."
                },
                ["encoding-bypass"] = new AttackInfo
                {
                    Description = "Contournement des filtres avec encodage URL ou Unicode.",
                    LearnMoreUrl = "https://owasp.org/www-community/Double_Encoding",
                    RiskLevel = "High",
                    PayloadExample = "%2e%2e%2f, %252e%252e%252f, ..%c0%af",
                    ErrorExplanation = "Les encodages multiples contournent les validations basiques."
                },
                ["null-byte"] = new AttackInfo
                {
                    Description = "Injection de null byte pour tronquer les extensions.",
                    LearnMoreUrl = "https://www.exploit-db.com/docs/english/14883-null-byte-injection.pdf",
                    RiskLevel = "High",
                    PayloadExample = "../../../../etc/passwd%00.jpg",
                    ErrorExplanation = "Le null byte termine la chaîne, ignorant l'extension."
                },
                ["template-injection"] = new AttackInfo
                {
                    Description = "Traversal via moteur de template pour lire des fichiers.",
                    LearnMoreUrl = "https://portswigger.net/research/server-side-template-injection",
                    RiskLevel = "High",
                    PayloadExample = "{{'/etc/passwd'|file_get_contents}}",
                    ErrorExplanation = "Les templates peuvent accéder au système de fichiers."
                },
                ["backup-files"] = new AttackInfo
                {
                    Description = "Accès aux fichiers de sauvegarde et temporaires.",
                    LearnMoreUrl = "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Backup_and_Unreferenced_Files",
                    RiskLevel = "Medium",
                    PayloadExample = "web.config~, .env.backup, database.sql.bak",
                    ErrorExplanation = "Les fichiers backup contiennent souvent des secrets."
                },
                ["windows-paths"] = new AttackInfo
                {
                    Description = "Traversal spécifique Windows avec syntaxes alternatives.",
                    LearnMoreUrl = "https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file",
                    RiskLevel = "High",
                    PayloadExample = "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    ErrorExplanation = "Windows accepte \\ et / avec différents encodages."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<DirectoryTraversalResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<DirectoryTraversalResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<DirectoryTraversalResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<DirectoryTraversalResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new DirectoryTraversalResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints ci-dessous pour tester les vulnérabilités Directory Traversal."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Lecture de fichier basique
        [HttpPost]
        public IActionResult ReadFile(string filename)
        {
            if (string.IsNullOrEmpty(filename))
                return Json(new { success = false, error = "Filename requis" });

            try
            {
                // VULNÉRABLE : Aucune validation du chemin
                var fullPath = Path.Combine(_documentsPath, filename);

                // VULNÉRABLE : Pas de vérification si le chemin reste dans le dossier autorisé
                if (System.IO.File.Exists(fullPath))
                {
                    var content = System.IO.File.ReadAllText(fullPath);
                    var fileInfo = new FileInfo(fullPath);

                    return Json(new
                    {
                        success = true,
                        filename = filename,
                        fullPath = fullPath,
                        content = content.Length > 5000 ? content.Substring(0, 5000) + "\n\n[TRONQUÉ...]" : content,
                        size = fileInfo.Length,
                        lastModified = fileInfo.LastWriteTime,
                        warning = "Directory Traversal réussi - Fichier lu!",
                        normalizedPath = Path.GetFullPath(fullPath)
                    });
                }
                else
                {
                    return Json(new { success = false, error = "Fichier non trouvé", attemptedPath = fullPath });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Download de fichiers
        [HttpGet]
        public IActionResult DownloadFile(string file)
        {
            if (string.IsNullOrEmpty(file))
                return BadRequest("Fichier requis");

            try
            {
                // VULNÉRABLE : Path.Combine avec entrée utilisateur non validée
                var filePath = Path.Combine(_documentsPath, file);

                // VULNÉRABLE : Pas de vérification du chemin canonique
                if (System.IO.File.Exists(filePath))
                {
                    var fileBytes = System.IO.File.ReadAllBytes(filePath);
                    var fileName = Path.GetFileName(filePath);

                    // VULNÉRABLE : Retourne n'importe quel fichier accessible
                    return File(fileBytes, "application/octet-stream", fileName);
                }

                return NotFound("Fichier non trouvé");
            }
            catch (Exception ex)
            {
                return BadRequest($"Erreur: {ex.Message}");
            }
        }

        // VULNÉRABLE : Include de fichier
        [HttpPost]
        public IActionResult IncludePage(string page)
        {
            if (string.IsNullOrEmpty(page))
                return Json(new { success = false, error = "Page requise" });

            try
            {
                // VULNÉRABLE : Include direct sans validation
                var pagePath = Path.Combine(_env.ContentRootPath, "Views", page);

                if (System.IO.File.Exists(pagePath))
                {
                    var content = System.IO.File.ReadAllText(pagePath);

                    // VULNÉRABLE : Expose le code source
                    return Json(new
                    {
                        success = true,
                        page = page,
                        content = content,
                        warning = "Code source exposé via Directory Traversal!",
                        fileType = Path.GetExtension(pagePath),
                        realPath = pagePath
                    });
                }

                return Json(new { success = false, error = "Page non trouvée" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Listing de répertoire
        [HttpPost]
        public IActionResult ListDirectory(string path)
        {
            if (string.IsNullOrEmpty(path))
                path = ".";

            try
            {
                // VULNÉRABLE : Permet de lister n'importe quel répertoire
                var fullPath = Path.Combine(_documentsPath, path);
                var dirInfo = new DirectoryInfo(fullPath);

                if (dirInfo.Exists)
                {
                    var entries = new List<object>();

                    // Lister les fichiers
                    foreach (var file in dirInfo.GetFiles())
                    {
                        entries.Add(new
                        {
                            type = "file",
                            name = file.Name,
                            size = file.Length,
                            modified = file.LastWriteTime,
                            extension = file.Extension
                        });
                    }

                    // Lister les dossiers
                    foreach (var dir in dirInfo.GetDirectories())
                    {
                        entries.Add(new
                        {
                            type = "directory",
                            name = dir.Name,
                            modified = dir.LastWriteTime
                        });
                    }

                    return Json(new
                    {
                        success = true,
                        path = path,
                        fullPath = fullPath,
                        parentPath = dirInfo.Parent?.FullName,
                        entries = entries,
                        warning = "Directory listing exposé!",
                        currentUser = Environment.UserName,
                        systemDrive = Path.GetPathRoot(fullPath)
                    });
                }

                return Json(new { success = false, error = "Répertoire non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Upload avec traversal
        [HttpPost]
        public async Task<IActionResult> UploadFile(IFormFile file, string destination)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Fichier requis" });

            try
            {
                // VULNÉRABLE : Destination non validée permet d'écrire n'importe où
                var destPath = string.IsNullOrEmpty(destination)
                    ? Path.Combine(_uploadPath, file.FileName)
                    : Path.Combine(_uploadPath, destination);

                // VULNÉRABLE : Crée les répertoires si nécessaire (permet de créer n'importe où)
                Directory.CreateDirectory(Path.GetDirectoryName(destPath));

                using (var stream = new FileStream(destPath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                return Json(new
                {
                    success = true,
                    filename = file.FileName,
                    destination = destination,
                    fullPath = destPath,
                    size = file.Length,
                    warning = "Fichier uploadé avec path traversal possible!",
                    canOverwrite = System.IO.File.Exists(destPath)
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Lecture avec encodage
        [HttpPost]
        public IActionResult ReadFileEncoded(string encodedPath)
        {
            if (string.IsNullOrEmpty(encodedPath))
                return Json(new { success = false, error = "Path requis" });

            try
            {
                // VULNÉRABLE : Décode mais ne valide pas
                var decodedPath = Uri.UnescapeDataString(encodedPath);
                var fullPath = Path.Combine(_documentsPath, decodedPath);

                // Log pour debug (VULNÉRABLE : log injection possible)
                System.IO.File.AppendAllText(
                    Path.Combine(_env.ContentRootPath, "access.log"),
                    $"{DateTime.Now}: Access to {decodedPath}\n"
                );

                if (System.IO.File.Exists(fullPath))
                {
                    var content = System.IO.File.ReadAllText(fullPath);

                    return Json(new
                    {
                        success = true,
                        encodedPath = encodedPath,
                        decodedPath = decodedPath,
                        content = content.Substring(0, Math.Min(content.Length, 1000)),
                        warning = "Encodage contourné - Directory Traversal!",
                        bypassMethods = new[]
                        {
                            "%2e%2e%2f = ../",
                            "%252e%252e%252f = double encodage",
                            "..%c0%af = unicode",
                            "..%ef%bc%8f = fullwidth slash"
                        }
                    });
                }

                return Json(new { success = false, error = "Fichier non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Null byte injection
        [HttpPost]
        public IActionResult ReadFileNullByte(string file)
        {
            if (string.IsNullOrEmpty(file))
                return Json(new { success = false, error = "File requis" });

            try
            {
                // VULNÉRABLE : Null byte peut tronquer la validation
                var cleanFile = file.Replace("\0", ""); // Tentative naïve de nettoyage

                // VULNÉRABLE : Validation après nettoyage insuffisant
                if (!cleanFile.EndsWith(".txt"))
                {
                    // Cette vérification peut être contournée avec file.txt%00.jpg
                }

                var fullPath = Path.Combine(_documentsPath, file);

                // Dans .NET moderne, le null byte est géré différemment
                // mais on simule la vulnérabilité pour la démo
                var simulatedPath = file.Contains("%00")
                    ? file.Substring(0, file.IndexOf("%00"))
                    : file;

                var realPath = Path.Combine(_documentsPath, simulatedPath);

                if (System.IO.File.Exists(realPath))
                {
                    var content = System.IO.File.ReadAllText(realPath);

                    return Json(new
                    {
                        success = true,
                        requestedFile = file,
                        actualFile = simulatedPath,
                        content = content.Substring(0, Math.Min(content.Length, 1000)),
                        warning = "Null byte injection - Extension bypass!",
                        technique = "file.txt%00.jpg bypasse la vérification .jpg"
                    });
                }

                return Json(new { success = false, error = "Fichier non trouvé" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Template injection avec traversal
        [HttpPost]
        public IActionResult RenderTemplate(string template)
        {
            if (string.IsNullOrEmpty(template))
                return Json(new { success = false, error = "Template requis" });

            try
            {
                // VULNÉRABLE : Simule un moteur de template vulnérable
                var templatePath = Path.Combine(_env.ContentRootPath, "Templates", template);

                // Remplacer les variables de template (VULNÉRABLE)
                var processedTemplate = template;

                // Simulation de template injection permettant file read
                if (template.Contains("{{") && template.Contains("}}"))
                {
                    var match = Regex.Match(template, @"\{\{(.+?)\}\}");
                    if (match.Success)
                    {
                        var expression = match.Groups[1].Value;

                        // VULNÉRABLE : Évalue l'expression
                        if (expression.Contains("file:"))
                        {
                            var filePath = expression.Replace("file:", "").Trim();
                            if (System.IO.File.Exists(filePath))
                            {
                                var fileContent = System.IO.File.ReadAllText(filePath);
                                return Json(new
                                {
                                    success = true,
                                    template = template,
                                    evaluation = fileContent,
                                    warning = "Template injection avec file read!",
                                    examples = new[]
                                    {
                                        "{{file:/etc/passwd}}",
                                        "{{file:C:\\Windows\\win.ini}}",
                                        "{{file:../../../web.config}}"
                                    }
                                });
                            }
                        }
                    }
                }

                return Json(new
                {
                    success = true,
                    template = template,
                    message = "Template traité (essayez {{file:/path/to/file}})"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Backup file access
        [HttpPost]
        public IActionResult AccessBackup(string file)
        {
            if (string.IsNullOrEmpty(file))
                return Json(new { success = false, error = "File requis" });

            try
            {
                // VULNÉRABLE : Recherche automatique de backups
                var backupExtensions = new[] { "~", ".bak", ".backup", ".old", ".save", ".swp", ".tmp" };
                var foundBackups = new List<object>();

                var basePath = Path.Combine(_documentsPath, file);
                var dir = Path.GetDirectoryName(basePath);
                var fileName = Path.GetFileNameWithoutExtension(basePath);
                var extension = Path.GetExtension(basePath);

                foreach (var backupExt in backupExtensions)
                {
                    // Différents patterns de backup
                    var patterns = new[]
                    {
                        $"{basePath}{backupExt}",
                        $"{basePath}.{backupExt}",
                        Path.Combine(dir, $".{fileName}{extension}{backupExt}"),
                        Path.Combine(dir, $"{fileName}{backupExt}{extension}")
                    };

                    foreach (var pattern in patterns)
                    {
                        if (System.IO.File.Exists(pattern))
                        {
                            var content = System.IO.File.ReadAllText(pattern);
                            foundBackups.Add(new
                            {
                                path = pattern,
                                size = new FileInfo(pattern).Length,
                                content = content.Substring(0, Math.Min(content.Length, 500))
                            });
                        }
                    }
                }

                return Json(new
                {
                    success = true,
                    requestedFile = file,
                    foundBackups = foundBackups,
                    warning = foundBackups.Any() ? "Fichiers backup exposés!" : "Aucun backup trouvé",
                    commonBackupPatterns = new[]
                    {
                        "file.txt~",
                        "file.txt.bak",
                        ".file.txt.swp",
                        "file.old.txt"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : ZIP extraction (Zip Slip)
        [HttpPost]
        public async Task<IActionResult> ExtractZip(IFormFile zipFile)
        {
            if (zipFile == null || zipFile.Length == 0)
                return Json(new { success = false, error = "Fichier ZIP requis" });

            try
            {
                var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempPath);

                var zipPath = Path.Combine(tempPath, "archive.zip");
                using (var stream = new FileStream(zipPath, FileMode.Create))
                {
                    await zipFile.CopyToAsync(stream);
                }

                var extractedFiles = new List<object>();

                // VULNÉRABLE : Extraction sans validation des chemins
                using (var archive = System.IO.Compression.ZipFile.OpenRead(zipPath))
                {
                    foreach (var entry in archive.Entries)
                    {
                        // VULNÉRABLE : Le nom peut contenir ../
                        var destinationPath = Path.Combine(_uploadPath, entry.FullName);

                        // Log du danger
                        var isDangerous = entry.FullName.Contains("..") ||
                                        entry.FullName.StartsWith("/") ||
                                        entry.FullName.StartsWith("\\");

                        extractedFiles.Add(new
                        {
                            entryName = entry.FullName,
                            destinationPath = destinationPath,
                            normalizedPath = Path.GetFullPath(destinationPath),
                            isDangerous = isDangerous,
                            wouldEscape = !Path.GetFullPath(destinationPath).StartsWith(_uploadPath)
                        });

                        // VULNÉRABLE : Extraction réelle (commentée pour sécurité)
                        // entry.ExtractToFile(destinationPath, true);
                    }
                }

                // Nettoyer
                Directory.Delete(tempPath, true);

                return Json(new
                {
                    success = true,
                    filename = zipFile.FileName,
                    extractedFiles = extractedFiles,
                    warning = "ZIP Slip vulnerability - Extraction peut échapper au dossier!",
                    maliciousExample = new
                    {
                        entry = "../../evil.aspx",
                        wouldExtractTo = Path.GetFullPath(Path.Combine(_uploadPath, "../../evil.aspx"))
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Windows specific paths
        [HttpPost]
        public IActionResult WindowsTraversal(string path)
        {
            if (string.IsNullOrEmpty(path))
                return Json(new { success = false, error = "Path requis" });

            try
            {
                // VULNÉRABLE : Accepte différentes syntaxes Windows
                var normalizations = new Dictionary<string, string>
                {
                    ["Original"] = path,
                    ["Backslash"] = path.Replace('/', '\\'),
                    ["ForwardSlash"] = path.Replace('\\', '/'),
                    ["MixedSlash"] = path.Replace("../", "..\\"),
                    ["UNCPath"] = $"\\\\?\\{path}",
                    ["DOSDevice"] = $"\\\\.\\{path}",
                    ["AlternateStream"] = $"{path}:$DATA"
                };

                var results = new Dictionary<string, object>();

                foreach (var (method, normalizedPath) in normalizations)
                {
                    try
                    {
                        var fullPath = Path.Combine(_documentsPath, normalizedPath);
                        var exists = System.IO.File.Exists(fullPath) || Directory.Exists(fullPath);

                        results[method] = new
                        {
                            path = normalizedPath,
                            fullPath = fullPath,
                            exists = exists,
                            normalized = Path.GetFullPath(fullPath)
                        };
                    }
                    catch (Exception ex)
                    {
                        results[method] = new { error = ex.Message };
                    }
                }

                return Json(new
                {
                    success = true,
                    originalPath = path,
                    results = results,
                    warning = "Multiples syntaxes Windows acceptées!",
                    examples = new[]
                    {
                        @"..\..\windows\system32\drivers\etc\hosts",
                        @"../../windows/system32/drivers/etc/hosts",
                        @"\\?\C:\Windows\System32\config\SAM",
                        @"C:boot.ini",
                        @"file.txt::$DATA"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Endpoint de test avec fichiers sensibles communs
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            // Créer quelques fichiers de test
            var testFiles = new[]
            {
                Path.Combine(_documentsPath, "public.txt"),
                Path.Combine(_documentsPath, "config.json"),
                Path.Combine(_documentsPath, ".env"),
                Path.Combine(_documentsPath, "secret", "passwords.txt"),
                Path.Combine(_documentsPath, "database.sql"),
                Path.Combine(_documentsPath, "backup", "users.csv"),
                Path.Combine(_documentsPath, "private", "api-keys.json")
            };

            foreach (var testFile in testFiles)
            {
                var dir = Path.GetDirectoryName(testFile);
                Directory.CreateDirectory(dir);
                if (!System.IO.File.Exists(testFile))
                {
                    var content = Path.GetFileName(testFile) switch
                    {
                        "public.txt" => "This is a public file, nothing sensitive here.",
                        "config.json" => "{\n  \"connectionString\": \"Server=localhost;Database=MyApp;User=sa;Password=P@ssw0rd123!\",\n  \"apiKey\": \"sk-1234567890abcdef\",\n  \"secret\": \"SuperSecretKey123\"\n}",
                        ".env" => "DATABASE_URL=postgresql://user:password@localhost/dbname\nSECRET_KEY=my-super-secret-key-123\nAPI_TOKEN=token_1234567890\nADMIN_PASSWORD=Admin123!",
                        "passwords.txt" => "admin:P@ssw0rd123\nuser1:Welcome123\nuser2:Password1\nbackup:BackupPass456",
                        "database.sql" => "-- Database backup\nCREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(100));\nINSERT INTO users VALUES (1, 'admin', 'hashed_password_here');",
                        "users.csv" => "id,username,email,password_hash\n1,admin,admin@example.com,5f4dcc3b5aa765d61d8327deb882cf99\n2,user,user@example.com,ee11cbb19052e40b07aac0ca060c23ee",
                        "api-keys.json" => "{\n  \"stripe\": \"sk_live_1234567890\",\n  \"aws\": \"AKIA1234567890ABCDEF\",\n  \"github\": \"ghp_1234567890abcdef\"\n}",
                        _ => $"Test content for {Path.GetFileName(testFile)}"
                    };
                    System.IO.File.WriteAllText(testFile, content);
                }
            }

            return Json(new
            {
                endpoints = new[]
                {
                    "POST /DirectoryTraversal/ReadFile - Lecture de fichiers",
                    "GET /DirectoryTraversal/DownloadFile?file=XXX - Téléchargement",
                    "POST /DirectoryTraversal/IncludePage - Inclusion de fichiers",
                    "POST /DirectoryTraversal/ListDirectory - Listing de répertoires",
                    "POST /DirectoryTraversal/UploadFile - Upload avec traversal",
                    "POST /DirectoryTraversal/ReadFileEncoded - Bypass par encodage",
                    "POST /DirectoryTraversal/ReadFileNullByte - Null byte injection",
                    "POST /DirectoryTraversal/RenderTemplate - Template injection",
                    "POST /DirectoryTraversal/AccessBackup - Accès aux backups",
                    "POST /DirectoryTraversal/ExtractZip - Zip Slip",
                    "POST /DirectoryTraversal/WindowsTraversal - Syntaxes Windows"
                },
                vulnerabilities = new[]
                {
                    "No path validation",
                    "Path.Combine with user input",
                    "No canonical path check",
                    "Directory listing enabled",
                    "Backup files accessible",
                    "Encoding bypass possible",
                    "Null byte injection",
                    "ZIP Slip vulnerability",
                    "Multiple path syntaxes",
                    "Template injection file read"
                },
                commonTargets = new[]
                {
                    "../../appsettings.json",
                    "../../Program.cs",
                    "../.env",
                    "..\\..\\web.config",
                    "secret/passwords.txt",
                    "backup/users.csv",
                    "private/api-keys.json",
                    "../../../*.csproj",
                    "../../bin/Debug/*.dll",
                    "../../obj/Debug/*.json"
                },
                testFiles = testFiles.Select(f => f.Replace(_documentsPath + Path.DirectorySeparatorChar, "")),
                hint = "Les fichiers de test ont été créés dans le dossier documents. Essayez de remonter avec ../ ou ..\\",
                currentPath = _documentsPath
            });
        }
    }

    // Modèle
    public class DirectoryTraversalResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}