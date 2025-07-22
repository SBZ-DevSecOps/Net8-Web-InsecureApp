using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace InsecureAppWebNet8.Controllers
{
    public class FileUploadController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;
        private readonly IWebHostEnvironment _env;
        private static readonly List<UploadedFile> _uploadedFiles = new();

        public FileUploadController(IWebHostEnvironment env)
        {
            _env = env;

            _attackInfos = new()
            {
                ["no-validation"] = new AttackInfo
                {
                    Description = "Upload sans validation permettant tout type de fichier.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    RiskLevel = "Critical",
                    PayloadExample = "Upload de fichiers .exe, .php, .aspx sans restriction",
                    ErrorExplanation = "Aucune validation du type, taille ou contenu du fichier."
                },
                ["path-traversal"] = new AttackInfo
                {
                    Description = "Nom de fichier permettant path traversal (../../etc/passwd).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/Path_Traversal",
                    RiskLevel = "High",
                    PayloadExample = "filename=../../wwwroot/web.config",
                    ErrorExplanation = "Le nom du fichier n'est pas sanitisé permettant d'écrire n'importe où."
                },
                ["executable-upload"] = new AttackInfo
                {
                    Description = "Upload de fichiers exécutables dans un répertoire accessible.",
                    LearnMoreUrl = "https://portswigger.net/web-security/file-upload",
                    RiskLevel = "Critical",
                    PayloadExample = "Upload de shell.aspx dans /wwwroot/uploads/",
                    ErrorExplanation = "Les fichiers exécutables peuvent être uploadés et exécutés."
                },
                ["mime-bypass"] = new AttackInfo
                {
                    Description = "Validation MIME-type faible contournable.",
                    LearnMoreUrl = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files",
                    RiskLevel = "High",
                    PayloadExample = "Fichier .php avec Content-Type: image/jpeg",
                    ErrorExplanation = "La validation se base uniquement sur le Content-Type modifiable."
                },
                ["dos-large-file"] = new AttackInfo
                {
                    Description = "Pas de limite de taille permettant DoS par fichiers volumineux.",
                    LearnMoreUrl = "https://cwe.mitre.org/data/definitions/400.html",
                    RiskLevel = "Medium",
                    PayloadExample = "Upload de fichiers de plusieurs GB",
                    ErrorExplanation = "Aucune limite de taille peut causer un déni de service."
                },
                ["double-extension"] = new AttackInfo
                {
                    Description = "Double extension permettant de contourner les filtres.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    RiskLevel = "High",
                    PayloadExample = "shell.jpg.aspx ou script.pdf.exe",
                    ErrorExplanation = "Seule la première extension est vérifiée."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<FileUploadResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<FileUploadResult>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<FileUploadResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<FileUploadResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new FileUploadResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les formulaires ci-dessous pour tester les vulnérabilités d'upload."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS RÉELLES DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Aucune validation
        [HttpPost]
        public async Task<IActionResult> UploadNoValidation(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                // VULNÉRABLE : Aucune validation du type de fichier
                var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
                Directory.CreateDirectory(uploadsPath);

                // VULNÉRABLE : Utilise directement le nom du fichier client
                var fileName = file.FileName;
                var filePath = Path.Combine(uploadsPath, fileName);

                // VULNÉRABLE : Sauvegarde sans aucune vérification
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var uploadedFile = new UploadedFile
                {
                    Id = _uploadedFiles.Count + 1,
                    FileName = fileName,
                    FilePath = $"/uploads/{fileName}",
                    ContentType = file.ContentType,
                    Size = file.Length,
                    UploadDate = DateTime.Now
                };
                _uploadedFiles.Add(uploadedFile);

                return Json(new
                {
                    success = true,
                    message = "Fichier uploadé sans aucune validation!",
                    file = uploadedFile,
                    warning = "Tout type de fichier accepté - RCE possible!",
                    directLink = uploadedFile.FilePath
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Path traversal dans le nom
        [HttpPost]
        public async Task<IActionResult> UploadWithPathTraversal(IFormFile file, string customPath)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                // VULNÉRABLE : Accepte un chemin personnalisé sans validation
                var basePath = _env.ContentRootPath;
                var fileName = file.FileName;

                // VULNÉRABLE : Path traversal possible
                if (!string.IsNullOrEmpty(customPath))
                {
                    fileName = customPath;
                }

                var filePath = Path.Combine(basePath, fileName);

                // VULNÉRABLE : Pas de vérification que le chemin reste dans le dossier autorisé
                var directory = Path.GetDirectoryName(filePath);
                if (directory != null)
                {
                    Directory.CreateDirectory(directory);
                }

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                return Json(new
                {
                    success = true,
                    message = "Fichier uploadé avec path traversal possible!",
                    uploadPath = filePath,
                    warning = "Path traversal permet d'écrire n'importe où!",
                    example = "Essayez: ../../wwwroot/evil.aspx"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Upload d'exécutables
        [HttpPost]
        public async Task<IActionResult> UploadExecutable(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                var uploadsPath = Path.Combine(_env.WebRootPath, "uploads", "scripts");
                Directory.CreateDirectory(uploadsPath);

                // VULNÉRABLE : Accepte les extensions exécutables
                var dangerousExtensions = new[] { ".aspx", ".php", ".exe", ".bat", ".ps1", ".jsp" };
                var fileExtension = Path.GetExtension(file.FileName).ToLower();

                // VULNÉRABLE : Sauvegarde même les fichiers dangereux
                var fileName = Guid.NewGuid().ToString() + fileExtension;
                var filePath = Path.Combine(uploadsPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // VULNÉRABLE : Rend le fichier accessible via URL
                var webPath = $"/uploads/scripts/{fileName}";

                return Json(new
                {
                    success = true,
                    message = $"Fichier exécutable uploadé: {fileExtension}",
                    webPath = webPath,
                    isDangerous = dangerousExtensions.Contains(fileExtension),
                    warning = "Fichier exécutable accessible via web!",
                    executeUrl = webPath
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Validation MIME faible
        [HttpPost]
        public async Task<IActionResult> UploadWithWeakMime(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                // VULNÉRABLE : Se fie uniquement au Content-Type fourni par le client
                var allowedMimeTypes = new[] { "image/jpeg", "image/png", "image/gif" };

                if (!allowedMimeTypes.Contains(file.ContentType))
                {
                    return Json(new
                    {
                        success = false,
                        error = "Type MIME non autorisé",
                        hint = "Mais le Content-Type peut être falsifié!"
                    });
                }

                // VULNÉRABLE : Pas de vérification du contenu réel du fichier
                var uploadsPath = Path.Combine(_env.WebRootPath, "uploads", "images");
                Directory.CreateDirectory(uploadsPath);

                var fileName = Guid.NewGuid().ToString() + Path.GetExtension(file.FileName);
                var filePath = Path.Combine(uploadsPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Lire les premiers octets pour vérifier (mais ne le fait pas!)
                var fileBytes = new byte[10];
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(fileBytes, 0, 10);
                }

                return Json(new
                {
                    success = true,
                    message = "Fichier accepté basé sur MIME type seulement!",
                    declaredMime = file.ContentType,
                    actualBytes = BitConverter.ToString(fileBytes),
                    warning = "Un .php peut passer pour une image!",
                    filePath = $"/uploads/images/{fileName}"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Pas de limite de taille
        [HttpPost]
        [RequestSizeLimit(2147483648)] // 2GB - Dangereux!
        public async Task<IActionResult> UploadLargeFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                // VULNÉRABLE : Aucune vérification de la taille
                var uploadsPath = Path.Combine(_env.WebRootPath, "uploads", "large");
                Directory.CreateDirectory(uploadsPath);

                var fileName = file.FileName;
                var filePath = Path.Combine(uploadsPath, fileName);

                // VULNÉRABLE : Upload de fichiers énormes possible
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Calculer l'espace disque restant
                var driveInfo = new DriveInfo(Path.GetPathRoot(filePath) ?? "C:\\");
                var freeSpace = driveInfo.AvailableFreeSpace;

                return Json(new
                {
                    success = true,
                    message = "Fichier volumineux uploadé!",
                    fileSize = file.Length,
                    fileSizeMB = file.Length / (1024.0 * 1024.0),
                    freeSpaceGB = freeSpace / (1024.0 * 1024.0 * 1024.0),
                    warning = "DoS possible par saturation disque!"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Double extension
        [HttpPost]
        public async Task<IActionResult> UploadDoubleExtension(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "Aucun fichier fourni" });

            try
            {
                var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
                Directory.CreateDirectory(uploadsPath);

                // VULNÉRABLE : Vérifie seulement la dernière extension
                var fileName = file.FileName;
                var lastExtension = Path.GetExtension(fileName).ToLower();
                var allowedExtensions = new[] { ".jpg", ".png", ".gif", ".pdf", ".txt" };

                if (!allowedExtensions.Contains(lastExtension))
                {
                    return Json(new
                    {
                        success = false,
                        error = "Extension non autorisée",
                        hint = "Mais essayez shell.jpg.aspx!"
                    });
                }

                // VULNÉRABLE : Sauvegarde avec le nom complet incluant double extension
                var filePath = Path.Combine(uploadsPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Détecter les doubles extensions
                var parts = fileName.Split('.');
                var hasDoubleExtension = parts.Length > 2;

                return Json(new
                {
                    success = true,
                    message = "Fichier avec double extension accepté!",
                    fileName = fileName,
                    extensions = parts.Skip(1).ToArray(),
                    hasDoubleExtension = hasDoubleExtension,
                    warning = hasDoubleExtension ? "Double extension détectée - bypass possible!" : "Extension simple",
                    webPath = $"/uploads/{fileName}"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // Lister les fichiers uploadés
        [HttpGet]
        public IActionResult ListUploads()
        {
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            var files = new List<object>();

            if (Directory.Exists(uploadsPath))
            {
                var allFiles = Directory.GetFiles(uploadsPath, "*", SearchOption.AllDirectories);
                files = allFiles.Select(f => new
                {
                    fileName = Path.GetFileName(f),
                    relativePath = Path.GetRelativePath(_env.WebRootPath, f),
                    size = new FileInfo(f).Length,
                    extension = Path.GetExtension(f),
                    isDangerous = IsDangerousFile(f),
                    webUrl = "/" + Path.GetRelativePath(_env.WebRootPath, f).Replace('\\', '/')
                }).ToList<object>();
            }

            return Json(new
            {
                success = true,
                uploadedFiles = files,
                totalFiles = files.Count,
                uploadsDirectory = uploadsPath,
                warning = "Fichiers accessibles publiquement!"
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
                    "POST /FileUpload/UploadNoValidation - Aucune validation",
                    "POST /FileUpload/UploadWithPathTraversal - Path traversal",
                    "POST /FileUpload/UploadExecutable - Upload d'exécutables",
                    "POST /FileUpload/UploadWithWeakMime - Validation MIME faible",
                    "POST /FileUpload/UploadLargeFile - Pas de limite de taille",
                    "POST /FileUpload/UploadDoubleExtension - Double extension",
                    "GET /FileUpload/ListUploads - Liste des fichiers"
                },
                vulnerabilities = new[]
                {
                    "No file type validation",
                    "Path traversal in filename",
                    "Executable files in web directory",
                    "MIME type spoofing",
                    "No file size limit (DoS)",
                    "Double extension bypass",
                    "Direct file access via URL"
                }
            });
        }

        private bool IsDangerousFile(string filePath)
        {
            var dangerousExtensions = new[] { ".exe", ".dll", ".aspx", ".php", ".jsp", ".bat", ".ps1", ".sh" };
            var extension = Path.GetExtension(filePath).ToLower();
            return dangerousExtensions.Contains(extension);
        }
    }

    // Modèles
    public class FileUploadResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class UploadedFile
    {
        public int Id { get; set; }
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long Size { get; set; }
        public DateTime UploadDate { get; set; }
    }
}