using Microsoft.AspNetCore.Mvc;

namespace InsecureAppWebNet8.Controllers
{
    public class AdminController : Controller
    {
        // Vulnérabilité #1 : Pas d'attribut [Authorize], accès public
        public IActionResult Index()
        {
            return Content("Admin Panel - accessible sans authentification.");
        }

        // Vulnérabilité #2 : IDOR – accès à un profil admin par ID
        public IActionResult UserDetails(int id)
        {
            // Aucune vérification que l'utilisateur connecté est autorisé à voir l'utilisateur #id
            return Content($"Affichage du profil de l'utilisateur ID #{id} (IDOR possible)");
        }

        // Vulnérabilité #3 : Contrôle basé sur l'UI (rôle supposé)
        public IActionResult ManageUsers(string role)
        {
            // Suppose que seul un utilisateur avec un rôle "admin" en paramètre peut gérer les utilisateurs
            if (role == "admin")
                return Content("Interface de gestion des utilisateurs");
            return Content("Accès refusé (mais protection facilement contournable)");
        }

        // Vulnérabilité #4 : Modification d'un rôle utilisateur via formulaire (Escalade horizontale ou verticale)
        [HttpPost]
        public IActionResult ChangeRole(string username, string role)
        {
            // Supposons que l'utilisateur connecté peut modifier n'importe quel rôle, Aucun contrôle RBAC
            return Content($"Rôle de {username} changé en {role} (aucune validation serveur)");
        }

        // Vulnérabilité #5 : Accès à des fichiers de logs sensibles (path traversal), Peut accéder à n'importe quel fichier du système
        public IActionResult ReadLog(string filename)
        {
            // Ex : ../../appsettings.json
            var path = $"./logs/{filename}";
            var content = System.IO.File.ReadAllText(path);
            return Content(content);
        }
    }
}
