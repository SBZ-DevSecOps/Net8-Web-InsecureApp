using Microsoft.AspNetCore.Mvc;

namespace InsecureAppWebNet8.Controllers
{
    // A06 – Security Misconfiguration
    public class ConfigController : Controller
    {
        public IActionResult DebugInfo()
        {
            return Content("Debug: StackTrace, Version, Assemblies...");
        }
    }
}
