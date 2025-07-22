using Microsoft.AspNetCore.Mvc;

namespace InsecureAppWebNet8.Controllers
{
    // A08 – Software Integrity Failures
    public class IntegrityController : Controller
    {
        public IActionResult LoadPlugin(string path)
        {
            var asm = System.Reflection.Assembly.LoadFrom(path); // sans validation d'intégrité
            return Content("DLL chargée dynamiquement");
        }
    }
}
