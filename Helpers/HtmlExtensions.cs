using Ganss.Xss;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace InsecureAppWebNet8.Helpers
{
    public static class HtmlExtensions
    {
        private static readonly HtmlSanitizer Sanitizer = new HtmlSanitizer();

        static HtmlExtensions()
        {
            // Configurer les balises autorisées
            Sanitizer.AllowedTags.Clear();
            Sanitizer.AllowedTags.Add("a");
            Sanitizer.AllowedTags.Add("strong");
            Sanitizer.AllowedTags.Add("em");
            Sanitizer.AllowedTags.Add("code");
            Sanitizer.AllowedTags.Add("br");

            // Configurer les attributs autorisés
            Sanitizer.AllowedAttributes.Clear();
            Sanitizer.AllowedAttributes.Add("href");
            Sanitizer.AllowedAttributes.Add("target");
            Sanitizer.AllowedAttributes.Add("class");

            // Configurer les schémas d'URL autorisés
            Sanitizer.AllowedSchemes.Clear();
            Sanitizer.AllowedSchemes.Add("http");
            Sanitizer.AllowedSchemes.Add("https");
        }

        public static IHtmlContent SafeHtml(this IHtmlHelper htmlHelper, string content)
        {
            if (string.IsNullOrEmpty(content))
                return new HtmlString("");

            var sanitized = Sanitizer.Sanitize(content);
            return new HtmlString(sanitized);
        }
    }
}
