using InsecureAppWebNet8.Data;
using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;

namespace InsecureAppWebNet8.Controllers
{
    public class InjectionSqlController : Controller
    {
        private readonly ProductDbContext _context;

        private readonly Dictionary<string, string> _attackDescriptions = new()
        {
            ["raw"] = "Injection SQL classique où le payload est inséré directement dans la requête. " +
                      "Permet d'exécuter du SQL arbitraire si non filtré. " +
                      "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["union"] = "Injection UNION permettant de combiner plusieurs résultats de requêtes, " +
                       "exfiltrant ainsi plus d'informations. " +
                       "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["boolean"] = "Injection booléenne exploitant la logique vraie/faux pour filtrer les données " +
                         "sans retour direct du contenu. Technique souvent utilisée en blind SQLi. " +
                         "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["error"] = "Injection provoquant une erreur volontaire pour extraire des informations " +
                       "sur la structure ou les données de la base via les messages d'erreur SQL. " +
                       "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["like"] = "Injection utilisant l'opérateur LIKE pour faire correspondre des patterns et " +
                      "exploiter la vulnérabilité même sur des comparaisons partielles. " +
                      "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["time"] = "Injection temporelle qui introduit un délai dans la requête SQL (ex: pg_sleep) " +
                      "pour détecter les vulnérabilités en mesurant le temps de réponse (blind SQLi). " +
                      "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["stacked"] = "Injection utilisant les requêtes empilées (stacked queries) pour exécuter " +
                         "plusieurs commandes SQL à la suite, par exemple pour modifier la base. " +
                         "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>.",
            ["comment"] = "Injection utilisant les commentaires SQL pour tronquer la requête légitime " +
                         "et injecter du code malicieux à la fin. " +
                         "<a href=\"https://owasp.org/Top10/A03_2025-Injection/\" target=\"_blank\">En savoir plus</a>."
        };

        private readonly Dictionary<string, string> _payloadExamples = new()
        {
            // Injection simple dans une clause LIKE, typiquement vulnérable si concaténée directement
            ["raw"] = "%' OR 1=1 --",

            // Injection UNION adaptée à PostgreSQL (avec les bons noms de colonnes)
            ["union"] = "' UNION SELECT \"Id\", \"Name\", \"Description\" FROM \"Product\" --",

            // Boolean-based injection directe dans un WHERE = ''
            ["boolean"] = "' OR 1=1 --",

            // Error-based SQLi avec PostgreSQL (utilise version(), pas database() ou concat+rand)
            ["error"] = "'||(SELECT 1/0)||'",

            // Injection LIKE avec motif
            ["like"] = "' OR \"Name\" LIKE '%test%' --",

            // Time-based blind SQLi avec pg_sleep()
            ["time"] = "'; SELECT pg_sleep(5); --",

            // Stacked query — ne fonctionne pas toujours selon la configuration (voir avertissement)
            ["stacked"] = "1; DELETE FROM \"Product\"; --",

            // Injection par troncation via commentaire SQL
            ["comment"] = "'; --"
        };

        private readonly Dictionary<string, string> _errorExplanations = new()
        {
            ["raw"] = "La requête utilise LIKE avec un payload directement injecté. Une mauvaise fermeture de guillemets ou un point-virgule peut casser la requête.",
            ["union"] = "Le payload UNION doit retourner le même nombre et type de colonnes que la requête initiale. Sinon, PostgreSQL renverra une erreur.",
            ["boolean"] = "Une condition booléenne mal formée peut causer une erreur. Vérifiez les guillemets et la logique SQL.",
            ["error"] = "Ce type d’injection provoque une erreur SQL volontaire. PostgreSQL peut bloquer certaines fonctions (ex : CONCAT ou RAND).",
            ["like"] = "La syntaxe LIKE avec des caractères spéciaux mal échappés peut provoquer des erreurs.",
            ["time"] = "La fonction <code>pg_sleep()</code> peut être bloquée par les politiques du serveur. Elle peut aussi échouer si le payload casse la syntaxe.",
            ["stacked"] = "Entity Framework et PostgreSQL bloquent souvent les requêtes empilées (plusieurs commandes séparées par <code>;</code>).",
            ["comment"] = "Le payload utilise <code>--</code> pour tronquer la requête. Une mauvaise position du commentaire ou une chaîne non fermée peut générer une erreur."
        };

        private readonly Dictionary<string, AttackInfo> _attackInfos = new()
        {
            ["raw"] = new AttackInfo
            {
                Description = "Injection SQL classique où le payload est inséré directement dans la requête. Permet d'exécuter du SQL arbitraire si non filtré.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "High",
                PayloadExample = "%' OR 1=1 --",
                ErrorExplanation = "La requête utilise LIKE avec un payload directement injecté. Une mauvaise fermeture de guillemets ou un point-virgule peut casser la requête."
            },
            ["union"] = new AttackInfo
            {
                Description = "Injection UNION permettant de combiner plusieurs résultats de requêtes, exfiltrant ainsi plus d'informations.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "High",
                PayloadExample = "' UNION SELECT \"Id\", \"Name\", \"Description\" FROM \"Product\" --",
                ErrorExplanation = "Le payload UNION doit retourner le même nombre et type de colonnes que la requête initiale. Sinon, PostgreSQL renverra une erreur."
            },
            ["boolean"] = new AttackInfo
            {
                Description = "Injection booléenne exploitant la logique vraie/faux pour filtrer les données sans retour direct du contenu. Technique souvent utilisée en blind SQLi.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "Medium",
                PayloadExample = "' OR 1=1 --",
                ErrorExplanation = "Une condition booléenne mal formée peut causer une erreur. Vérifiez les guillemets et la logique SQL."
            },
            ["error"] = new AttackInfo
            {
                Description = "Injection provoquant une erreur volontaire pour extraire des informations sur la structure ou les données de la base via les messages d'erreur SQL.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "Medium",
                PayloadExample = "'||(SELECT 1/0)||'",
                ErrorExplanation = "Ce type d'injection provoque une erreur SQL volontaire. PostgreSQL peut bloquer certaines fonctions (ex : CONCAT ou RAND)."
            },
            ["like"] = new AttackInfo
            {
                Description = "Injection utilisant l'opérateur LIKE pour faire correspondre des patterns et exploiter la vulnérabilité même sur des comparaisons partielles.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "Medium",
                PayloadExample = "' OR \"Name\" LIKE '%test%' --",
                ErrorExplanation = "La syntaxe LIKE avec des caractères spéciaux mal échappés peut provoquer des erreurs."
            },
            ["time"] = new AttackInfo
            {
                Description = "Injection temporelle qui introduit un délai dans la requête SQL (ex: pg_sleep) pour détecter les vulnérabilités en mesurant le temps de réponse (blind SQLi).",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "High",
                PayloadExample = "'; SELECT pg_sleep(5); --",
                ErrorExplanation = "La fonction pg_sleep() peut être bloquée par les politiques du serveur. Elle peut aussi échouer si le payload casse la syntaxe."
            },
            ["stacked"] = new AttackInfo
            {
                Description = "Injection utilisant les requêtes empilées (stacked queries) pour exécuter plusieurs commandes SQL à la suite, par exemple pour modifier la base.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "High",
                PayloadExample = "1; DELETE FROM \"Product\"; --",
                ErrorExplanation = "Entity Framework et PostgreSQL bloquent souvent les requêtes empilées (plusieurs commandes séparées par <code>;</code>)."
            },
            ["comment"] = new AttackInfo
            {
                Description = "Injection utilisant les commentaires SQL pour tronquer la requête légitime et injecter du code malicieux à la fin.",
                LearnMoreUrl = "https://owasp.org/Top10/A03_2025-Injection/",
                RiskLevel = "Medium",
                PayloadExample = "'; --",
                ErrorExplanation = "Le payload utilise <code>--</code> pour tronquer la requête. Une mauvaise position du commentaire ou une chaîne non fermée peut générer une erreur."
            }
        };


        public InjectionSqlController(ProductDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<Product>
            {
                AttackType = "",
                Payload = "",
                Results = new List<Product>(),
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
                var emptyModel = new VulnerabilityViewModel<Product>
                {
                    AttackType = "",
                    Payload = "",
                    Results = new List<Product>(),
                    AttackDescriptions = _attackDescriptions,
                    PayloadExamples = _payloadExamples,
                    AttackInfos = _attackInfos
                };
                return View(emptyModel);
            }

            try
            {
                string sql = attackType switch
                {
                    "raw" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",
                    "union" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",
                    "boolean" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",
                    "error" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",
                    "like" => $"SELECT * FROM \"Product\" WHERE \"Name\" LIKE '{payload}'", // payload peut être '%x%' OR 1=1
                    "time" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",
                    "stacked" => $"SELECT * FROM \"Product\" WHERE \"Id\" = {payload}", // ici pas de quote — injection via entier
                    "comment" => $"SELECT * FROM \"Product\" WHERE \"Name\" = '{payload}'",

                    _ => throw new ArgumentException("Type d'attaque inconnu")
                };

                var results = _context.Products.FromSqlRaw(sql).ToList();

                var model = VulnerabilityViewModel<Product>.WithResults(payload, attackType, results, sql);
                model.AttackDescriptions = _attackDescriptions;
                model.PayloadExamples = _payloadExamples;
                model.ErrorExplanations = _errorExplanations;
                model.AttackInfos = _attackInfos;
                return View(model);
            }
            catch (Exception ex)
            {
                var errorModel = new VulnerabilityViewModel<Product>
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
    }
}
