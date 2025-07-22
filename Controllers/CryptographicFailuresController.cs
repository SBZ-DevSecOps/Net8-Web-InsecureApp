using InsecureAppWebNet8.Models;
using InsecureAppWebNet8.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace InsecureAppWebNet8.Controllers
{
    public class CryptographicFailuresController : Controller
    {
        private readonly Dictionary<string, AttackInfo> _attackInfos;

        // VULNÉRABLE : Secrets hardcodés détectables par SAST
        private const string HARDCODED_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        private const string DATABASE_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "my-super-secret-key-123";
        private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string STRIPE_SECRET_KEY = "sk_live_51H0OxXKfBBMH8QJqV5xOvxk8Rku3Zvg5P";
        private const string GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        private const string AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=storage;AccountKey=key123==;";

        // VULNÉRABLE : Certificat et clés privées stockés dans le code
        private const string PRIVATE_KEY_PEM = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4ggF8HTqzUJZS+1xA4HaIv7TjUuatD8xvQ1F0mCBhgRYLG6h
LkiMQKDnkLr5lIEqXVvzZBjhZkVQQJMZNG1+4fJBDpugz8E2OQBPbTnFmwZ2FqfW
-----END RSA PRIVATE KEY-----";

        private const string SSL_CERTIFICATE = @"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKLdQRydOlrZMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----";

        // VULNÉRABLE : Stockage des secrets en clair
        private static readonly Dictionary<string, UserSecrets> _userSecrets = new()
        {
            ["alice"] = new UserSecrets
            {
                Username = "alice",
                Password = "alice123", // Mot de passe en clair
                PasswordMD5 = "5f4dcc3b5aa765d61d8327deb882cf99", // MD5 (vulnérable)
                ApiToken = "token_alice_2024",
                RecoveryCode = "RECOVERY-ALICE-123456",
                TwoFactorSecret = "JBSWY3DPEHPK3PXP",
                CreditCard = "4111111111111111", // Numéro de carte non masqué
                SSN = "123-45-6789" // SSN en clair
            },
            ["admin"] = new UserSecrets
            {
                Username = "admin",
                Password = "admin@123", // Mot de passe faible et en clair
                PasswordMD5 = "0192023a7bbd73250516f069df18b500",
                ApiToken = "token_admin_master",
                RecoveryCode = "RECOVERY-ADMIN-789012",
                TwoFactorSecret = "JBSWY3DPEHPK3PXZ",
                CreditCard = "5500000000000004",
                SSN = "987-65-4321"
            }
        };

        // VULNÉRABLE : Configuration sensible
        private static readonly Dictionary<string, string> _configSecrets = new()
        {
            ["ConnectionString"] = "Server=prod-db.example.com;Database=ProductionDB;User Id=sa;Password=P@ssw0rd123!;",
            ["RedisConnection"] = "redis-cluster.example.com:6379,password=RedisP@ss123",
            ["SmtpPassword"] = "smtp-password-123",
            ["EncryptionKey"] = "ThisIsAWeakKey123", // Clé faible
            ["PaymentApiKey"] = "pk_live_payment_key_123456",
            ["OAuth2ClientSecret"] = "oauth2_client_secret_xyz",
            ["MongoDBUri"] = "mongodb://admin:password123@mongodb.example.com:27017/",
            ["ElasticsearchUrl"] = "https://elastic:changeme@localhost:9200"
        };

        // VULNÉRABLE : Encryption avec algorithmes faibles
        private static readonly byte[] WeakIV = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }; // IV hardcodé
        private static readonly byte[] WeakKey = Encoding.UTF8.GetBytes("WeakKey123456789"); // Clé faible

        public CryptographicFailuresController()
        {
            _attackInfos = new()
            {
                ["hardcoded-secrets"] = new AttackInfo
                {
                    Description = "Secrets, mots de passe et clés API hardcodés dans le code source.",
                    LearnMoreUrl = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /CryptographicFailures/ExposedSecrets",
                    ErrorExplanation = "Les secrets ne doivent jamais être stockés dans le code source."
                },
                ["weak-hashing"] = new AttackInfo
                {
                    Description = "Utilisation d'algorithmes de hachage faibles (MD5, SHA1).",
                    LearnMoreUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                    RiskLevel = "High",
                    PayloadExample = "GET /CryptographicFailures/WeakHashing?password=test123",
                    ErrorExplanation = "MD5 et SHA1 sont vulnérables aux collisions et attaques."
                },
                ["plaintext-storage"] = new AttackInfo
                {
                    Description = "Stockage de données sensibles en clair.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Plaintext_Storage_of_Password",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /CryptographicFailures/GetUserSecrets?username=alice",
                    ErrorExplanation = "Les mots de passe et données sensibles doivent être chiffrés."
                },
                ["weak-encryption"] = new AttackInfo
                {
                    Description = "Chiffrement avec algorithmes obsolètes ou mal configurés.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Weak_Cryptography",
                    RiskLevel = "High",
                    PayloadExample = "POST /CryptographicFailures/WeakEncryption",
                    ErrorExplanation = "DES, ECB mode, clés faibles rendent le chiffrement inutile."
                },
                ["exposed-keys"] = new AttackInfo
                {
                    Description = "Clés privées et certificats exposés.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Private_key_storage",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /CryptographicFailures/GetPrivateKeys",
                    ErrorExplanation = "Les clés privées exposées compromettent toute la sécurité."
                },
                ["insecure-random"] = new AttackInfo
                {
                    Description = "Utilisation de générateurs de nombres pseudo-aléatoires non sécurisés.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness",
                    RiskLevel = "High",
                    PayloadExample = "GET /CryptographicFailures/InsecureRandom",
                    ErrorExplanation = "Random() n'est pas cryptographiquement sûr pour les tokens."
                },
                ["weak-tls"] = new AttackInfo
                {
                    Description = "Configuration TLS/SSL faible ou obsolète.",
                    LearnMoreUrl = "https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet",
                    RiskLevel = "High",
                    PayloadExample = "GET /CryptographicFailures/WeakTLSConfig",
                    ErrorExplanation = "TLS 1.0/1.1 et chiffrements faibles sont vulnérables."
                },
                ["missing-encryption"] = new AttackInfo
                {
                    Description = "Absence de chiffrement pour les données sensibles en transit.",
                    LearnMoreUrl = "https://owasp.org/www-community/vulnerabilities/Missing_Encryption_of_Sensitive_Data",
                    RiskLevel = "Critical",
                    PayloadExample = "GET /CryptographicFailures/UnencryptedTransmission",
                    ErrorExplanation = "Les données sensibles doivent être chiffrées en transit."
                }
            };
        }

        [HttpGet]
        public IActionResult Index()
        {
            var model = new VulnerabilityViewModel<SecretExposure>
            {
                AttackType = "",
                Payload = "",
                Results = new List<SecretExposure>(),
                AttackInfos = _attackInfos
            };
            return View(model);
        }

        [HttpPost]
        public IActionResult Index(string attackType, string payload)
        {
            payload = payload ?? string.Empty;

            var model = new VulnerabilityViewModel<SecretExposure>
            {
                AttackType = attackType,
                Payload = payload,
                Results = new List<SecretExposure>(),
                AttackInfos = _attackInfos
            };

            if (!string.IsNullOrEmpty(attackType))
            {
                var result = new SecretExposure
                {
                    AttackType = attackType,
                    Success = true,
                    Message = "Utilisez les endpoints vulnérables ci-dessous pour tester."
                };
                model.Results.Add(result);
            }

            return View(model);
        }

        // === VULNÉRABILITÉS DÉTECTABLES PAR SAST ===

        // VULNÉRABLE : Expose tous les secrets hardcodés
        [HttpGet]
        public IActionResult ExposedSecrets()
        {
            // VULNÉRABLE : Retourne tous les secrets hardcodés
            return Json(new
            {
                success = true,
                message = "Secrets hardcodés exposés!",
                secrets = new
                {
                    apiKeys = new
                    {
                        stripe = STRIPE_SECRET_KEY,
                        aws_access = AWS_ACCESS_KEY,
                        aws_secret = AWS_SECRET_KEY,
                        github = GITHUB_TOKEN,
                        generic = HARDCODED_API_KEY
                    },
                    passwords = new
                    {
                        database = DATABASE_PASSWORD,
                        jwt_secret = JWT_SECRET
                    },
                    connectionStrings = _configSecrets,
                    warning = "CRITIQUE: Tous ces secrets sont hardcodés dans le code!"
                }
            });
        }

        // VULNÉRABLE : Hachage avec algorithmes faibles
        [HttpGet]
        public IActionResult WeakHashing(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                password = "test123";
            }

            // VULNÉRABLE : Utilisation de MD5
            using (var md5 = MD5.Create())
            {
                var md5Hash = BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(password))).Replace("-", "").ToLower();

                // VULNÉRABLE : Utilisation de SHA1
                using (var sha1 = SHA1.Create())
                {
                    var sha1Hash = BitConverter.ToString(sha1.ComputeHash(Encoding.UTF8.GetBytes(password))).Replace("-", "").ToLower();

                    return Json(new
                    {
                        success = true,
                        password = password,
                        hashes = new
                        {
                            md5 = md5Hash,
                            sha1 = sha1Hash,
                            plaintext = password // VULNÉRABLE : Retour du mot de passe en clair
                        },
                        warning = "MD5 et SHA1 sont des algorithmes de hachage obsolètes et vulnérables!"
                    });
                }
            }
        }

        // VULNÉRABLE : Stockage et retour de données sensibles en clair
        [HttpGet]
        public IActionResult GetUserSecrets(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                // VULNÉRABLE : Retourne TOUS les secrets si pas de username
                return Json(new
                {
                    success = true,
                    allUsers = _userSecrets,
                    warning = "Toutes les données sensibles sont exposées en clair!"
                });
            }

            if (_userSecrets.ContainsKey(username))
            {
                var secrets = _userSecrets[username];
                return Json(new
                {
                    success = true,
                    user = username,
                    secrets = secrets, // VULNÉRABLE : Expose toutes les données sensibles
                    warning = "Données sensibles stockées et transmises en clair!"
                });
            }

            return Json(new { success = false, error = "Utilisateur non trouvé" });
        }

        // VULNÉRABLE : Chiffrement faible
        [HttpPost]
        public IActionResult WeakEncryption([FromBody] EncryptRequest request)
        {
            try
            {
                var data = request?.Data ?? "Sensitive Data";

                // VULNÉRABLE : DES avec ECB mode
                using (var des = DES.Create())
                {
                    des.Key = WeakKey.Take(8).ToArray(); // DES utilise une clé de 8 bytes
                    des.Mode = CipherMode.ECB; // VULNÉRABLE : ECB mode
                    des.Padding = PaddingMode.PKCS7;

                    var encryptor = des.CreateEncryptor();
                    var encrypted = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(data), 0, data.Length);

                    return Json(new
                    {
                        success = true,
                        original = data,
                        encrypted = Convert.ToBase64String(encrypted),
                        algorithm = "DES",
                        mode = "ECB",
                        keySize = "56 bits",
                        warning = "DES avec ECB mode est complètement obsolète et vulnérable!"
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        // VULNÉRABLE : Expose les clés privées et certificats
        [HttpGet]
        public IActionResult GetPrivateKeys()
        {
            return Json(new
            {
                success = true,
                message = "Clés privées et certificats exposés!",
                keys = new
                {
                    privateKey = PRIVATE_KEY_PEM,
                    certificate = SSL_CERTIFICATE,
                    jwtSecret = JWT_SECRET,
                    encryptionKey = _configSecrets["EncryptionKey"]
                },
                warning = "CRITIQUE: Les clés privées ne doivent JAMAIS être exposées!"
            });
        }

        // VULNÉRABLE : Logs avec données sensibles
        [HttpGet]
        public IActionResult GetLogs()
        {
            var logs = new List<object>();

            foreach (var user in _userSecrets)
            {
                // VULNÉRABLE : Log des mots de passe en clair
                logs.Add(new
                {
                    timestamp = DateTime.Now.AddMinutes(-Random.Shared.Next(60)),
                    level = "INFO",
                    message = $"Login attempt for user {user.Key}",
                    details = new
                    {
                        username = user.Key,
                        password = user.Value.Password, // VULNÉRABLE : Mot de passe en clair dans les logs
                        apiToken = user.Value.ApiToken
                    }
                });
            }

            return Json(new
            {
                success = true,
                logs = logs,
                warning = "Les logs contiennent des données sensibles non masquées!"
            });
        }

        // VULNÉRABLE : Configuration exposée
        [HttpGet]
        public IActionResult GetConfig()
        {
            return Json(new
            {
                success = true,
                config = new
                {
                    database = _configSecrets["ConnectionString"],
                    redis = _configSecrets["RedisConnection"],
                    smtp = new
                    {
                        host = "smtp.example.com",
                        port = 587,
                        username = "noreply@example.com",
                        password = _configSecrets["SmtpPassword"] // VULNÉRABLE
                    },
                    oauth = new
                    {
                        clientId = "oauth-client-id",
                        clientSecret = _configSecrets["OAuth2ClientSecret"] // VULNÉRABLE
                    },
                    payment = new
                    {
                        apiKey = _configSecrets["PaymentApiKey"] // VULNÉRABLE
                    }
                },
                warning = "Configuration avec secrets exposés!"
            });
        }

        // VULNÉRABLE : Expose les fichiers de configuration
        [HttpGet]
        public IActionResult GetConfigFiles(string filename)
        {
            var configFiles = new Dictionary<string, string>
            {
                ["appsettings.json"] = @"{
  ""ConnectionStrings"": {
    ""DefaultConnection"": ""Server=prod-db.example.com;Database=ProductionDB;User Id=sa;Password=P@ssw0rd123!;"",
    ""RedisConnection"": ""redis-cluster.example.com:6379,password=RedisP@ss123""
  },
  ""AppSettings"": {
    ""JwtSecret"": ""ThisIsMySecretKeyForJWT_MinimumLength32Characters"",
    ""ApiKey"": ""sk_live_4eC39HqLyjWDarjtT1zdp7dc""
  },
  ""AWS"": {
    ""AccessKeyId"": ""AKIAIOSFODNN7EXAMPLE"",
    ""SecretAccessKey"": ""wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""
  },
  ""Stripe"": {
    ""SecretKey"": ""sk_live_51H0vKmICTx8fBbMHkV5xOvxk8Rku3Zvg5P""
  }
}",
                ["web.config"] = @"<?xml version=""1.0""?>
<configuration>
  <connectionStrings>
    <add name=""DefaultConnection"" connectionString=""Data Source=prod-sql;User ID=sa;Password=SQLServerP@ssw0rd123!""/>
  </connectionStrings>
  <appSettings>
    <add key=""ApiKey"" value=""4f8b5c3d-9e2a-4b6f-8d1c-3a7e9f2b5d8c""/>
    <add key=""AWS_SECRET_ACCESS_KEY"" value=""wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""/>
  </appSettings>
</configuration>",
                [".env"] = @"DATABASE_URL=postgresql://postgres:PostgresAdm!n2024@prod-db.example.com:5432/production_db
JWT_SECRET=jwt_secret_key_minimum_256_bits_for_hs256_algorithm
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H0vKmICTx8fBbMHkV5xOvxk8Rku3Zvg5P
ADMIN_PASSWORD=SuperAdm!n2024"
            };

            if (string.IsNullOrEmpty(filename))
            {
                // VULNÉRABLE : Liste tous les fichiers de config avec leurs contenus
                return Json(new
                {
                    success = true,
                    message = "Tous les fichiers de configuration exposés!",
                    files = configFiles.Keys.ToList(),
                    warning = "Ces fichiers contiennent des secrets en production!"
                });
            }

            if (configFiles.ContainsKey(filename))
            {
                return Json(new
                {
                    success = true,
                    filename = filename,
                    content = configFiles[filename],
                    secrets_found = CountSecrets(configFiles[filename]),
                    warning = "Fichier de configuration avec secrets exposé!"
                });
            }

            return Json(new { success = false, error = "Fichier non trouvé" });
        }

        // Helper pour compter les secrets
        private int CountSecrets(string content)
        {
            var secretPatterns = new[]
            {
                "password", "secret", "key", "token", "credential",
                "AKIA", "sk_live", "ghp_", "-----BEGIN"
            };

            return secretPatterns.Count(pattern =>
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        // VULNÉRABLE : Génération de tokens avec Random non sécurisé
        [HttpGet]
        public IActionResult InsecureRandom()
        {
            // VULNÉRABLE : Utilisation de Random au lieu de RNGCryptoServiceProvider
            var random = new Random();
            var tokens = new List<string>();

            for (int i = 0; i < 5; i++)
            {
                // VULNÉRABLE : Token prévisible
                var token = "";
                for (int j = 0; j < 16; j++)
                {
                    token += random.Next(0, 10).ToString();
                }
                tokens.Add(token);
            }

            // VULNÉRABLE : Session ID faible
            var sessionId = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 16);

            // VULNÉRABLE : Seed prévisible
            var seededRandom = new Random(DateTime.Now.Millisecond);
            var predictableToken = seededRandom.Next(100000, 999999);

            return Json(new
            {
                success = true,
                message = "Tokens générés avec Random() non sécurisé!",
                vulnerableTokens = tokens,
                sessionId = sessionId,
                predictableToken = predictableToken,
                seed = DateTime.Now.Millisecond,
                warning = "Random() est prévisible et ne doit pas être utilisé pour la sécurité!"
            });
        }

        // VULNÉRABLE : Configuration TLS faible
        [HttpGet]
        public IActionResult WeakTLSConfig()
        {
            return Json(new
            {
                success = true,
                message = "Configuration TLS/SSL vulnérable détectée!",
                tlsConfig = new
                {
                    // VULNÉRABLE : Protocoles obsolètes
                    enabledProtocols = new[] { "SSLv3", "TLS1.0", "TLS1.1" },

                    // VULNÉRABLE : Chiffrements faibles
                    cipherSuites = new[]
                    {
                        "TLS_RSA_WITH_RC4_128_SHA",
                        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                        "TLS_RSA_WITH_NULL_SHA256",
                        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
                    },

                    // VULNÉRABLE : Pas de certificate pinning
                    certificatePinning = false,

                    // VULNÉRABLE : Validation de certificat désactivée
                    validateCertificate = false,

                    // VULNÉRABLE : Renegotiation non sécurisée
                    secureRenegotiation = false
                },
                warning = "Configuration TLS vulnérable aux attaques BEAST, CRIME, POODLE!"
            });
        }

        // VULNÉRABLE : Transmission de données sensibles sans chiffrement
        [HttpGet]
        public IActionResult UnencryptedTransmission()
        {
            // Simuler une transmission HTTP non sécurisée
            var sensitiveData = new
            {
                // VULNÉRABLE : Données sensibles transmises en clair
                creditCard = new
                {
                    number = "4111111111111111",
                    cvv = "123",
                    expiry = "12/25",
                    holder = "John Doe"
                },

                // VULNÉRABLE : Credentials en clair sur HTTP
                loginForm = new
                {
                    action = "http://example.com/login", // HTTP au lieu de HTTPS
                    username = "user@example.com",
                    password = "P@ssw0rd123",
                    rememberMe = true
                },

                // VULNÉRABLE : API calls non sécurisés
                apiCalls = new[]
                {
                    "http://api.example.com/users?token=secret123",
                    "http://api.example.com/payment?card=4111111111111111",
                    "http://internal-api:8080/admin?key=master_key"
                },

                // VULNÉRABLE : Cookies sans flag Secure
                cookies = new[]
                {
                    "sessionId=abc123; HttpOnly",  // Manque Secure
                    "authToken=xyz789",  // Manque HttpOnly et Secure
                    "userData=base64_encoded_sensitive_data"
                }
            };

            return Json(new
            {
                success = true,
                message = "Données sensibles transmises sans chiffrement!",
                unencryptedData = sensitiveData,
                warning = "CRITIQUE: Toutes ces données sont vulnérables à l'interception!"
            });
        }

        // VULNÉRABLE : Stockage de mots de passe avec encodage réversible
        [HttpGet]
        public IActionResult ReversiblePasswordStorage()
        {
            var passwords = new Dictionary<string, object>();

            // VULNÉRABLE : Base64 (pas du chiffrement!)
            var password = "P@ssw0rd123";
            passwords["base64"] = new
            {
                encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(password)),
                decoded = password,
                method = "Base64 encoding (NOT encryption!)"
            };

            // VULNÉRABLE : ROT13
            passwords["rot13"] = new
            {
                encoded = ROT13(password),
                decoded = password,
                method = "ROT13 substitution cipher"
            };

            // VULNÉRABLE : XOR simple
            byte xorKey = 42;
            passwords["xor"] = new
            {
                encoded = Convert.ToBase64String(XORCipher(Encoding.UTF8.GetBytes(password), xorKey)),
                decoded = password,
                key = xorKey,
                method = "Simple XOR cipher"
            };

            return Json(new
            {
                success = true,
                message = "Mots de passe stockés avec encodage réversible!",
                passwords = passwords,
                warning = "Ces méthodes ne sont PAS du chiffrement sécurisé!"
            });
        }

        // Helper methods pour les exemples vulnérables
        private string ROT13(string input)
        {
            return new string(input.Select(c =>
            {
                if (!char.IsLetter(c)) return c;
                char offset = char.IsUpper(c) ? 'A' : 'a';
                return (char)((((c - offset) + 13) % 26) + offset);
            }).ToArray());
        }

        private byte[] XORCipher(byte[] data, byte key)
        {
            return data.Select(b => (byte)(b ^ key)).ToArray();
        }

        // Endpoint de test mis à jour
        [HttpGet]
        public IActionResult TestEndpoints()
        {
            return Json(new
            {
                endpoints = new[]
                {
                    "GET /CryptographicFailures/ExposedSecrets",
                    "GET /CryptographicFailures/WeakHashing?password=test123",
                    "GET /CryptographicFailures/GetUserSecrets?username=alice",
                    "POST /CryptographicFailures/WeakEncryption",
                    "GET /CryptographicFailures/GetPrivateKeys",
                    "GET /CryptographicFailures/GetLogs",
                    "GET /CryptographicFailures/GetConfig",
                    "GET /CryptographicFailures/GetConfigFiles",
                    "GET /CryptographicFailures/GetConfigFiles?filename=appsettings.json",
                    "GET /CryptographicFailures/GetConfigFiles?filename=web.config",
                    "GET /CryptographicFailures/GetConfigFiles?filename=.env",
                    "GET /CryptographicFailures/InsecureRandom",
                    "GET /CryptographicFailures/WeakTLSConfig",
                    "GET /CryptographicFailures/UnencryptedTransmission",
                    "GET /CryptographicFailures/ReversiblePasswordStorage"
                },
                vulnerabilities = new[]
                {
                    "Hardcoded secrets (API keys, passwords)",
                    "Weak hashing (MD5, SHA1)",
                    "Plaintext storage",
                    "Weak encryption (DES, ECB)",
                    "Exposed private keys",
                    "Secrets in logs",
                    "Secrets in configuration files",
                    "Config files (.env, appsettings.json, web.config)",
                    "Insecure random number generation",
                    "Weak TLS/SSL configuration",
                    "Unencrypted data transmission",
                    "Reversible password encoding"
                }
            });
        }
    }

    // Modèles
    public class SecretExposure
    {
        public string AttackType { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class UserSecrets
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string PasswordMD5 { get; set; } = string.Empty;
        public string ApiToken { get; set; } = string.Empty;
        public string RecoveryCode { get; set; } = string.Empty;
        public string TwoFactorSecret { get; set; } = string.Empty;
        public string CreditCard { get; set; } = string.Empty;
        public string SSN { get; set; } = string.Empty;
    }

    public class EncryptRequest
    {
        public string Data { get; set; } = string.Empty;
    }
}