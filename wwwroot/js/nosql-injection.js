// wwwroot/js/nosql-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour NoSQL Injection
    const config = {
        vulnerabilityType: 'NOSQL INJECTION',
        clearResultsOnChange: true,
        payloadInputId: 'payload', // Textarea pour JSON

        // Callback pour nettoyer les résultats spécifiques à NoSQL
        onClearResults: function () {
            // Masquer toutes les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info):not(.border-secondary)');
            cards.forEach(card => {
                if (!card.closest('.mt-4')?.querySelector('#testHistory')) {
                    card.style.display = 'none';
                }
            });

            // Masquer les alertes spécifiques
            const alerts = document.querySelectorAll('.alert-danger:has(.fa-exclamation-triangle), .alert-warning:has(.fa-user-secret), .alert-info:has(.fa-info-circle), .alert-secondary:not(:has(#payloadExampleContent))');
            alerts.forEach(alert => {
                if (!alert.querySelector('#testHistory') && !alert.querySelector('.container')) {
                    alert.style.display = 'none';
                }
            });

            // Masquer la section requête MongoDB
            const querySection = document.querySelector('pre.bg-dark')?.closest('.mb-3');
            if (querySection) querySection.style.display = 'none';

            // Masquer la section résultats
            const resultsSection = document.querySelector('h5 .fa-database')?.closest('.mt-4');
            if (resultsSection) resultsSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.nosqlInjectionData && window.nosqlInjectionData.hasResults) {
                this.addToHistory(
                    window.nosqlInjectionData.attackType,
                    window.nosqlInjectionData.payload,
                    !window.nosqlInjectionData.hasError
                );
            }

            // Formatter le JSON dans le textarea si présent
            this.formatJsonPayload();
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Méthode pour formatter le JSON
    tester.formatJsonPayload = function () {
        if (this.elements.payloadInput && this.elements.payloadInput.value) {
            try {
                const parsed = JSON.parse(this.elements.payloadInput.value);
                this.elements.payloadInput.value = JSON.stringify(parsed, null, 2);
            } catch (e) {
                // Ignorer les erreurs de parsing
            }
        }
    };

    // Override de showExample pour formatter le JSON
    const originalShowExample = tester.showExample;
    tester.showExample = function (payload) {
        originalShowExample.call(this, payload);

        // Formatter et ajuster la hauteur
        try {
            const parsed = JSON.parse(payload);
            const formatted = JSON.stringify(parsed, null, 2);
            this.elements.payloadInput.value = formatted;

            const lines = formatted.split('\n').length;
            this.elements.payloadInput.rows = Math.max(4, Math.min(12, lines + 1));
        } catch (e) {
            // Si ce n'est pas du JSON valide, garder tel quel
            const lines = payload.split('\n').length;
            this.elements.payloadInput.rows = Math.max(4, Math.min(12, lines + 1));
        }
    };

    // Fonction globale pour copier la requête MongoDB
    window.copyQueryToClipboard = async function () {
        const queryElement = document.querySelector('pre.bg-dark code');
        if (!queryElement) return;

        const text = queryElement.textContent;
        const btn = event.target.closest('button');

        await VulnerabilityTester.copyToClipboard(text, btn);
    };

    // Fonction d'export des résultats NoSQL en JSON
    window.exportResults = function () {
        if (!window.nosqlInjectionData || !window.nosqlInjectionData.results || window.nosqlInjectionData.results.length === 0) {
            alert('Aucun résultat à exporter');
            return;
        }

        const result = window.nosqlInjectionData.results[0];
        const exportData = {
            query: result.query || result.Query,
            executionTime: result.executionTime || result.ExecutionTime,
            javascriptExecuted: result.javaScriptExecuted || result.JavaScriptExecuted,
            sensitiveDataExposed: result.sensitiveDataExposed || result.SensitiveDataExposed,
            documentsFound: []
        };

        // Extraire les documents
        const documents = result.matchedDocuments || result.MatchedDocuments || [];
        documents.forEach(doc => {
            const docData = {
                _id: doc.id || doc.Id,
                ...doc.data || doc.Data
            };
            exportData.documentsFound.push(docData);
        });

        // Convertir en JSON et télécharger
        const json = JSON.stringify(exportData, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'nosql_injection_results_' + Date.now() + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    // Event listener pour formater le JSON lors de la saisie
    document.addEventListener('DOMContentLoaded', function () {
        const payloadInput = document.getElementById('payload');
        if (payloadInput) {
            let formatTimer;
            payloadInput.addEventListener('blur', function () {
                clearTimeout(formatTimer);
                formatTimer = setTimeout(() => {
                    try {
                        const parsed = JSON.parse(this.value);
                        this.value = JSON.stringify(parsed, null, 2);
                    } catch (e) {
                        // Ignorer si ce n'est pas du JSON valide
                    }
                }, 500);
            });
        }
    });

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();