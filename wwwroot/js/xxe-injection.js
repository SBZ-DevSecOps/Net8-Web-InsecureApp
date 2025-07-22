// wwwroot/js/xxe-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour XXE Injection
    const config = {
        vulnerabilityType: 'XXE INJECTION',
        clearResultsOnChange: true,
        payloadInputId: 'payload', // Textarea au lieu d'input

        // Callback pour nettoyer les résultats spécifiques à XXE
        onClearResults: function () {
            // Masquer toutes les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info):not(.border-secondary)');
            cards.forEach(card => {
                if (!card.closest('.mt-4')?.querySelector('#testHistory')) {
                    const parent = card.closest('.mt-4');
                    if (parent && parent.querySelector('h5 .fa-file-code')) {
                        parent.style.display = 'none';
                    }
                }
            });

            // Masquer les alertes spécifiques
            const alerts = document.querySelectorAll('.alert-danger:has(.fa-times-circle), .alert-danger:has(.fa-shield-alt), .alert-secondary:not(:has(#payloadExampleContent))');
            alerts.forEach(alert => {
                if (!alert.querySelector('#testHistory')) {
                    alert.style.display = 'none';
                }
            });
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.xxeInjectionData && window.xxeInjectionData.hasResults) {
                this.addToHistory(
                    window.xxeInjectionData.attackType,
                    window.xxeInjectionData.payload,
                    !window.xxeInjectionData.hasError
                );
            }
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Override de la méthode showExample pour mieux gérer les payloads multilignes
    const originalShowExample = tester.showExample;
    tester.showExample = function (payload) {
        // Afficher l'exemple dans la zone d'exemple uniquement
        if (this.elements.payloadExample && this.elements.payloadExampleContent) {
            this.elements.payloadExampleContent.textContent = payload;
            this.elements.payloadExample.style.display = 'block';

            // Animation
            this.elements.payloadExample.classList.remove('fade-in');
            void this.elements.payloadExample.offsetWidth;
            this.elements.payloadExample.classList.add('fade-in');
        }

        // Ajuster la hauteur du textarea si nécessaire
        if (this.elements.payloadInput && this.elements.payloadInput.tagName === 'TEXTAREA') {
            const lines = payload.split('\n').length;
            this.elements.payloadInput.rows = Math.max(6, Math.min(15, lines + 2));
        }
    };

    // Fonction d'export des résultats XXE
    window.exportResults = function () {
        if (!window.xxeInjectionData || !window.xxeInjectionData.results || window.xxeInjectionData.results.length === 0) {
            alert('Aucun résultat à exporter');
            return;
        }

        const result = window.xxeInjectionData.results[0];
        const rows = [];

        // En-têtes
        rows.push(['Type', 'Valeur']);

        // Données
        rows.push(['Input XML', result.inputXml || result.InputXml || '']);
        rows.push(['Processed XML', result.processedXml || result.ProcessedXml || '']);
        rows.push(['Processing Time (ms)', (result.processingTime || result.ProcessingTime || 0).toString()]);

        // Ressources externes
        const externalResources = result.externalResourcesAccessed || result.ExternalResourcesAccessed || [];
        if (externalResources.length > 0) {
            externalResources.forEach((resource, index) => {
                rows.push([`External Resource ${index + 1}`, resource]);
            });
        }

        // Entités résolues
        const resolvedEntities = result.resolvedEntities || result.ResolvedEntities || {};
        Object.keys(resolvedEntities).forEach(key => {
            rows.push([`Entity &${key};`, resolvedEntities[key]]);
        });

        // Convertir en CSV
        const csv = rows.map(row =>
            row.map(cell => `"${String(cell).replace(/"/g, '""').replace(/\n/g, ' ')}"`).join(',')
        ).join('\n');

        VulnerabilityTester.downloadCSV(csv, 'xxe_injection_results_' + Date.now() + '.csv');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();