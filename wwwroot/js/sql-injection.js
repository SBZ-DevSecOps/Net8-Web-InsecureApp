// wwwroot/js/sql-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour SQL Injection
    const config = {
        vulnerabilityType: 'SQL INJECTION',
        clearResultsOnChange: true,

        // Callback pour nettoyer les résultats spécifiques à SQL
        onClearResults: function () {
            const selectors = [
                '.table-responsive',
                '.alert-info:has(.fas.fa-info-circle)',
                '.alert-danger:has(.fas.fa-times-circle)'
            ];

            selectors.forEach(selector => {
                const elements = document.querySelectorAll(selector);
                elements.forEach(el => {
                    if (el && !el.querySelector('#testHistory')) {
                        el.style.display = 'none';
                    }
                });
            });

            // Masquer la section "SQL exécuté"
            const sqlSection = document.querySelector('pre.bg-light')?.closest('.mb-3');
            if (sqlSection) sqlSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats (sera géré par Razor)
            if (window.sqlInjectionData && window.sqlInjectionData.hasResults) {
                this.addToHistory(
                    window.sqlInjectionData.attackType,
                    window.sqlInjectionData.payload,
                    !window.sqlInjectionData.hasError
                );
            }
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Fonction globale pour copier le SQL
    window.copySqlToClipboard = async function () {
        const sqlElement = document.querySelector('pre.bg-light code');
        if (!sqlElement) return;

        const text = sqlElement.textContent;
        const btn = event.target.closest('button');

        await VulnerabilityTester.copyToClipboard(text, btn);
    };

    // Fonction d'export des résultats
    window.exportResults = function () {
        if (!window.sqlInjectionData || !window.sqlInjectionData.results) {
            alert('Aucun résultat à exporter');
            return;
        }

        const results = window.sqlInjectionData.results;
        const csv = VulnerabilityTester.convertToCSV(results, ['Id', 'Name', 'Description']);
        VulnerabilityTester.downloadCSV(csv, 'sql_injection_results_' + Date.now() + '.csv');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();