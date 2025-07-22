// wwwroot/js/command-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour Command Injection
    const config = {
        vulnerabilityType: 'COMMAND INJECTION',
        clearResultsOnChange: true,

        // Callback pour nettoyer les résultats spécifiques à Command
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

            // Masquer la section "Commande exécutée"
            const cmdSection = document.querySelector('pre.bg-dark')?.closest('.mb-3');
            if (cmdSection) cmdSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.commandInjectionData && window.commandInjectionData.hasResults) {
                this.addToHistory(
                    window.commandInjectionData.attackType,
                    window.commandInjectionData.payload,
                    !window.commandInjectionData.hasError
                );
            }
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Fonction globale pour copier la commande
    window.copyCommandToClipboard = async function () {
        const commandElement = document.querySelector('pre code');
        if (!commandElement) return;

        const text = commandElement.textContent;
        const btn = event.target.closest('button');

        await VulnerabilityTester.copyToClipboard(text, btn);
    };

    // Fonction d'export des résultats
    window.exportResults = function () {
        if (!window.commandInjectionData || !window.commandInjectionData.results) {
            alert('Aucun résultat à exporter');
            return;
        }

        const results = window.commandInjectionData.results;

        // Transformer les données pour l'export CSV
        const csvData = results.map(r => ({
            Command: r.command || r.Command || '',
            Output: (r.output || r.Output || '').replace(/[\r\n]+/g, ' '),
            ExecutionTime: r.executionTime || r.ExecutionTime || 0,
            Success: (r.success || r.Success) ? 'Oui' : 'Non'
        }));

        const csv = VulnerabilityTester.convertToCSV(csvData, ['Command', 'Output', 'ExecutionTime', 'Success']);
        VulnerabilityTester.downloadCSV(csv, 'command_injection_' + Date.now() + '.csv');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();