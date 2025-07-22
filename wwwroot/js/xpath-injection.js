// wwwroot/js/xpath-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour XPath Injection
    const config = {
        vulnerabilityType: 'XPATH INJECTION',
        clearResultsOnChange: true,

        // Callback pour nettoyer les résultats spécifiques à XPath
        onClearResults: function () {
            // Masquer les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info):not(.border-secondary)');
            cards.forEach(card => {
                if (!card.closest('.mt-4')?.querySelector('#testHistory')) {
                    card.style.display = 'none';
                }
            });

            // Masquer les alertes spécifiques
            const alerts = document.querySelectorAll('.alert-info:has(.fa-info-circle), .alert-danger:has(.fa-times-circle), .alert-warning:has(.fa-search)');
            alerts.forEach(alert => {
                if (!alert.querySelector('#testHistory')) {
                    alert.style.display = 'none';
                }
            });

            // Masquer la section requête XPath
            const xpathSection = document.querySelector('pre.bg-dark')?.closest('.mb-3');
            if (xpathSection) xpathSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.xpathInjectionData && window.xpathInjectionData.hasResults) {
                this.addToHistory(
                    window.xpathInjectionData.attackType,
                    window.xpathInjectionData.payload,
                    !window.xpathInjectionData.hasError
                );
            }
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Fonction globale pour copier la requête XPath
    window.copyXPathToClipboard = async function () {
        const xpathElement = document.querySelector('pre.bg-dark code');
        if (!xpathElement) return;

        const text = xpathElement.textContent;
        const btn = event.target.closest('button');

        await VulnerabilityTester.copyToClipboard(text, btn);
    };

    // Fonction d'export des résultats XPath
    window.exportResults = function () {
        if (!window.xpathInjectionData || !window.xpathInjectionData.results) {
            alert('Aucun résultat à exporter');
            return;
        }

        const results = window.xpathInjectionData.results;
        const rows = [];

        // En-têtes
        rows.push(['NodePath', 'NodeType', 'Attribute/Element', 'Value']);

        // Données - Transformer la structure XPath en lignes CSV
        results.forEach(result => {
            const nodePath = result.nodePath || result.NodePath || '';
            const nodeType = result.nodeType || result.NodeType || '';
            const attributes = result.attributes || result.Attributes || {};
            const elements = result.elements || result.Elements || {};

            // Ajouter les attributs
            Object.keys(attributes).forEach(key => {
                rows.push([nodePath, nodeType, `@${key}`, attributes[key]]);
            });

            // Ajouter les éléments
            Object.keys(elements).forEach(key => {
                rows.push([nodePath, nodeType, key, elements[key]]);
            });

            // Si pas d'attributs ni d'éléments, ajouter une ligne pour le nœud
            if (Object.keys(attributes).length === 0 && Object.keys(elements).length === 0) {
                rows.push([nodePath, nodeType, '', '']);
            }
        });

        // Convertir en CSV
        const csv = rows.map(row =>
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');

        VulnerabilityTester.downloadCSV(csv, 'xpath_injection_results_' + Date.now() + '.csv');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();