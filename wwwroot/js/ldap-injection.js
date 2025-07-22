// wwwroot/js/ldap-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour LDAP Injection
    const config = {
        vulnerabilityType: 'LDAP INJECTION',
        clearResultsOnChange: true,

        // Callback pour nettoyer les résultats spécifiques à LDAP
        onClearResults: function () {
            // Masquer les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info)');
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

            // Masquer la section filtre LDAP
            const filterSection = document.querySelector('pre.bg-dark')?.closest('.mb-3');
            if (filterSection) filterSection.style.display = 'none';
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.ldapInjectionData && window.ldapInjectionData.hasResults) {
                this.addToHistory(
                    window.ldapInjectionData.attackType,
                    window.ldapInjectionData.payload,
                    !window.ldapInjectionData.hasError
                );
            }
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Fonction globale pour copier le filtre LDAP
    window.copyFilterToClipboard = async function () {
        const filterElement = document.querySelector('pre.bg-dark code');
        if (!filterElement) return;

        const text = filterElement.textContent;
        const btn = event.target.closest('button');

        await VulnerabilityTester.copyToClipboard(text, btn);
    };

    // Fonction d'export des résultats LDAP
    window.exportResults = function () {
        if (!window.ldapInjectionData || !window.ldapInjectionData.results) {
            alert('Aucun résultat à exporter');
            return;
        }

        const results = window.ldapInjectionData.results;
        const rows = [];

        // En-têtes
        rows.push(['DN', 'Attribut', 'Valeur']);

        // Données - Transformer la structure LDAP en lignes CSV
        results.forEach(entry => {
            const dn = entry.dn || entry.Dn || '';
            const attrs = entry.attributes || entry.Attributes || {};

            Object.keys(attrs).forEach(key => {
                rows.push([dn, key, attrs[key]]);
            });
        });

        // Convertir en CSV
        const csv = rows.map(row =>
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');

        VulnerabilityTester.downloadCSV(csv, 'ldap_injection_results_' + Date.now() + '.csv');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();