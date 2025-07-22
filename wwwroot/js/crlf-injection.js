// wwwroot/js/crlf-injection.js

(function () {
    'use strict';

    // Configuration spécifique pour CRLF Injection
    const config = {
        vulnerabilityType: 'CRLF INJECTION',
        clearResultsOnChange: true,
        payloadInputId: 'payload',

        // Callback pour nettoyer les résultats spécifiques à CRLF Injection
        onClearResults: function () {
            // Masquer toutes les cartes de résultats
            const cards = document.querySelectorAll('.card:not(.border-info):not(.border-secondary)');
            cards.forEach(card => {
                if (!card.closest('.mt-4')?.querySelector('#testHistory')) {
                    const parent = card.closest('.mt-4');
                    if (parent && parent.querySelector('h5 .fa-network-wired')) {
                        parent.style.display = 'none';
                    }
                }
            });

            // Masquer les alertes spécifiques
            const alerts = document.querySelectorAll('.alert-warning:has(.fa-check-circle), .alert-danger:has(.fa-shield-alt), .alert-secondary:not(:has(#payloadExampleContent))');
            alerts.forEach(alert => {
                if (!alert.querySelector('#testHistory')) {
                    alert.style.display = 'none';
                }
            });
        },

        // Callback après initialisation
        onInitialized: function () {
            // Ajouter à l'historique si on a des résultats
            if (window.crlfInjectionData && window.crlfInjectionData.hasResults) {
                this.addToHistory(
                    window.crlfInjectionData.attackType,
                    window.crlfInjectionData.payload,
                    !window.crlfInjectionData.hasError
                );
            }

            // Ajouter un handler pour les caractères spéciaux
            this.setupSpecialCharacterHelpers();
        }
    };

    // Créer l'instance
    const tester = new VulnerabilityTester(config);

    // Ajouter des helpers pour les caractères spéciaux
    tester.setupSpecialCharacterHelpers = function () {
        // Créer un bouton d'aide pour les caractères CRLF
        const payloadGroup = this.elements.payloadInput.parentElement;

        const helperDiv = document.createElement('div');
        helperDiv.className = 'mt-2';
        helperDiv.innerHTML = `
            <small class="text-muted">Caractères spéciaux :</small>
            <div class="btn-group btn-group-sm ms-2" role="group">
                <button type="button" class="btn btn-outline-secondary" data-insert="\\r\\n" title="Carriage Return + Line Feed">
                    \\r\\n
                </button>
                <button type="button" class="btn btn-outline-secondary" data-insert="%0d%0a" title="URL Encoded CRLF">
                    %0d%0a
                </button>
                <button type="button" class="btn btn-outline-secondary" data-insert="%0D%0A" title="URL Encoded CRLF (uppercase)">
                    %0D%0A
                </button>
            </div>
        `;

        payloadGroup.appendChild(helperDiv);

        // Ajouter les event listeners
        helperDiv.querySelectorAll('[data-insert]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const textToInsert = e.target.getAttribute('data-insert');
                const input = this.elements.payloadInput;
                const start = input.selectionStart;
                const end = input.selectionEnd;
                const value = input.value;

                input.value = value.substring(0, start) + textToInsert + value.substring(end);
                input.focus();
                input.setSelectionRange(start + textToInsert.length, start + textToInsert.length);
            });
        });
    };

    // Override de la méthode showExample pour gérer les caractères spéciaux
    const originalShowExample = tester.showExample;
    tester.showExample = function (payload) {
        // Afficher le payload tel quel, sans traitement
        if (this.elements.payloadExampleContent) {
            this.elements.payloadExampleContent.textContent = payload;
        }

        if (this.elements.payloadExample) {
            this.elements.payloadExample.style.display = 'block';
        }
    };

    // Fonction d'export des résultats CRLF Injection
    window.exportResults = function () {
        if (!window.crlfInjectionData || !window.crlfInjectionData.results || window.crlfInjectionData.results.length === 0) {
            alert('Aucun résultat à exporter');
            return;
        }

        const result = window.crlfInjectionData.results[0];
        const rows = [];

        // En-têtes
        rows.push(['Type', 'Valeur']);

        // Données
        rows.push(['Payload Original', result.originalPayload || result.OriginalPayload || '']);
        rows.push(['Type d\'attaque', result.attackType || result.AttackType || '']);
        rows.push(['CRLF Détecté', (result.crlfDetected || result.CrlfDetected) ? 'Oui' : 'Non']);
        rows.push(['Score de Risque', (result.riskScore || result.RiskScore || 0).toString() + '%']);

        // En-têtes injectés
        const injectedHeaders = result.injectedHeaders || result.InjectedHeaders || {};
        Object.keys(injectedHeaders).forEach(key => {
            rows.push([`En-tête injecté: ${key}`, injectedHeaders[key]]);
        });

        // Modifications de la réponse
        const modifications = result.responseModifications || result.ResponseModifications || [];
        modifications.forEach((mod, index) => {
            rows.push([`Modification ${index + 1}`, mod]);
        });

        // Impact de sécurité
        const impacts = result.securityImpact || result.SecurityImpact || [];
        impacts.forEach((impact, index) => {
            rows.push([`Impact ${index + 1}`, impact]);
        });

        // Contenu injecté
        if (result.injectedContent || result.InjectedContent) {
            rows.push(['Contenu injecté', (result.injectedContent || result.InjectedContent).replace(/\n/g, ' ')]);
        }

        // Convertir en CSV
        const csv = rows.map(row =>
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');

        VulnerabilityTester.downloadCSV(csv, 'crlf_injection_results_' + Date.now() + '.csv');
    };

    // Fonction pour visualiser les caractères spéciaux
    tester.visualizePayload = function (payload) {
        return payload
            .replace(/\r/g, '<span class="text-danger">\\r</span>')
            .replace(/\n/g, '<span class="text-danger">\\n</span>')
            .replace(/%0d/gi, '<span class="text-warning">%0d</span>')
            .replace(/%0a/gi, '<span class="text-warning">%0a</span>');
    };

    // Initialisation au chargement
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tester.initialize());
    } else {
        tester.initialize();
    }
})();