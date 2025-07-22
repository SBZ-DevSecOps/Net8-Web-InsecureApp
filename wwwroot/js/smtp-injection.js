// smtp-injection.js - Gestion spécifique pour SMTP Injection

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeSmtpInjection();
    });

    function initializeSmtpInjection() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Ajouter à l'historique si nous avons des résultats
        if (window.smtpInjectionData && window.smtpInjectionData.hasResults) {
            addToHistory(
                window.smtpInjectionData.attackType,
                window.smtpInjectionData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();
    }

    function handleAttackTypeChange() {
        const attackTypeSelect = document.getElementById('attackType');
        const attackType = attackTypeSelect.value;
        const payloadExample = document.getElementById('payloadExample');
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadInput = document.getElementById('payload');

        if (!attackType) {
            payloadExample.style.display = 'none';
            return;
        }

        // Méthode 1 : Récupérer depuis les attributs data de l'option sélectionnée
        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        if (payloadExampleFromData) {
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';

            // Remplir automatiquement le champ payload
            payloadInput.value = payloadExampleFromData;

            updateContextualHelp(attackType, payloadInput);
            return;
        }

        // Méthode 2 : Récupérer depuis les données JSON (fallback)
        const attackInfosData = document.getElementById('attackInfosData');
        if (attackInfosData) {
            try {
                const attackInfos = JSON.parse(attackInfosData.textContent);
                const attackInfo = attackInfos[attackType];

                if (attackInfo) {
                    // Essayer les deux conventions de nommage
                    const payloadExampleText = attackInfo.payloadExample || attackInfo.PayloadExample;

                    if (payloadExampleText) {
                        payloadExampleContent.textContent = payloadExampleText;
                        payloadExample.style.display = 'block';

                        // Remplir automatiquement le champ payload
                        payloadInput.value = payloadExampleText;

                        updateContextualHelp(attackType, payloadInput);
                    }
                }
            } catch (e) {
                console.error('Erreur lors du parsing des données d\'attaque:', e);
            }
        }
    }

    function updateContextualHelp(attackType, payloadInput) {
        // Ajouter des placeholders contextuels selon le type d'attaque
        const placeholders = {
            'header-injection': 'victim@example.com%0ABcc: attacker@evil.com',
            'log-injection': 'test@example.com%0A[ADMIN] User promoted to admin',
            'command-injection': 'test@example.com; cat /etc/passwd',
            'template-injection': 'Bonjour {{username}}, résultat: {{7*7}}',
            'open-relay': 'Destination non autorisée pour tester le relais'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }

        // Ajouter des animations visuelles
        highlightVulnerabilityIndicators(attackType);
    }

    function highlightVulnerabilityIndicators(attackType) {
        // Mettre en évidence les éléments pertinents selon le type d'attaque
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            card.classList.remove('highlight-vulnerability');
        });

        // Highlight spécifique selon le type
        if (attackType === 'header-injection') {
            const headerCard = Array.from(cards).find(card =>
                card.textContent.includes("Injection d'en-têtes"));
            if (headerCard) {
                headerCard.classList.add('highlight-vulnerability');
            }
        }
    }

    function addToHistory(attackType, payload, success) {
        const historyContainer = document.getElementById('testHistory');
        if (!historyContainer) return;

        // Créer ou récupérer le conteneur d'historique
        let historyList = historyContainer.querySelector('.history-entries');
        if (!historyList) {
            historyList = document.createElement('div');
            historyList.className = 'history-entries';
            historyContainer.innerHTML = '';
            historyContainer.appendChild(historyList);
        }

        // Créer la nouvelle entrée
        const entry = document.createElement('div');
        entry.className = `history-entry ${success ? 'success' : 'failed'}`;

        const icon = success ?
            '<i class="fas fa-envelope text-success"></i>' :
            '<i class="fas fa-times-circle text-danger"></i>';

        const time = new Date().toLocaleTimeString();
        const typeFormatted = attackType.replace(/-/g, ' ').toUpperCase();

        entry.innerHTML = `
            ${icon}
            <span class="time">${time}</span> - 
            <span class="type">${typeFormatted}</span>: 
            <code class="payload">${escapeHtml(payload.substring(0, 50))}${payload.length > 50 ? '...' : ''}</code>
        `;

        // Ajouter en haut de la liste
        historyList.insertBefore(entry, historyList.firstChild);

        // Limiter à 10 entrées
        while (historyList.children.length > 10) {
            historyList.removeChild(historyList.lastChild);
        }
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: '[name="attackType"]', title: 'Sélectionnez le type de vulnérabilité SMTP à tester' },
            { selector: '[name="payload"]', title: 'Le payload sera automatiquement rempli selon votre sélection' },
            { selector: '.btn-danger', title: 'Afficher les endpoints vulnérables pour ce type d\'attaque' }
        ];

        tooltips.forEach(tooltip => {
            const elements = document.querySelectorAll(tooltip.selector);
            elements.forEach(el => {
                el.setAttribute('title', tooltip.title);
                el.setAttribute('data-bs-toggle', 'tooltip');
                el.setAttribute('data-bs-placement', 'top');
            });
        });

        // Initialiser Bootstrap tooltips si disponible
        if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        }
    }

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    // Exposer certaines fonctions si nécessaire
    window.SmtpInjection = {
        addToHistory: addToHistory,
        highlightVulnerabilityIndicators: highlightVulnerabilityIndicators
    };

})();