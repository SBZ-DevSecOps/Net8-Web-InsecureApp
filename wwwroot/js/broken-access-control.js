// broken-access-control.js - Gestion spécifique pour Broken Access Control

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeBrokenAccessControl();
    });

    function initializeBrokenAccessControl() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                // Utiliser setTimeout pour s'assurer que le DOM est prêt
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Gestionnaire pour le bouton "Utiliser cet exemple"
        const useExampleBtn = document.getElementById('useExampleBtn');
        if (useExampleBtn) {
            useExampleBtn.addEventListener('click', useExamplePayload);
        }

        // Ajouter à l'historique si nous avons des résultats
        if (window.brokenAccessControlData && window.brokenAccessControlData.hasResults) {
            addToHistory(
                window.brokenAccessControlData.attackType,
                window.brokenAccessControlData.payload,
                window.brokenAccessControlData.results[0]?.Success || false
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
                        updateContextualHelp(attackType, payloadInput);
                    }
                }
            } catch (e) {
                console.error('Erreur lors du parsing des données d\'attaque:', e);
            }
        }
    }

    function updateContextualHelp(attackType, payloadInput) {
        // Ajouter des placeholders contextuels
        const placeholders = {
            'idor': '/profile/2 ou /api/user/3 ou /document/5',
            'missing-auth': '/admin/dashboard ou /api/admin/users',
            'privilege-escalation': 'role=admin ou isAdmin=true&userId=1',
            'path-traversal': '../../../../etc/passwd ou ../../../web.config',
            'forced-browsing': '/backup/database.sql ou /.git/config ou /logs/error.log',
            'jwt-manipulation': '{"alg":"none"}{"user":"alice","role":"admin"}',
            'api-access': 'DELETE /api/user/2 ou GET /api/users/all',
            'cors-misconfiguration': 'Origin: https://evil.com'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }

        // Ajouter des conseils visuels
        highlightVulnerabilityIndicators(attackType);
    }

    function useExamplePayload() {
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadInput = document.getElementById('payload');

        if (payloadExampleContent && payloadInput) {
            payloadInput.value = payloadExampleContent.textContent;
            payloadInput.focus();

            // Animation visuelle
            payloadInput.classList.add('pulse-animation');
            setTimeout(() => {
                payloadInput.classList.remove('pulse-animation');
            }, 1000);
        }
    }

    function highlightVulnerabilityIndicators(attackType) {
        // Mettre en évidence les éléments de l'interface liés à la vulnérabilité
        const userContext = document.querySelector('.alert-info');

        if (attackType === 'idor' && userContext) {
            userContext.classList.add('highlight-context');
            setTimeout(() => {
                userContext.classList.remove('highlight-context');
            }, 3000);
        }
    }

    function addToHistory(attackType, payload, success) {
        const historyContainer = document.getElementById('testHistory');
        if (!historyContainer) return;

        // Récupérer l'historique existant
        let history = [];
        const existingHistory = historyContainer.querySelector('.history-entries');
        if (existingHistory) {
            history = Array.from(existingHistory.children).map(entry => ({
                time: entry.querySelector('.time').textContent,
                type: entry.querySelector('.type').textContent,
                payload: entry.querySelector('.payload').textContent,
                success: entry.classList.contains('success')
            }));
        }

        // Ajouter la nouvelle entrée
        const now = new Date().toLocaleTimeString();
        history.unshift({
            time: now,
            type: attackType.toUpperCase(),
            payload: payload,
            success: success
        });

        // Limiter à 10 entrées
        history = history.slice(0, 10);

        // Reconstruire l'affichage
        let historyHtml = '<div class="history-entries">';
        history.forEach(entry => {
            const statusIcon = entry.success ?
                '<i class="fas fa-check-circle text-danger"></i>' :
                '<i class="fas fa-times-circle text-success"></i>';
            const statusClass = entry.success ? 'success' : 'failed';

            historyHtml += `
                <div class="history-entry ${statusClass}">
                    ${statusIcon}
                    <span class="time">${entry.time}</span> - 
                    <span class="type">${entry.type}</span>: 
                    <code class="payload">${escapeHtml(entry.payload)}</code>
                </div>
            `;
        });
        historyHtml += '</div>';

        historyContainer.innerHTML = historyHtml;
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: '[name="attackType"]', title: 'Sélectionnez le type de vulnérabilité à tester' },
            { selector: '[name="payload"]', title: 'Entrez la requête ou le payload malveillant' },
            { selector: '.btn-danger', title: 'Exécuter l\'attaque avec le payload spécifié' }
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
    window.BrokenAccessControl = {
        addToHistory: addToHistory,
        highlightVulnerabilityIndicators: highlightVulnerabilityIndicators
    };

})();