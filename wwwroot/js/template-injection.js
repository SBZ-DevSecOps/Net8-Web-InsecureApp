// template-injection.js - Gestion spécifique pour Template Injection

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeTemplateInjection();
    });

    function initializeTemplateInjection() {
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
        if (window.templateInjectionData && window.templateInjectionData.hasResults) {
            addToHistory(
                window.templateInjectionData.attackType,
                window.templateInjectionData.payload,
                true
            );
        }

        // Initialiser les animations et tooltips
        initializeAnimations();
        initializeTooltips();
    }

    function handleAttackTypeChange() {
        const attackTypeSelect = document.getElementById('attackType');
        const attackType = attackTypeSelect.value;
        const payloadExample = document.getElementById('payloadExample');
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadTextarea = document.getElementById('payload');

        if (!attackType) {
            payloadExample.style.display = 'none';
            return;
        }

        // Récupérer depuis les attributs data de l'option sélectionnée
        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        if (payloadExampleFromData) {
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';

            // Remplir automatiquement le textarea
            payloadTextarea.value = payloadExampleFromData;

            // Ajuster la hauteur du textarea
            autoResizeTextarea(payloadTextarea);

            updateContextualHelp(attackType);

            // Animation d'apparition
            payloadExample.classList.remove('fade-in');
            void payloadExample.offsetWidth; // Trigger reflow
            payloadExample.classList.add('fade-in');
        }
    }

    function updateContextualHelp(attackType) {
        // Mettre en évidence les éléments pertinents
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            card.classList.remove('highlight-danger');
        });

        // Highlight spécifique selon le type
        if (attackType === 'razor-compile' || attackType === 'code-injection') {
            const compileCard = Array.from(cards).find(card =>
                card.textContent.includes('Compilation & Exécution'));
            if (compileCard) {
                compileCard.classList.add('highlight-danger');
            }
        }
    }

    function autoResizeTextarea(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 300) + 'px';
    }

    function addToHistory(attackType, payload, success) {
        const historyContainer = document.getElementById('testHistory');
        if (!historyContainer) return;

        // Créer ou récupérer le conteneur d'historique
        let historyList = historyContainer.querySelector('.history-list');
        if (!historyList) {
            historyList = document.createElement('div');
            historyList.className = 'history-list';
            historyContainer.innerHTML = '';
            historyContainer.appendChild(historyList);
        }

        // Créer la nouvelle entrée
        const entry = document.createElement('div');
        entry.className = `history-entry ${success ? 'exploit-success' : 'exploit-failed'}`;

        const icon = success ?
            '<i class="fas fa-bug text-danger"></i>' :
            '<i class="fas fa-shield-alt text-success"></i>';

        const time = new Date().toLocaleTimeString();
        const typeFormatted = attackType.replace(/-/g, ' ').toUpperCase();

        entry.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    ${icon}
                    <span class="time">${time}</span> - 
                    <span class="type">${typeFormatted}</span>
                </div>
                <span class="badge bg-${success ? 'danger' : 'success'}">
                    ${success ? 'RCE' : 'Protégé'}
                </span>
            </div>
            <div class="payload-preview mt-1">
                <small><code>${escapeHtml(payload.substring(0, 50))}${payload.length > 50 ? '...' : ''}</code></small>
            </div>
        `;

        // Ajouter en haut de la liste
        historyList.insertBefore(entry, historyList.firstChild);

        // Limiter à 10 entrées
        while (historyList.children.length > 10) {
            historyList.removeChild(historyList.lastChild);
        }

        // Animation d'entrée
        entry.classList.add('slide-in');
    }

    function initializeAnimations() {
        // Animation pour les résultats
        const resultCards = document.querySelectorAll('.card');
        resultCards.forEach((card, index) => {
            if (card.closest('#testHistory')) return;

            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';

            setTimeout(() => {
                card.style.transition = 'all 0.3s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            {
                selector: '[name="attackType"]',
                title: 'Sélectionnez le type de vulnérabilité SSTI à tester'
            },
            {
                selector: '[name="payload"]',
                title: 'Le template sera automatiquement rempli avec un exemple dangereux'
            },
            {
                selector: '.btn-danger',
                title: 'Afficher les endpoints vulnérables pour l\'exécution de code'
            }
        ];

        tooltips.forEach(tooltip => {
            const elements = document.querySelectorAll(tooltip.selector);
            elements.forEach(el => {
                el.setAttribute('title', tooltip.title);
                el.setAttribute('data-bs-toggle', 'tooltip');
                el.setAttribute('data-bs-placement', 'top');
            });
        });

        // Initialiser Bootstrap tooltips
        if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            const tooltipTriggerList = [].slice.call(
                document.querySelectorAll('[data-bs-toggle="tooltip"]')
            );
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

    // Auto-resize pour le textarea
    const payloadTextarea = document.getElementById('payload');
    if (payloadTextarea) {
        payloadTextarea.addEventListener('input', function () {
            autoResizeTextarea(this);
        });

        // Initial resize si contenu présent
        if (payloadTextarea.value) {
            autoResizeTextarea(payloadTextarea);
        }
    }

    // Exposer certaines fonctions si nécessaire
    window.TemplateInjection = {
        addToHistory: addToHistory
    };

})();