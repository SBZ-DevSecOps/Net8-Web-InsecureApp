// insecure-design.js - Gestion spécifique pour Insecure Design

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeInsecureDesign();
    });

    function initializeInsecureDesign() {
        console.log('Initializing Insecure Design module...');

        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            console.log('Attack type select found, adding event listener');
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);

            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                console.log('Initial value found:', attackTypeSelect.value);
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Ajouter à l'historique si nous avons des résultats
        if (window.insecureDesignData && window.insecureDesignData.hasResults) {
            addToHistory(
                window.insecureDesignData.attackType,
                window.insecureDesignData.payload,
                window.insecureDesignData.results[0]?.Success || false
            );
        }

        // Initialiser les animations et interactions
        initializeAnimations();
        initializeTooltips();
    }

    function handleAttackTypeChange() {
        const attackTypeSelect = document.getElementById('attackType');
        const attackType = attackTypeSelect.value;
        const payloadExample = document.getElementById('payloadExample');
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadHidden = document.getElementById('payload');

        console.log('Attack type changed to:', attackType);

        if (!attackType) {
            payloadExample.style.display = 'none';
            if (payloadHidden) payloadHidden.value = '';
            return;
        }

        // Récupérer l'exemple depuis l'option sélectionnée
        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        console.log('Payload example from data:', payloadExampleFromData);

        if (payloadExampleFromData) {
            // Afficher l'exemple dans la zone d'exemple
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';

            // Mettre à jour le champ caché
            if (payloadHidden) {
                payloadHidden.value = payloadExampleFromData;
            }

            // Ajouter une animation d'apparition
            payloadExample.classList.remove('fade-in');
            void payloadExample.offsetWidth; // Trigger reflow
            payloadExample.classList.add('fade-in');

            // Mettre en évidence les éléments pertinents
            highlightRelevantElements(attackType);
        }
    }

    function updatePlaceholder(attackType, payloadTextarea) {
        // Ajouter des placeholders contextuels
        const placeholders = {
            'delete-order': 'orderId=2 (commande d\'un autre utilisateur)',
            'admin-panel': 'Accès direct sans authentification',
            'add-product': 'name=TV&price=-1000',
            'reset-password': 'username=alice',
            'update-user': 'userId=101&username=pwned',
            'mass-assignment': 'JSON avec role=Admin',
            'command-exec': 'host=8.8.8.8;dir',
            'xxe-parse': 'Payload XML avec entités externes',
            'sql-concat': 'name=admin\' OR \'1\'=\'1',
            'hardcoded-secrets': 'Aucun paramètre requis',
            'path-traversal': 'filename=../../../../etc/passwd',
            'weak-crypto': 'password=test123',
            'open-redirect': 'url=http://evil.com',
            'debug-enabled': 'Aucun paramètre requis',
            'insecure-random': 'Aucun paramètre requis'
        };

        if (placeholders[attackType]) {
            payloadTextarea.placeholder = placeholders[attackType];
            console.log('Placeholder updated to:', placeholders[attackType]);
        }

        // Mettre en évidence les éléments pertinents
        highlightRelevantElements(attackType);
    }

    function useExamplePayload() {
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadTextarea = document.getElementById('payload');

        if (payloadExampleContent && payloadTextarea) {
            // Maintenant on copie l'exemple dans le textarea
            payloadTextarea.value = payloadExampleContent.textContent;
            payloadTextarea.focus();

            // Animation visuelle
            payloadTextarea.classList.add('pulse-animation');
            setTimeout(() => {
                payloadTextarea.classList.remove('pulse-animation');
            }, 1000);

            // Auto-resize du textarea
            autoResizeTextarea(payloadTextarea);
        }
    }

    function autoResizeTextarea(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = textarea.scrollHeight + 'px';
    }

    function highlightRelevantElements(attackType) {
        // Mettre en évidence les cartes d'information pertinentes
        const systemCards = document.querySelectorAll('.card');
        systemCards.forEach(card => {
            card.classList.remove('highlight-card');
        });

        // Highlighter selon le type d'attaque
        const cardMappings = {
            'admin-panel': 'Sans Autorisation',
            'delete-order': 'Sans Autorisation',
            'command-exec': 'Injections',
            'sql-concat': 'Injections',
            'xxe-parse': 'Injections',
            'path-traversal': 'Injections',
            'weak-crypto': 'Crypto/Config',
            'hardcoded-secrets': 'Crypto/Config',
            'open-redirect': 'Crypto/Config',
            'insecure-random': 'Crypto/Config'
        };

        if (cardMappings[attackType]) {
            const targetCard = Array.from(systemCards).find(card =>
                card.querySelector('.card-header')?.textContent.includes(cardMappings[attackType])
            );
            if (targetCard) {
                targetCard.classList.add('highlight-card');
            }
        }
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
                    ${success ? 'Exploité' : 'Protégé'}
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
            if (card.closest('#testHistory')) return; // Skip history cards

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
                title: 'Choisissez un défaut de conception à exploiter'
            },
            {
                selector: '.btn-danger',
                title: 'Tester cette vulnérabilité'
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

    // Fonction de test pour débugger
    function testPayloadExamples() {
        const attackTypeSelect = document.getElementById('attackType');
        if (!attackTypeSelect) {
            console.error('Select not found!');
            return;
        }

        console.log('Options in select:');
        for (let i = 0; i < attackTypeSelect.options.length; i++) {
            const option = attackTypeSelect.options[i];
            console.log(`Option ${i}: value="${option.value}", payload="${option.getAttribute('data-payload-example')}"`);
        }
    }

    // Exposer certaines fonctions si nécessaire
    window.InsecureDesign = {
        addToHistory: addToHistory,
        highlightRelevantElements: highlightRelevantElements,
        testPayloadExamples: testPayloadExamples
    };

})();