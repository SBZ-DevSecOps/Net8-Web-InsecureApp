// cryptographic-failures.js - Gestion spécifique pour Cryptographic Failures

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeCryptographicFailures();
    });

    function initializeCryptographicFailures() {
        console.log('Initializing Cryptographic Failures module...');

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
        } else {
            console.error('Attack type select not found!');
        }

        // Ajouter à l'historique si nous avons des résultats
        if (window.cryptographicFailuresData && window.cryptographicFailuresData.hasResults) {
            addToHistory(
                window.cryptographicFailuresData.attackType,
                window.cryptographicFailuresData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Simuler la détection de secrets dans la page
        simulateSecretDetection();
    }

    function handleAttackTypeChange() {
        const attackTypeSelect = document.getElementById('attackType');
        const attackType = attackTypeSelect.value;
        const payloadExample = document.getElementById('payloadExample');
        const payloadExampleContent = document.getElementById('payloadExampleContent');
        const payloadInput = document.getElementById('payload');

        console.log('Attack type changed to:', attackType);

        if (!attackType) {
            payloadExample.style.display = 'none';
            return;
        }

        // Récupérer l'exemple depuis l'option sélectionnée
        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        console.log('Payload example from data:', payloadExampleFromData);

        if (payloadExampleFromData) {
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';
            updateContextualHelp(attackType, payloadInput);
            return;
        }

        // Si pas trouvé dans data attribute, essayer de récupérer depuis attackInfosData
        const attackInfosData = document.getElementById('attackInfosData');
        if (attackInfosData) {
            try {
                const attackInfos = JSON.parse(attackInfosData.textContent);
                console.log('Attack infos:', attackInfos);

                // Chercher la clé correspondante (case insensitive)
                let attackInfo = null;
                for (const key in attackInfos) {
                    if (key.toLowerCase() === attackType.toLowerCase()) {
                        attackInfo = attackInfos[key];
                        break;
                    }
                }

                if (attackInfo && attackInfo.PayloadExample) {
                    payloadExampleContent.textContent = attackInfo.PayloadExample;
                    payloadExample.style.display = 'block';
                    updateContextualHelp(attackType, payloadInput);
                }
            } catch (e) {
                console.error('Erreur lors du parsing des données d\'attaque:', e);
            }
        }
    }

    function updateContextualHelp(attackType, payloadInput) {
        // Ajouter des placeholders contextuels
        const placeholders = {
            'hardcoded-secrets': 'Aucun paramètre nécessaire',
            'weak-hashing': 'password=VotreMotDePasse',
            'plaintext-storage': 'username=alice ou username=admin',
            'weak-encryption': 'Utiliser POST avec JSON',
            'exposed-keys': 'Aucun paramètre nécessaire',
            'insecure-random': 'Aucun paramètre nécessaire',
            'weak-tls': 'Aucun paramètre nécessaire',
            'missing-encryption': 'Aucun paramètre nécessaire'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
            console.log('Placeholder mis à jour:', placeholders[attackType]);
        }

        // Mettre en évidence les éléments pertinents
        highlightSecretIndicators(attackType);
    }

    function highlightSecretIndicators(attackType) {
        // Animation pour attirer l'attention sur les secrets
        const secretWarning = document.querySelector('.alert-warning');
        if (secretWarning && (attackType === 'hardcoded-secrets' || attackType === 'exposed-keys')) {
            secretWarning.classList.add('pulse-warning');
            setTimeout(() => {
                secretWarning.classList.remove('pulse-warning');
            }, 2000);
        }
    }

    function simulateSecretDetection() {
        // Simuler la détection de secrets dans le code source
        const codeExamples = document.querySelectorAll('pre code');
        codeExamples.forEach(code => {
            const text = code.textContent;

            // Patterns de secrets à détecter
            const secretPatterns = [
                { pattern: /sk_live_[\w]+/g, type: 'Stripe Secret Key' },
                { pattern: /AKIA[\w]+/g, type: 'AWS Access Key' },
                { pattern: /ghp_[\w]+/g, type: 'GitHub Token' },
                { pattern: /-----BEGIN RSA PRIVATE KEY-----/g, type: 'Private Key' },
                { pattern: /[Pp]assword\s*=\s*["'][\w@!#$%^&*]+["']/g, type: 'Hardcoded Password' }
            ];

            secretPatterns.forEach(({ pattern, type }) => {
                if (pattern.test(text)) {
                    // Ajouter une classe pour la mise en évidence
                    code.classList.add('contains-secret');

                    // Ajouter un indicateur visuel
                    const indicator = document.createElement('span');
                    indicator.className = 'secret-indicator';
                    indicator.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${type} détecté`;
                    code.parentElement.insertBefore(indicator, code);
                }
            });
        });
    }

    function addToHistory(attackType, payload, success) {
        const historyContainer = document.getElementById('cryptoHistory');
        if (!historyContainer) return;

        const now = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'history-entry fade-in';

        const icon = getSecretIcon(attackType);
        const description = getAttackDescription(attackType);

        entry.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas ${icon} text-danger me-2"></i>
                <span class="time text-muted">${now}</span>
                <span class="mx-2">-</span>
                <span class="attack-type">${attackType.toUpperCase()}</span>
                <span class="mx-2">:</span>
                <span class="description">${description}</span>
            </div>
        `;

        // Ajouter en haut de l'historique
        historyContainer.insertBefore(entry, historyContainer.firstChild);

        // Limiter à 10 entrées
        while (historyContainer.children.length > 10) {
            historyContainer.removeChild(historyContainer.lastChild);
        }
    }

    function getSecretIcon(attackType) {
        const icons = {
            'hardcoded-secrets': 'fa-key',
            'weak-hashing': 'fa-hashtag',
            'plaintext-storage': 'fa-unlock',
            'weak-encryption': 'fa-lock-open',
            'exposed-keys': 'fa-certificate',
            'insecure-random': 'fa-dice',
            'weak-tls': 'fa-shield-alt',
            'missing-encryption': 'fa-wifi'
        };
        return icons[attackType] || 'fa-exclamation-triangle';
    }

    function getAttackDescription(attackType) {
        const descriptions = {
            'hardcoded-secrets': 'Secrets exposés dans le code',
            'weak-hashing': 'Algorithme de hachage vulnérable',
            'plaintext-storage': 'Données sensibles en clair',
            'weak-encryption': 'Chiffrement obsolète utilisé',
            'exposed-keys': 'Clés privées compromises',
            'insecure-random': 'Génération aléatoire prévisible',
            'weak-tls': 'Configuration TLS vulnérable',
            'missing-encryption': 'Transmission non chiffrée'
        };
        return descriptions[attackType] || 'Test effectué';
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs sur les éléments dangereux
        const tooltips = [
            { selector: '.badge', title: 'Niveau de risque de cette vulnérabilité' },
            { selector: '.fa-key', title: 'Secret ou clé exposée' },
            { selector: '.fa-certificate', title: 'Certificat ou clé privée' },
            { selector: '.fa-hashtag', title: 'Fonction de hachage' }
        ];

        tooltips.forEach(tooltip => {
            const elements = document.querySelectorAll(tooltip.selector);
            elements.forEach(el => {
                if (!el.hasAttribute('title')) {
                    el.setAttribute('title', tooltip.title);
                    el.setAttribute('data-bs-toggle', 'tooltip');
                    el.setAttribute('data-bs-placement', 'top');
                }
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

    // Fonction pour copier un secret dans le presse-papier (pour les tests)
    function copySecret(secret) {
        navigator.clipboard.writeText(secret).then(() => {
            showNotification('Secret copié dans le presse-papier!', 'warning');
        }).catch(err => {
            console.error('Erreur lors de la copie:', err);
        });
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} notification fade-in`;
        notification.innerHTML = `
            <i class="fas fa-info-circle"></i> ${message}
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
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
    window.CryptographicFailures = {
        addToHistory: addToHistory,
        copySecret: copySecret,
        simulateSecretDetection: simulateSecretDetection,
        testPayloadExamples: testPayloadExamples
    };

})();