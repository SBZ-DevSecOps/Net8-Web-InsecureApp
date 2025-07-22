// security-misconfiguration.js - Gestion spécifique pour Security Misconfiguration

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeSecurityMisconfiguration();
    });

    function initializeSecurityMisconfiguration() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Gestionnaires pour les tests spécifiques
        initializeDefaultCredsTests();
        initializeXXETest();
        initializeCORSTest();

        // Ajouter à l'historique si nous avons des résultats
        if (window.securityMisconfigurationData && window.securityMisconfigurationData.hasResults) {
            addToHistory(
                window.securityMisconfigurationData.attackType,
                window.securityMisconfigurationData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Simuler des logs de configuration au chargement
        simulateConfigLogs();
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

        // Récupérer depuis les attributs data de l'option sélectionnée
        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        if (payloadExampleFromData) {
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';
            updateContextualHelp(attackType, payloadInput);
            return;
        }

        // Récupérer depuis les données JSON (fallback)
        const attackInfosData = document.getElementById('attackInfosData');
        if (attackInfosData) {
            try {
                const attackInfos = JSON.parse(attackInfosData.textContent);
                const attackInfo = attackInfos[attackType];

                if (attackInfo) {
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
            'debug-enabled': '/GenerateError ou /api/debug/info',
            'default-creds': 'username=admin&password=admin',
            'directory-listing': '?path=wwwroot ou ?path=Views',
            'xxe-enabled': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            'weak-crypto': '?data=SensitiveData123',
            'cors-misconfigured': 'Origin: https://evil.com',
            'headers-missing': '/CheckHeaders',
            'sensitive-data-exposure': '/GetConfig ou /GetLogs'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }

        // Ajouter des conseils visuels
        highlightConfigurationIssues(attackType);
    }

    function initializeDefaultCredsTests() {
        const buttons = document.querySelectorAll('.test-default-creds');
        buttons.forEach(button => {
            button.addEventListener('click', function () {
                const username = this.getAttribute('data-user');
                const password = this.getAttribute('data-pass');
                testDefaultCredentials(username, password);
            });
        });
    }

    function testDefaultCredentials(username, password) {
        // Simuler un test de credentials par défaut
        fetch('/SecurityMisconfiguration/AdminLogin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${username}&password=${password}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('danger', `Connexion réussie avec ${username}/${password} ! Token: ${data.token}`);
                    addToHistory('default-creds', `${username}/${password}`, true);
                } else {
                    showNotification('info', 'Credentials invalides');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function initializeXXETest() {
        const xxeButton = document.querySelector('.test-xxe');
        if (xxeButton) {
            xxeButton.addEventListener('click', function () {
                const xxePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`;

                // Afficher le payload
                showNotification('warning', 'Envoi du payload XXE...');

                // Simuler l'envoi (dans la vraie app, utiliser fetch)
                console.log('XXE Payload:', xxePayload);
                addToHistory('xxe-enabled', 'XXE payload envoyé', true);
            });
        }
    }

    function initializeCORSTest() {
        const corsButton = document.querySelector('.test-cors');
        if (corsButton) {
            corsButton.addEventListener('click', function () {
                // Simuler une requête cross-origin
                showNotification('warning', 'Test CORS depuis origine malveillante...');

                // Dans un vrai test, ceci serait fait depuis un autre domaine
                fetch('/SecurityMisconfiguration/ApiData', {
                    headers: {
                        'Origin': 'https://evil.com'
                    }
                })
                    .then(response => {
                        const corsHeader = response.headers.get('Access-Control-Allow-Origin');
                        if (corsHeader === '*') {
                            showNotification('danger', `CORS mal configuré! Allow-Origin: ${corsHeader}`);
                            addToHistory('cors-misconfigured', 'CORS: * detecté', true);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('Données exposées:', data);
                    });
            });
        }
    }

    function highlightConfigurationIssues(attackType) {
        const configAlert = document.querySelector('.alert-warning');

        if (configAlert) {
            configAlert.classList.add('highlight-config');
            setTimeout(() => {
                configAlert.classList.remove('highlight-config');
            }, 3000);
        }

        // Mettre en évidence les éléments spécifiques
        const highlights = {
            'debug-enabled': '.fa-bug',
            'default-creds': '.fa-key',
            'directory-listing': '.fa-folder-open',
            'xxe-enabled': '.fa-code',
            'weak-crypto': '.fa-lock-open',
            'cors-misconfigured': '.fa-globe',
            'headers-missing': '.fa-shield-alt'
        };

        if (highlights[attackType]) {
            const elements = document.querySelectorAll(highlights[attackType]);
            elements.forEach(el => {
                el.classList.add('pulse-icon');
                setTimeout(() => {
                    el.classList.remove('pulse-icon');
                }, 2000);
            });
        }
    }

    function simulateConfigLogs() {
        // Simuler des logs de configuration dans la console
        console.warn('%c⚠️ Configuration Warning', 'color: orange; font-size: 16px; font-weight: bold');
        console.log('Debug mode: ENABLED');
        console.log('Environment: Development');
        console.log('CORS: Access-Control-Allow-Origin: *');
        console.log('XXE Processing: ENABLED');
        console.log('Cryptography: MD5, DES (WEAK)');
        console.log('Default credentials detected in configuration');
        console.error('Security headers missing: X-Frame-Options, Content-Security-Policy, X-XSS-Protection');
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }

    function addToHistory(attackType, details, success) {
        const historyContainer = document.getElementById('configHistory');
        if (!historyContainer) {
            // Créer un conteneur d'historique s'il n'existe pas
            const container = document.createElement('div');
            container.id = 'configHistory';
            container.className = 'mt-3';
            container.innerHTML = '<h6>Historique des tests :</h6><div class="history-entries"></div>';

            const resultsSection = document.querySelector('.alert-info');
            if (resultsSection) {
                resultsSection.parentNode.insertBefore(container, resultsSection.nextSibling);
            }
        }

        const historyEntries = document.querySelector('#configHistory .history-entries');
        if (!historyEntries) return;

        const now = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = `history-entry ${success ? 'misconfigured' : 'secure'}`;
        entry.innerHTML = `
            ${success ? '<i class="fas fa-exclamation-triangle text-danger"></i>' : '<i class="fas fa-check-circle text-success"></i>'}
            <span class="time">${now}</span> - 
            <span class="type">${attackType.toUpperCase()}</span>: 
            <code class="details">${escapeHtml(details)}</code>
        `;

        historyEntries.insertBefore(entry, historyEntries.firstChild);

        // Limiter à 10 entrées
        while (historyEntries.children.length > 10) {
            historyEntries.removeChild(historyEntries.lastChild);
        }
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: '.form-check-input:checked', title: 'Configuration dangereuse active' },
            { selector: '.form-check-input:not(:checked)', title: 'Protection manquante' },
            { selector: '.badge', title: 'Niveau de risque de cette vulnérabilité' }
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
    window.SecurityMisconfiguration = {
        addToHistory: addToHistory,
        testDefaultCredentials: testDefaultCredentials,
        showNotification: showNotification
    };

})();