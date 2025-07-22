// csrf.js - Gestion spécifique pour les vulnérabilités CSRF

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeCSRF();
    });

    function initializeCSRF() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Initialiser les tests spécifiques
        initializeCSRFTests();

        // Charger l'état du compte
        loadAccountStatus();

        // Ajouter à l'historique si nous avons des résultats
        if (window.csrfData && window.csrfData.hasResults) {
            addToHistory(
                window.csrfData.attackType,
                window.csrfData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Afficher les avertissements CSRF
        showCSRFWarnings();
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
    }

    function updateContextualHelp(attackType, payloadInput) {
        // Ajouter des placeholders contextuels
        const placeholders = {
            'no-token': 'POST /TransferMoney sans token CSRF',
            'get-state-change': 'GET /DeleteAccount?id=1',
            'cors-wildcard': 'POST /ApiTransfer avec Origin: evil.com',
            'no-samesite': 'Cookie sans SameSite=Strict',
            'json-csrf': 'POST /UpdateProfileJson avec form-data'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }

        // Mettre en évidence les vulnérabilités
        highlightVulnerability(attackType);
    }

    function initializeCSRFTests() {
        // Test CORS CSRF
        const corsButton = document.querySelector('.test-cors-csrf');
        if (corsButton) {
            corsButton.addEventListener('click', function () {
                testCORSCSRF();
            });
        }

        // Intercepter les soumissions de formulaires pour logging
        const forms = document.querySelectorAll('form[action*="CSRF"]');
        forms.forEach(form => {
            form.addEventListener('submit', function (e) {
                const action = this.action || this.getAttribute('action');
                const method = this.method || 'POST';

                showNotification('warning', `Formulaire ${method} soumis vers ${action} SANS token CSRF!`);
                addToHistory('form-submit', `${method} ${action}`, true);

                // Recharger l'état après un délai
                setTimeout(loadAccountStatus, 1000);
            });
        });

        // Détecter les liens GET dangereux
        const dangerousLinks = document.querySelectorAll('a[href*="Delete"], a[href*="Subscribe"]');
        dangerousLinks.forEach(link => {
            link.addEventListener('click', function (e) {
                const href = this.href;
                showNotification('danger', `Action d'état via GET détectée: ${href}`);
                addToHistory('get-state-change', href, true);

                // Recharger l'état après un délai
                setTimeout(loadAccountStatus, 1000);
            });
        });
    }

    function testCORSCSRF() {
        showNotification('info', 'Test CSRF cross-origin en cours...');

        // Simuler une requête cross-origin
        fetch('/CSRF/ApiTransfer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'http://evil.com' // Simuler une origine malveillante
            },
            credentials: 'include', // Inclure les cookies
            body: 'recipient=attacker&amount=250'
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('danger', 'CORS mal configuré! Transfert cross-origin réussi!');
                    addToHistory('cors-csrf', 'Transfert cross-origin exécuté', true);
                    loadAccountStatus();
                }
            })
            .catch(error => {
                console.error('Erreur CORS:', error);
            });
    }

    function loadAccountStatus() {
        fetch('/CSRF/CheckStatus')
            .then(response => response.json())
            .then(data => {
                updateAccountDisplay(data);
            })
            .catch(error => {
                console.error('Erreur chargement état:', error);
            });
    }

    function updateAccountDisplay(data) {
        const statusDiv = document.getElementById('accountStatus');
        if (!statusDiv) return;

        let html = '<h6>État actuel :</h6>';

        // Comptes
        if (data.accounts && data.accounts.length > 0) {
            html += '<div class="mb-3"><strong>Comptes :</strong><ul class="mb-0">';
            data.accounts.forEach(account => {
                html += `<li>${account.username}: ${account.balance}€ (${account.email})</li>`;
            });
            html += '</ul></div>';
        }

        // Profil actuel
        if (data.currentProfile) {
            html += '<div class="mb-3"><strong>Profil actuel :</strong><ul class="mb-0">';
            html += `<li>Email: ${data.currentProfile.email}</li>`;
            html += `<li>Téléphone: ${data.currentProfile.phone}</li>`;
            html += `<li>Adresse: ${data.currentProfile.address}</li>`;
            html += '</ul></div>';
        }

        // Transactions récentes
        if (data.transactions && data.transactions.length > 0) {
            html += '<div class="mb-3"><strong>Dernières transactions :</strong><ul class="mb-0">';
            data.transactions.forEach(trans => {
                const date = new Date(trans.date).toLocaleString();
                html += `<li>${date}: ${trans.from} → ${trans.to}: ${trans.amount}€</li>`;
            });
            html += '</ul></div>';
        }

        // Info cookies
        if (data.cookieInfo) {
            const sameSiteStatus = data.cookieInfo.sameSite || 'None';
            const statusClass = sameSiteStatus === 'None (vulnérable!)' ? 'text-danger' : 'text-success';
            html += `<div><strong>Cookie SameSite:</strong> <span class="${statusClass}">${sameSiteStatus}</span></div>`;
        }

        statusDiv.innerHTML = html;
        statusDiv.className = 'alert alert-light';
    }

    function highlightVulnerability(vulnType) {
        // Animation visuelle selon le type
        const elements = {
            'no-token': '#vulnerableForm',
            'get-state-change': 'a[href*="Delete"], a[href*="Subscribe"]',
            'json-csrf': '#jsonCsrfForm'
        };

        if (elements[vulnType]) {
            const targets = document.querySelectorAll(elements[vulnType]);
            targets.forEach(el => {
                el.classList.add('highlight-vulnerability');
                setTimeout(() => {
                    el.classList.remove('highlight-vulnerability');
                }, 3000);
            });
        }
    }

    function showCSRFWarnings() {
        console.group('%c⚠️ CSRF Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ Missing CSRF tokens on POST endpoints');
        console.error('❌ State-changing operations via GET requests');
        console.error('❌ CORS misconfiguration with credentials');
        console.error('❌ Cookies without SameSite attribute');
        console.warn('💡 To prevent CSRF:');
        console.warn('   - Use [ValidateAntiForgeryToken] on all POST/PUT/DELETE');
        console.warn('   - Add @Html.AntiForgeryToken() to forms');
        console.warn('   - Set SameSite=Strict on cookies');
        console.warn('   - Never use GET for state changes');
        console.groupEnd();
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'danger' ? 'skull' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }

    function addToHistory(actionType, details, isVulnerable) {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[${timestamp}] CSRF ${actionType}: ${details}`);

        // Créer un historique visuel
        updateVisualHistory(actionType, details, isVulnerable, timestamp);
    }

    function updateVisualHistory(actionType, details, isVulnerable, timestamp) {
        let historyContainer = document.getElementById('csrf-history');
        if (!historyContainer) {
            const statusDiv = document.getElementById('accountStatus');
            if (statusDiv) {
                historyContainer = document.createElement('div');
                historyContainer.id = 'csrf-history';
                historyContainer.className = 'mt-3';
                historyContainer.innerHTML = '<h6><i class="fas fa-history"></i> Historique CSRF :</h6><div class="history-items"></div>';
                statusDiv.parentNode.insertBefore(historyContainer, statusDiv);
            }
        }

        if (historyContainer) {
            const historyItems = historyContainer.querySelector('.history-items');
            const newItem = document.createElement('div');
            newItem.className = `alert alert-${isVulnerable ? 'danger' : 'success'} alert-sm py-1 mb-1`;
            newItem.innerHTML = `
                <small>
                    <i class="fas fa-${isVulnerable ? 'crosshairs' : 'shield-alt'}"></i>
                    <strong>${timestamp}</strong> - ${actionType}: ${details}
                </small>
            `;
            historyItems.insertBefore(newItem, historyItems.firstChild);

            // Limiter à 5 entrées
            while (historyItems.children.length > 5) {
                historyItems.removeChild(historyItems.lastChild);
            }
        }
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: 'form:not([antiforgery])', title: 'Ce formulaire n\'a pas de token CSRF!' },
            { selector: 'a[href*="Delete"]', title: 'Suppression via GET - vulnérable au CSRF!' },
            { selector: '.test-cors-csrf', title: 'Teste si les requêtes cross-origin sont acceptées' }
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

    // Exposer certaines fonctions si nécessaire
    window.CSRF = {
        loadAccountStatus: loadAccountStatus,
        showNotification: showNotification,
        testCORSCSRF: testCORSCSRF
    };

})();