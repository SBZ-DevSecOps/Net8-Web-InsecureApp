// logging-monitoring.js - Gestion spécifique pour les défaillances de logging et monitoring

(function () {
    'use strict';

    // Variables globales
    let securityEvents = [];
    let failedLoginAttempts = 0;
    let alertsMissed = 0;

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeLoggingMonitoring();
    });

    function initializeLoggingMonitoring() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Initialiser les formulaires
        initializeLoggingForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.loggingData && window.loggingData.hasResults) {
            addToHistory(
                window.loggingData.attackType,
                window.loggingData.payload,
                true
            );
        }

        // Afficher les avertissements
        showLoggingWarnings();
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
            'no-logging': 'Username pour test login',
            'insufficient-logging': 'Événement à logger',
            'log-injection': 'Input avec \\n pour injection',
            'sensitive-data-logging': 'Données sensibles',
            'no-alerting': 'Username pour brute force',
            'log-tampering': 'Nom du fichier log',
            'unencrypted-logs': 'URL du serveur de logs',
            'no-correlation': 'Type d\'événement',
            'delayed-detection': 'Incident ID',
            'no-integrity': 'Fichier log à vérifier'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeLoggingForms() {
        // Form: No Logging
        const noLoggingForm = document.getElementById('noLoggingForm');
        if (noLoggingForm) {
            noLoggingForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;
                attemptLogin(username, password);
            });
        }

        // Form: Sensitive Data
        const sensitiveDataForm = document.getElementById('sensitiveDataForm');
        if (sensitiveDataForm) {
            sensitiveDataForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('sensitiveUsername').value;
                const password = document.getElementById('sensitivePassword').value;
                const creditCard = document.getElementById('creditCard').value;
                logSensitiveData(username, password, creditCard);
            });
        }

        // Form: Log Injection
        const logInjectionForm = document.getElementById('logInjectionForm');
        if (logInjectionForm) {
            logInjectionForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const userInput = document.getElementById('userInput').value;
                injectLog(userInput);
            });
        }

        // Form: Brute Force
        const bruteForceForm = document.getElementById('bruteForceForm');
        if (bruteForceForm) {
            bruteForceForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('bruteUsername').value;
                const attempts = parseInt(document.getElementById('attempts').value) || 1000;
                simulateBruteForce(username, attempts);
            });
        }

        // Form: Tamper Logs
        const tamperForm = document.getElementById('tamperForm');
        if (tamperForm) {
            tamperForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const action = document.getElementById('tamperAction').value;
                const logFile = document.getElementById('logFile').value;
                tamperLogs(action, logFile);
            });
        }

        // Form: Transmit Logs
        const transmitForm = document.getElementById('transmitForm');
        if (transmitForm) {
            transmitForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const logServer = document.getElementById('logServer').value;
                transmitLogs(logServer);
            });
        }

        // Form: Integrity Check
        const integrityForm = document.getElementById('integrityForm');
        if (integrityForm) {
            integrityForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const logFile = document.getElementById('integrityLogFile').value;
                verifyLogIntegrity(logFile);
            });
        }
    }

    function attemptLogin(username, password) {
        showNotification('info', `Tentative de login: ${username}`);

        fetch('/LoggingMonitoring/AttemptLogin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        })
            .then(response => response.json())
            .then(data => {
                if (!data.success) {
                    failedLoginAttempts++;
                    showLoggingResult(data, 'failed-login');
                    showNotification('danger', data.warning);
                    addSecurityEvent('failed_login', username, 'NOT LOGGED!');
                } else {
                    showLoggingResult(data, 'successful-login');
                    showNotification('success', 'Login réussi mais non loggé!');
                }
                addToHistory('no-logging', `${username} - ${data.success ? 'success' : 'failed'}`, true);
            });
    }

    function logSensitiveData(username, password, creditCard) {
        showNotification('info', 'Logging de données sensibles...');

        fetch('/LoggingMonitoring/LogSensitiveData', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&creditCard=${encodeURIComponent(creditCard)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'sensitive-data');
                    showNotification('danger', data.warning);
                    addToHistory('sensitive-logging', 'Données sensibles exposées', true);
                }
            });
    }

    function injectLog(userInput) {
        showNotification('info', 'Injection dans les logs...');

        fetch('/LoggingMonitoring/InjectLog', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `userInput=${encodeURIComponent(userInput)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'log-injection');
                    showNotification('danger', data.warning);
                    addToHistory('log-injection', `${data.injectedLines} lignes injectées`, true);
                }
            });
    }

    function simulateBruteForce(username, attempts) {
        showNotification('info', `Simulation de ${attempts} tentatives...`);

        fetch('/LoggingMonitoring/SimulateBruteForce', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&attempts=${attempts}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'brute-force');
                    showNotification('danger', data.warning);
                    alertsMissed += attempts;
                    updateEventMonitor();
                    addToHistory('no-alerting', `${attempts} tentatives sans alerte`, true);
                }
            });
    }

    function tamperLogs(action, logName) {
        showNotification('info', `${action} sur ${logName}...`);

        fetch('/LoggingMonitoring/TamperLogs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `action=${encodeURIComponent(action)}&logName=${encodeURIComponent(logName)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'log-tampering');
                    showNotification('danger', data.warning);
                    addToHistory('log-tampering', `${action} - ${logName}`, true);
                }
            });
    }

    function transmitLogs(destination) {
        showNotification('info', `Transmission vers: ${destination}`);

        fetch('/LoggingMonitoring/TransmitLogs', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'log-transmission');
                    showNotification('danger', data.warning);
                    addToHistory('unencrypted-logs', destination, true);
                }
            });
    }

    function verifyLogIntegrity(logName) {
        showNotification('info', `Vérification intégrité: ${logName}`);

        fetch('/LoggingMonitoring/VerifyLogIntegrity', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `logName=${encodeURIComponent(logName)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'integrity-check');
                    showNotification('danger', data.warning);
                    addToHistory('no-integrity', logName, true);
                }
            });
    }

    function showLoggingResult(data, type) {
        const resultsDiv = document.getElementById('loggingResults');
        const contentDiv = document.getElementById('loggingResultContent');

        resultsDiv.style.display = 'block';

        let html = '<h6>Résultat Logging/Monitoring :</h6>';

        if (type === 'failed-login' || type === 'successful-login') {
            html += `<div class="mb-3">`;
            html += `<strong>Type:</strong> ${type === 'failed-login' ? 'Échec de connexion' : 'Connexion réussie'}<br>`;
            if (data.username) {
                html += `<strong>Username:</strong> ${data.username}<br>`;
            }
            if (data.error) {
                html += `<strong>Erreur:</strong> ${data.error}<br>`;
            }
            if (data.issues) {
                html += `<strong>Informations manquantes dans les logs:</strong>`;
                html += `<ul>`;
                data.issues.forEach(issue => {
                    html += `<li class="text-danger">${issue}</li>`;
                });
                html += `</ul>`;
            }
            html += `</div>`;
        } else if (type === 'sensitive-data') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier log:</strong> <a href="${data.logFile}" target="_blank">${data.logFile}</a><br>`;
            html += `<strong>Données loggées en clair:</strong>`;
            html += `<ul>`;
            html += `<li>Password: <code>${data.loggedData.password}</code></li>`;
            if (data.loggedData.creditCard) {
                html += `<li>Credit Card: <code>${data.loggedData.creditCard}</code></li>`;
            }
            html += `</ul>`;
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-danger">${risk}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'log-injection') {
            html += `<div class="mb-3">`;
            html += `<strong>Input original:</strong> <code>${escapeHtml(data.originalInput)}</code><br>`;
            html += `<strong>Lignes injectées:</strong> ${data.injectedLines}<br>`;
            html += `<strong>Fichier affecté:</strong> <a href="${data.logFile}" target="_blank">${data.logFile}</a><br>`;
            html += `<strong>Exemple d'exploit:</strong><br>`;
            html += `<pre class="bg-light p-2">${escapeHtml(data.exploit)}</pre>`;
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-warning">${risk}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'brute-force') {
            html += `<div class="mb-3">`;
            html += `<strong>Username cible:</strong> ${data.username}<br>`;
            html += `<strong>Total tentatives échouées:</strong> <span class="badge bg-danger">${data.totalFailedAttempts}</span><br>`;
            html += `<strong>Alerte déclenchée:</strong> <span class="badge bg-${data.alertTriggered ? 'success' : 'danger'}">${data.alertTriggered ? 'OUI' : 'NON'}</span><br>`;
            html += `<strong>Problèmes:</strong>`;
            html += `<ul>`;
            data.issues.forEach(issue => {
                html += `<li class="text-danger">${issue}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'log-tampering') {
            html += `<div class="mb-3">`;
            html += `<strong>Action:</strong> <span class="badge bg-danger">${data.action.toUpperCase()}</span><br>`;
            html += `<strong>Fichier:</strong> ${data.file}<br>`;
            if (data.modifications) {
                html += `<strong>Modifications:</strong>`;
                html += `<ul>`;
                data.modifications.forEach(mod => {
                    html += `<li><code>${mod}</code></li>`;
                });
                html += `</ul>`;
            }
            html += `<strong>Impact:</strong> ${data.impact || 'Logs compromis'}<br>`;
            html += `</div>`;
        } else if (type === 'log-transmission') {
            html += `<div class="mb-3">`;
            html += `<strong>Destination:</strong> <code>${data.destination}</code><br>`;
            html += `<strong>Protocole:</strong> <span class="badge bg-${data.protocol === 'HTTP' ? 'danger' : 'success'}">${data.protocol}</span><br>`;
            html += `<strong>Logs transmis:</strong> ${data.logsTransmitted}<br>`;
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-danger">${risk}</li>`;
            });
            html += `</ul>`;
            if (data.sampleData) {
                html += `<strong>Échantillon transmis:</strong><br>`;
                html += `<pre class="bg-light p-2 small">${escapeHtml(data.sampleData)}...</pre>`;
            }
            html += `</div>`;
        } else if (type === 'integrity-check') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier:</strong> ${data.file}<br>`;
            html += `<strong>Hash actuel:</strong> <code>${data.currentHash}</code><br>`;
            html += `<strong>Hash stocké:</strong> <span class="badge bg-danger">${data.storedHash}</span><br>`;
            html += `<strong>Intégrité vérifiée:</strong> <span class="badge bg-danger">NON</span><br>`;
            html += `<strong>Problèmes:</strong>`;
            html += `<ul>`;
            data.issues.forEach(issue => {
                html += `<li class="text-danger">${issue}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'event-correlation') {
            html += `<div class="mb-3">`;
            html += `<strong>Événement loggé:</strong> ${data.eventLogged.EventType}<br>`;
            html += `<strong>Source:</strong> ${data.eventLogged.Source}<br>`;
            html += `<strong>Cible:</strong> ${data.eventLogged.Target}<br>`;
            html += `<strong>Événements corrélés:</strong> <span class="badge bg-danger">${data.correlatedEvents}</span><br>`;
            html += `<strong>Patterns manqués:</strong>`;
            html += `<ul>`;
            data.missedPatterns.forEach(pattern => {
                html += `<li class="text-warning">${pattern}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'detection-delay') {
            html += `<div class="mb-3">`;
            html += `<strong>Total événements:</strong> ${data.totalEvents}<br>`;
            html += `<strong>Non revus:</strong> <span class="badge bg-danger">${data.unreviewedEvents}</span><br>`;
            html += `<strong>Plus ancien non revu:</strong> <span class="badge bg-danger">${data.oldestUnreviewedDays} jours</span><br>`;
            html += `<strong>Moyenne industrie:</strong> ${data.industryAverage}<br>`;
            html += `<strong>Problèmes:</strong>`;
            html += `<ul>`;
            data.issues.forEach(issue => {
                html += `<li class="text-danger">${issue}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        }

        if (data.warning) {
            html += `<div class="alert alert-danger mt-3">`;
            html += `<i class="fas fa-exclamation-triangle"></i> ${data.warning}`;
            html += `</div>`;
        }

        contentDiv.innerHTML = html;
    }

    // Fonctions globales pour les boutons
    window.attemptMultipleLogins = function () {
        showNotification('info', 'Tentative de 10 logins échoués...');

        for (let i = 0; i < 10; i++) {
            setTimeout(() => {
                const username = `user${i}`;
                const password = 'wrongpass';
                attemptLogin(username, password);
            }, i * 500);
        }
    };

    window.simulateAttackChain = function () {
        showNotification('info', 'Simulation d\'une chaîne d\'attaque...');

        const events = [
            { type: 'port_scan', source: '192.168.1.100', target: 'server.local' },
            { type: 'failed_login', source: '192.168.1.100', target: 'admin' },
            { type: 'sql_injection', source: '192.168.1.100', target: '/login.php' },
            { type: 'privilege_escalation', source: '192.168.1.100', target: 'system' },
            { type: 'data_exfiltration', source: '192.168.1.100', target: 'database' }
        ];

        events.forEach((event, index) => {
            setTimeout(() => {
                fetch('/LoggingMonitoring/LogSecurityEvent', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `eventType=${event.type}&source=${event.source}&target=${event.target}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            addSecurityEvent(event.type, event.source, event.target);
                            if (index === events.length - 1) {
                                showLoggingResult(data, 'event-correlation');
                                showNotification('danger', 'Chaîne d\'attaque non détectée!');
                            }
                        }
                    });
            }, index * 1000);
        });
    };

    window.checkDetectionDelay = function () {
        fetch('/LoggingMonitoring/CheckIncidents')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showLoggingResult(data, 'detection-delay');
                    showNotification('danger', data.warning);
                    updateEventMonitor();
                }
            });
    };

    window.createOldEvents = function () {
        showNotification('info', 'Création d\'événements anciens...');

        // Simuler des événements vieux de plusieurs jours
        for (let i = 0; i < 5; i++) {
            const daysAgo = Math.floor(Math.random() * 200) + 1;
            const event = {
                type: 'suspicious_activity',
                source: `attacker${i}`,
                target: 'production_server',
                daysAgo: daysAgo
            };

            addSecurityEvent(event.type, event.source, `${event.target} (${daysAgo} jours)`);
        }

        showNotification('warning', '5 événements anciens créés');
        updateEventMonitor();
    };

    window.viewLoggingConfig = function () {
        fetch('/LoggingMonitoring/GetLoggingConfig')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let html = '<h6>Configuration de logging actuelle :</h6>';
                    html += '<div class="table-responsive"><table class="table table-sm">';
                    html += '<tbody>';

                    Object.entries(data.configuration).forEach(([key, value]) => {
                        const isDangerous = value === false || value === 'Never' || value === 'Error' || value === 'Unlimited';
                        html += '<tr>';
                        html += `<td><strong>${key}:</strong></td>`;
                        html += `<td class="${isDangerous ? 'text-danger' : ''}">${value}</td>`;
                        html += '</tr>';
                    });

                    html += '</tbody></table></div>';

                    html += '<strong>Problèmes identifiés :</strong>';
                    html += '<ul>';
                    data.issues.forEach(issue => {
                        html += `<li class="text-danger">${issue}</li>`;
                    });
                    html += '</ul>';

                    showCustomResult(html);
                    showNotification('danger', data.warning);
                }
            });
    };

    function addSecurityEvent(type, source, target) {
        securityEvents.push({
            id: Date.now(),
            timestamp: new Date(),
            type: type,
            source: source,
            target: target,
            reviewed: false
        });

        updateEventMonitor();
    }

    function updateEventMonitor() {
        const monitor = document.getElementById('eventMonitor');
        const eventList = document.getElementById('eventList');
        const unreviewedCount = document.getElementById('unreviewedCount');
        const alertCount = document.getElementById('alertCount');

        if (securityEvents.length > 0 || alertsMissed > 0) {
            monitor.style.display = 'block';

            const unreviewedEvents = securityEvents.filter(e => !e.reviewed);
            unreviewedCount.textContent = unreviewedEvents.length;
            alertCount.textContent = alertsMissed;

            let html = '<div class="table-responsive"><table class="table table-sm">';
            html += '<thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Target</th></tr></thead>';
            html += '<tbody>';

            securityEvents.slice(-10).reverse().forEach(event => {
                html += '<tr>';
                html += `<td>${event.timestamp.toLocaleTimeString()}</td>`;
                html += `<td><span class="badge bg-warning">${event.type}</span></td>`;
                html += `<td>${event.source}</td>`;
                html += `<td>${event.target}</td>`;
                html += '</tr>';
            });

            html += '</tbody></table></div>';
            eventList.innerHTML = html;
        }
    }

    function showCustomResult(html) {
        const resultsDiv = document.getElementById('loggingResults');
        const contentDiv = document.getElementById('loggingResultContent');

        resultsDiv.style.display = 'block';
        contentDiv.innerHTML = html;
    }

    function showLoggingWarnings() {
        console.group('%c⚠️ Security Logging and Monitoring Failures Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ No security event logging');
        console.error('❌ Sensitive data logged in plaintext');
        console.error('❌ Log injection vulnerability');
        console.error('❌ No alerting on suspicious activity');
        console.error('❌ Logs can be tampered or deleted');
        console.error('❌ No event correlation');
        console.error('❌ No integrity protection');
        console.warn('💡 Prevention:');
        console.warn('   - Log all security events');
        console.warn('   - Never log sensitive data');
        console.warn('   - Sanitize user input in logs');
        console.warn('   - Set alerting thresholds');
        console.warn('   - Protect log integrity');
        console.warn('   - Implement real-time monitoring');
        console.groupEnd();
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
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
        console.log(`[${timestamp}] Logging/Monitoring ${actionType}: ${details}`);
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
    window.LoggingMonitoring = {
        attemptLogin: attemptLogin,
        showNotification: showNotification,
        addSecurityEvent: addSecurityEvent
    };

})();