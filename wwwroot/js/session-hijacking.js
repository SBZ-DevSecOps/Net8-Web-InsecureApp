// session-hijacking.js - Gestion spécifique pour les vulnérabilités de session

(function () {
    'use strict';

    // Variables globales pour le module
    let currentSessionId = null;
    let stolenTokens = [];

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeSessionHijacking();
    });

    function initializeSessionHijacking() {
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
        initializeSessionForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.sessionData && window.sessionData.hasResults) {
            addToHistory(
                window.sessionData.attackType,
                window.sessionData.payload,
                true
            );
        }

        // Initialiser le cookie monitor
        initializeCookieMonitor();

        // Afficher les avertissements
        showSessionWarnings();
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
            'predictable-id': 'Username pour générer session',
            'session-fixation': 'Session ID à imposer',
            'exposed-tokens': 'Token à exposer dans URL',
            'no-httponly': 'Nom du cookie vulnérable',
            'weak-tokens': 'Seed pour génération faible',
            'no-timeout': 'Username pour session éternelle',
            'jwt-none-alg': 'Username pour JWT sans signature',
            'concurrent-sessions': 'Username pour sessions multiples'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeSessionForms() {
        // Form: Predictable Sessions
        const predictableForm = document.getElementById('predictableForm');
        if (predictableForm) {
            predictableForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('predictableUsername').value;
                createPredictableSession(username);
            });
        }

        // Form: Session Fixation
        const fixationForm = document.getElementById('fixationForm');
        if (fixationForm) {
            fixationForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const sessionId = document.getElementById('fixedSessionId').value;
                const username = document.getElementById('fixationUsername').value;
                acceptFixedSession(sessionId, username);
            });
        }

        // Form: Vulnerable Cookie
        const cookieForm = document.getElementById('cookieForm');
        if (cookieForm) {
            cookieForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const name = document.getElementById('cookieName').value;
                const value = document.getElementById('cookieValue').value;
                setVulnerableCookie(name, value);
            });
        }

        // Form: Weak Tokens
        const weakTokenForm = document.getElementById('weakTokenForm');
        if (weakTokenForm) {
            weakTokenForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const seed = document.getElementById('tokenSeed').value;
                generateWeakTokens(seed);
            });
        }

        // Form: Eternal Session
        const eternalForm = document.getElementById('eternalForm');
        if (eternalForm) {
            eternalForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('eternalUsername').value;
                createEternalSession(username);
            });
        }

        // Form: JWT None
        const jwtForm = document.getElementById('jwtForm');
        if (jwtForm) {
            jwtForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('jwtUsername').value;
                createJWTNone(username);
            });
        }

        // Form: Concurrent Sessions
        const concurrentForm = document.getElementById('concurrentForm');
        if (concurrentForm) {
            concurrentForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('concurrentUsername').value;
                createConcurrentSession(username);
            });
        }
    }

    function createPredictableSession(username) {
        showNotification('info', `Création session prévisible pour: ${username}`);

        fetch('/SessionHijacking/CreatePredictableSession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'predictable');
                    showNotification('danger', 'Session ID prévisible créé!');
                    addToHistory('predictable-id', `${username} - ID: ${data.sessionId}`, true);
                    currentSessionId = data.sessionId;
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function acceptFixedSession(sessionId, username) {
        showNotification('info', `Fixation de session: ${sessionId}`);

        fetch('/SessionHijacking/AcceptFixedSession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `sessionId=${encodeURIComponent(sessionId)}&username=${encodeURIComponent(username)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'fixation');
                    showNotification('danger', data.warning);
                    addToHistory('session-fixation', `Fixed: ${sessionId}`, true);
                }
            });
    }

    function setVulnerableCookie(name, value) {
        showNotification('info', `Création cookie vulnérable: ${name}`);

        fetch('/SessionHijacking/SetVulnerableCookie', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `name=${encodeURIComponent(name)}&value=${encodeURIComponent(value)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'cookie');
                    showNotification('danger', 'Cookie vulnérable créé!');
                    refreshCookies();
                    addToHistory('vulnerable-cookie', `${name}=${value}`, true);
                }
            });
    }

    function generateWeakTokens(seed) {
        showNotification('info', `Génération tokens faibles avec seed: ${seed}`);

        fetch('/SessionHijacking/GenerateWeakToken', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `seed=${encodeURIComponent(seed)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'weak-tokens');
                    showNotification('danger', 'Tokens faibles générés!');
                    addToHistory('weak-tokens', `Seed: ${seed}`, true);
                }
            });
    }

    function createEternalSession(username) {
        showNotification('info', `Création session éternelle pour: ${username}`);

        fetch('/SessionHijacking/CreateEternalSession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'eternal');
                    showNotification('danger', 'Session sans expiration créée!');
                    addToHistory('eternal-session', username, true);
                }
            });
    }

    function createJWTNone(username) {
        showNotification('info', `Création JWT sans signature pour: ${username}`);

        fetch('/SessionHijacking/CreateJWTNone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'jwt-none');
                    showNotification('danger', 'JWT sans signature accepté!');
                    addToHistory('jwt-none', username, true);
                }
            });
    }

    function createConcurrentSession(username) {
        showNotification('info', `Création session concurrente pour: ${username}`);

        fetch('/SessionHijacking/CreateConcurrentSession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'concurrent');
                    showNotification('warning', data.warning);
                    addToHistory('concurrent-sessions', `${username} - ${data.activeSessions} sessions`, true);
                }
            });
    }

    function showSessionResult(data, type) {
        const resultsDiv = document.getElementById('sessionResults');
        const contentDiv = document.getElementById('sessionResultContent');

        resultsDiv.style.display = 'block';

        let html = '<h6>Résultat Session Hijacking :</h6>';

        if (type === 'predictable') {
            html += `<div class="mb-3">`;
            html += `<strong>Session ID créé:</strong> ${data.sessionId}<br>`;
            html += `<strong>Sequential ID:</strong> ${data.sequentialId}<br>`;
            html += `<strong>Weak Token:</strong> <code>${data.weakToken}</code><br>`;
            html += `<strong>Timestamp:</strong> ${data.timestamp}<br>`;
            html += `<strong>Prochains IDs prévisibles:</strong><br>`;
            html += `<ul>`;
            data.nextIds.forEach(id => {
                html += `<li><code>${id}</code></li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'fixation') {
            html += `<ul>`;
            html += `<li><strong>Session ID accepté:</strong> <code>${data.acceptedSessionId}</code></li>`;
            html += `<li><strong>Username:</strong> ${data.username}</li>`;
            html += `<li><strong>Exploit:</strong> <code>${data.exploit}</code></li>`;
            html += `</ul>`;
        } else if (type === 'cookie') {
            html += `<div class="mb-3">`;
            html += `<strong>Cookie créé:</strong> ${data.cookieName}=${data.cookieValue}<br>`;
            html += `<strong>Vulnérabilités:</strong>`;
            html += `<ul>`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li>${vuln}</li>`;
            });
            html += `</ul>`;
            html += `<strong>Accès JS:</strong> <code>${data.jsAccess}</code><br>`;
            html += `<strong>XSS Payload:</strong> <code>${escapeHtml(data.xssPayload)}</code>`;
            html += `</div>`;
        } else if (type === 'weak-tokens') {
            html += `<div class="mb-3">`;
            html += `<strong>Seed utilisé:</strong> ${data.seed}<br>`;
            html += `<strong>Tokens faibles générés:</strong><br>`;
            Object.entries(data.weakTokens).forEach(([method, token]) => {
                html += `<div class="mt-2">`;
                html += `<strong>${method.toUpperCase()}:</strong><br>`;
                html += `<code class="text-break">${token}</code><br>`;
                html += `<small class="text-danger">Temps de crack: ${data.crackTime[method]}</small>`;
                html += `</div>`;
            });
            html += `</div>`;
        } else if (type === 'eternal') {
            html += `<ul>`;
            html += `<li><strong>Session ID:</strong> <code>${data.sessionId}</code></li>`;
            html += `<li><strong>Créée:</strong> ${new Date(data.createdAt).toLocaleString()}</li>`;
            html += `<li><strong>Expire:</strong> <span class="badge bg-danger">${data.expiresAt}</span></li>`;
            html += `<li><strong>Cookie MaxAge:</strong> ${data.maxAge}</li>`;
            html += `</ul>`;
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-danger">${risk}</li>`;
            });
            html += `</ul>`;
        } else if (type === 'jwt-none') {
            html += `<div class="mb-3">`;
            html += `<strong>JWT généré (sans signature):</strong><br>`;
            html += `<code class="text-break">${data.jwt}</code><br>`;
            html += `<strong>Décodé:</strong><br>`;
            html += `<pre class="bg-light p-2">${JSON.stringify(data.decoded, null, 2)}</pre>`;
            html += `<strong>Exemple forgé (admin):</strong><br>`;
            html += `<code class="text-break text-danger">${data.forgedExample}</code>`;
            html += `</div>`;
        } else if (type === 'concurrent') {
            html += `<ul>`;
            html += `<li><strong>Nouvelle session:</strong> <code>${data.sessionId}</code></li>`;
            html += `<li><strong>Token:</strong> <code>${data.token}</code></li>`;
            html += `<li><strong>Sessions actives:</strong> <span class="badge bg-warning">${data.activeSessions}</span></li>`;
            html += `</ul>`;
            if (data.allTokens && data.allTokens.length > 0) {
                html += `<strong>Tous les tokens actifs:</strong>`;
                html += `<ul>`;
                data.allTokens.forEach(token => {
                    html += `<li><code>${token}</code></li>`;
                });
                html += `</ul>`;
            }
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-warning">${risk}</li>`;
            });
            html += `</ul>`;
        } else if (type === 'exposed-token') {
            html += `<ul>`;
            html += `<li><strong>URL avec token:</strong></li>`;
            html += `<li><code class="text-break">${data.exposedUrl}</code></li>`;
            html += `<li><strong>Token:</strong> <code>${data.token}</code></li>`;
            html += `</ul>`;
            html += `<strong>Risques d'exposition:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-danger">${risk}</li>`;
            });
            html += `</ul>`;
        } else if (type === 'session-replay') {
            html += `<ul>`;
            html += `<li><strong>Message:</strong> ${data.message}</li>`;
            html += `<li><strong>Session toujours valide:</strong> <span class="badge bg-${data.sessionStillValid ? 'danger' : 'success'}">${data.sessionStillValid ? 'OUI' : 'NON'}</span></li>`;
            html += `<li><strong>Exploit:</strong> <code>${data.exploit}</code></li>`;
            html += `</ul>`;
        } else if (type === 'all-sessions') {
            html += `<div class="mb-3">`;
            html += `<strong>Total sessions actives:</strong> ${data.totalSessions}<br>`;
            html += `<strong>Sessions exposées:</strong><br>`;
            html += `<div class="table-responsive mt-2">`;
            html += `<table class="table table-sm table-striped">`;
            html += `<thead><tr><th>Session ID</th><th>Username</th><th>Token</th><th>Créée</th></tr></thead>`;
            html += `<tbody>`;
            data.sessions.forEach(session => {
                html += `<tr>`;
                html += `<td><code>${session.sessionId}</code></td>`;
                html += `<td>${session.username}</td>`;
                html += `<td><code>${session.token}</code></td>`;
                html += `<td>${new Date(session.createdAt).toLocaleTimeString()}</td>`;
                html += `</tr>`;
            });
            html += `</tbody></table></div>`;
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
    window.predictNextIds = function () {
        const timestamp = Math.floor(Date.now() / 1000);
        const predictions = [];

        for (let i = 1; i <= 10; i++) {
            predictions.push(timestamp + i);
        }

        showNotification('warning', `IDs prévisibles: ${predictions.slice(0, 5).join(', ')}...`);

        const html = `
            <h6>Prochains IDs prévisibles (basés sur timestamp):</h6>
            <ul>
                ${predictions.map(id => `<li><code>${id}</code> - Dans ${predictions.indexOf(id) + 1} secondes</li>`).join('')}
            </ul>
        `;

        showCustomResult(html);
    };

    window.testExposedToken = function () {
        // Créer d'abord une session
        fetch('/SessionHijacking/CreatePredictableSession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'username=tokentest'
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const token = data.weakToken;
                    const exposedUrl = `/SessionHijacking/ProfileWithToken?token=${token}`;

                    // Ouvrir dans un nouvel onglet pour montrer l'URL
                    window.open(exposedUrl, '_blank');

                    showSessionResult({
                        success: true,
                        exposedUrl: window.location.origin + exposedUrl,
                        token: token,
                        warning: 'Token exposé dans l\'URL!',
                        risks: [
                            'Visible dans l\'historique du navigateur',
                            'Enregistré dans les logs serveur',
                            'Transmis dans le Referer header',
                            'Partageable par erreur'
                        ]
                    }, 'exposed-token');

                    showNotification('danger', 'Token exposé dans l\'URL!');
                    addToHistory('exposed-token', token, true);
                }
            });
    };

    window.stealCookies = function () {
        // Simuler un vol de cookies via XSS
        const cookies = document.cookie;
        const cookieArray = cookies.split(';').map(c => c.trim());

        if (cookieArray.length > 0 && cookies !== '') {
            stolenTokens = cookieArray;

            const html = `
                <h6>🎭 Cookies volés via XSS:</h6>
                <ul>
                    ${cookieArray.map(cookie => `<li><code>${escapeHtml(cookie)}</code></li>`).join('')}
                </ul>
                <p class="text-danger">Ces cookies étaient accessibles car HttpOnly=false!</p>
                <button class="btn btn-sm btn-danger" onclick="sendStolenCookies()">
                    <i class="fas fa-paper-plane"></i> Envoyer à l'attaquant
                </button>
            `;

            showCustomResult(html);
            showNotification('danger', `${cookieArray.length} cookies volés!`);
        } else {
            showNotification('warning', 'Aucun cookie trouvé (créez-en d\'abord)');
        }
    };

    window.sendStolenCookies = function () {
        // Simuler l'envoi des cookies volés
        showNotification('danger', `Cookies envoyés à evil.com: ${stolenTokens.join(', ')}`);
        console.error('🔥 STOLEN COOKIES SENT TO ATTACKER:', stolenTokens);
    };

    window.forgeJWT = function () {
        // Forger un JWT avec privilèges admin
        const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }));
        const payload = btoa(JSON.stringify({
            sub: "attacker",
            admin: true,
            role: "superadmin",
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        }));

        const forgedJWT = `${header}.${payload}.`;

        const html = `
            <h6>🔨 JWT Forgé (admin):</h6>
            <code class="text-break">${forgedJWT}</code>
            <br><br>
            <strong>Payload décodé:</strong>
            <pre>${JSON.stringify(JSON.parse(atob(payload)), null, 2)}</pre>
            <p class="text-danger">Ce JWT sera accepté car l'algorithme 'none' est autorisé!</p>
        `;

        showCustomResult(html);
        showNotification('danger', 'JWT admin forgé avec succès!');
    };

    window.testSessionReplay = function () {
        // Test de session replay
        if (!currentSessionId) {
            showNotification('warning', 'Créez d\'abord une session');
            return;
        }

        // Simuler un logout
        fetch('/SessionHijacking/Logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `sessionId=${encodeURIComponent(currentSessionId)}`
        })
            .then(response => response.json())
            .then(data => {
                showSessionResult(data, 'session-replay');

                // Tester si la session est toujours valide
                setTimeout(() => {
                    fetch('/SessionHijacking/ValidateSession', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `sessionId=${encodeURIComponent(currentSessionId)}`
                    })
                        .then(response => response.json())
                        .then(validationData => {
                            if (validationData.valid) {
                                showNotification('danger', 'Session toujours valide après logout!');
                            }
                        });
                }, 1000);
            });
    };

    window.createManySessions = function () {
        const username = document.getElementById('concurrentUsername').value || 'multiuser';

        showNotification('info', 'Création de 10 sessions simultanées...');

        for (let i = 0; i < 10; i++) {
            setTimeout(() => {
                createConcurrentSession(username);
            }, i * 200);
        }
    };

    window.viewAllSessions = function () {
        fetch('/SessionHijacking/GetAllSessions')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSessionResult(data, 'all-sessions');
                    showNotification('danger', data.warning);

                    // Ajouter des boutons pour voler les sessions
                    setTimeout(() => {
                        const buttons = data.sessions.map(s =>
                            `<button class="btn btn-sm btn-danger me-1" onclick="hijackSession('${s.sessionId}', '${s.token}')">
                                <i class="fas fa-mask"></i> Hijack ${s.username}
                            </button>`
                        ).join('');

                        const contentDiv = document.getElementById('sessionResultContent');
                        contentDiv.innerHTML += `<div class="mt-3">${buttons}</div>`;
                    }, 100);
                }
            });
    };

    window.hijackSession = function (sessionId, token) {
        showNotification('danger', `Session hijackée! ID: ${sessionId}`);
        console.error(`🔥 SESSION HIJACKED: ${sessionId} with token: ${token}`);

        // Simuler l'utilisation de la session volée
        document.cookie = `HijackedSession=${sessionId}; path=/`;
        document.cookie = `HijackedToken=${token}; path=/`;
    };

    function initializeCookieMonitor() {
        // Afficher le cookie monitor si on est sur certains types d'attaque
        const attackType = window.sessionData?.attackType;
        if (attackType === 'no-httponly' || attackType === 'no-secure-flag') {
            document.getElementById('cookieMonitor').style.display = 'block';
            refreshCookies();
        }
    }

    window.refreshCookies = function () {
        const cookieList = document.getElementById('cookieList');
        const cookies = document.cookie.split(';').map(c => c.trim()).filter(c => c);

        if (cookies.length === 0 || document.cookie === '') {
            cookieList.innerHTML = '<p class="text-muted">Aucun cookie détecté</p>';
            return;
        }

        let html = '<ul class="list-unstyled">';
        cookies.forEach(cookie => {
            const [name, value] = cookie.split('=');
            html += `<li>`;
            html += `<i class="fas fa-cookie text-warning"></i> `;
            html += `<strong>${name}:</strong> <code>${value || ''}</code>`;
            html += `<button class="btn btn-sm btn-outline-danger ms-2" onclick="deleteCookie('${name}')">`;
            html += `<i class="fas fa-trash"></i></button>`;
            html += `</li>`;
        });
        html += '</ul>';

        cookieList.innerHTML = html;
    };

    window.deleteCookie = function (name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        refreshCookies();
        showNotification('info', `Cookie ${name} supprimé`);
    };

    function showCustomResult(html) {
        const resultsDiv = document.getElementById('sessionResults');
        const contentDiv = document.getElementById('sessionResultContent');

        resultsDiv.style.display = 'block';
        contentDiv.innerHTML = html;
    }

    function showSessionWarnings() {
        console.group('%c⚠️ Session Hijacking Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ Predictable session IDs (timestamp-based)');
        console.error('❌ Session fixation accepted');
        console.error('❌ Cookies without HttpOnly flag');
        console.error('❌ Cookies without Secure flag');
        console.error('❌ Weak token generation (MD5/SHA1)');
        console.error('❌ No session timeout');
        console.error('❌ JWT "none" algorithm accepted');
        console.error('❌ Session replay possible');
        console.warn('💡 Prevention:');
        console.warn('   - Use cryptographically secure random IDs');
        console.warn('   - Regenerate session ID after login');
        console.warn('   - Set HttpOnly + Secure + SameSite flags');
        console.warn('   - Implement proper session timeout');
        console.warn('   - Never accept JWT "none" algorithm');
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
        console.log(`[${timestamp}] Session ${actionType}: ${details}`);
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
    window.SessionHijacking = {
        createPredictableSession: createPredictableSession,
        showNotification: showNotification,
        refreshCookies: refreshCookies
    };

})();