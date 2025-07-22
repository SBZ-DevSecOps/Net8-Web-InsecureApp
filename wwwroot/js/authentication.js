// authentication.js - Gestion spécifique pour les vulnérabilités Authentication

(function () {
    'use strict';

    // Variables globales pour le module
    let timingResults = [];
    let bruteForceInProgress = false;

    // Liste des mots de passe communs
    const commonPasswords = [
        'password', '123456', 'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'qwerty', 'abc123', 'Password1', 'password1', '123123',
        'admin123', 'root', 'toor', 'pass', 'test', 'guest', 'master', 'god',
        '111111', '12345', 'dragon', 'passw0rd', 'mustang', 'baseball', 'football',
        'shadow', 'michael', 'auth', '666666', '654321', 'superman', '1qaz2wsx',
        'qazwsx', 'qwertyuiop', 'password123', 'p@ssw0rd', 'p@ssword', 'password!',
        'Pa$$w0rd', 'princess', 'login', 'sunshine', 'flower', 'hello', 'hottie'
    ];

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeAuthentication();
    });

    function initializeAuthentication() {
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
        initializeAuthForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.authenticationData && window.authenticationData.hasResults) {
            addToHistory(
                window.authenticationData.attackType,
                window.authenticationData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Afficher les avertissements
        showAuthWarnings();
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
            'weak-credentials': 'admin/admin123, user1/password',
            'user-enumeration': 'admin (existe) vs fakuser (n\'existe pas)',
            'timing-attack': 'Testez plusieurs usernames',
            'weak-session': 'Session ID: 1, 2, 3...',
            'insecure-storage': 'test/password123',
            'no-account-lockout': 'admin + liste de passwords'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeAuthForms() {
        // Form: Weak login
        const weakLoginForm = document.getElementById('weakLoginForm');
        if (weakLoginForm) {
            weakLoginForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;
                performLogin(username, password);
            });
        }

        // Form: User enumeration
        const userEnumForm = document.getElementById('userEnumForm');
        if (userEnumForm) {
            userEnumForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('enumUsername').value;
                const password = document.getElementById('enumPassword').value;
                testUserEnumeration(username, password);
            });
        }

        // Form: Timing attack
        const timingForm = document.getElementById('timingForm');
        if (timingForm) {
            timingForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('timingUsername').value;
                performTimingAttack(username);
            });
        }

        // Form: Register
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('regUsername').value;
                const password = document.getElementById('regPassword').value;
                const email = document.getElementById('regEmail').value;
                registerUser(username, password, email);
            });
        }

        // Form: Brute force
        const bruteForceForm = document.getElementById('bruteForceForm');
        if (bruteForceForm) {
            bruteForceForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const username = document.getElementById('bruteUsername').value;
                const passwordList = document.getElementById('passwordList').value.split('\n').filter(p => p.trim());
                performBruteForce(username, passwordList);
            });
        }

        // Monitor password strength
        const passwordInputs = document.querySelectorAll('input[type="password"], input#regPassword');
        passwordInputs.forEach(input => {
            input.addEventListener('input', function () {
                checkPasswordStrength(this.value);
            });
        });
    }

    function performLogin(username, password) {
        showNotification('info', 'Tentative de connexion...');

        fetch('/Authentication/Login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        })
            .then(response => response.json())
            .then(data => {
                showAuthResult(data, 'login');

                if (data.success) {
                    showNotification('danger', 'Connexion réussie avec credentials faibles!');
                    addToHistory('weak-credentials', `${username} connecté`, true);

                    // Afficher les vulnérabilités
                    if (data.sessionId) {
                        showNotification('warning', `Session ID prévisible: ${data.sessionId}`);
                    }
                } else {
                    showNotification('warning', data.error);
                    if (data.hint) {
                        showNotification('info', data.hint);
                    }
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
                showNotification('error', 'Erreur lors de la connexion');
            });
    }

    function testUserEnumeration(username, password) {
        const startTime = Date.now();

        fetch('/Authentication/Login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        })
            .then(response => response.json())
            .then(data => {
                const elapsed = Date.now() - startTime;

                const result = {
                    username: username,
                    error: data.error,
                    timing: elapsed,
                    userExists: data.error === 'Mot de passe incorrect'
                };

                showEnumerationResult(result);

                if (result.userExists) {
                    showNotification('danger', `User "${username}" EXISTE!`);
                } else {
                    showNotification('info', `User "${username}" n'existe pas`);
                }

                addToHistory('user-enumeration', `${username}: ${result.userExists ? 'EXISTS' : 'NOT FOUND'}`, true);
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function performTimingAttack(username) {
        showNotification('info', `Analyse timing pour "${username}"...`);

        const measurements = [];
        let count = 0;
        const total = 10;

        function measure() {
            const startTime = performance.now();

            fetch('/Authentication/Login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `username=${encodeURIComponent(username)}&password=wrongpassword`
            })
                .then(response => response.json())
                .then(data => {
                    const elapsed = performance.now() - startTime;
                    measurements.push(elapsed);
                    count++;

                    if (count < total) {
                        setTimeout(measure, 100);
                    } else {
                        analyzeTimingResults(username, measurements);
                    }
                })
                .catch(error => {
                    console.error('Erreur:', error);
                });
        }

        measure();
    }

    function analyzeTimingResults(username, measurements) {
        const average = measurements.reduce((a, b) => a + b, 0) / measurements.length;
        const min = Math.min(...measurements);
        const max = Math.max(...measurements);

        timingResults.push({ username, average, min, max });

        // Afficher les résultats
        showTimingResults();

        // Déterminer si l'utilisateur existe basé sur le timing
        const threshold = 50; // ms
        const likelyExists = average > threshold;

        showNotification(
            likelyExists ? 'warning' : 'info',
            `${username}: ${average.toFixed(2)}ms avg - ${likelyExists ? 'Probablement EXISTE' : 'Probablement n\'existe pas'}`
        );

        addToHistory('timing-attack', `${username}: ${average.toFixed(2)}ms`, true);
    }

    function showTimingResults() {
        const resultsDiv = document.getElementById('timingResults');
        resultsDiv.style.display = 'block';

        // Créer un graphique simple avec canvas
        const canvas = document.getElementById('timingChart');
        const ctx = canvas.getContext('2d');

        // Clear canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Draw results
        const barWidth = canvas.width / timingResults.length;
        const maxTime = Math.max(...timingResults.map(r => r.average));

        timingResults.forEach((result, index) => {
            const barHeight = (result.average / maxTime) * (canvas.height - 40);
            const x = index * barWidth + 10;
            const y = canvas.height - barHeight - 20;

            // Draw bar
            ctx.fillStyle = result.average > 50 ? '#dc3545' : '#28a745';
            ctx.fillRect(x, y, barWidth - 20, barHeight);

            // Draw label
            ctx.fillStyle = '#000';
            ctx.font = '12px Arial';
            ctx.fillText(result.username, x, canvas.height - 5);
            ctx.fillText(result.average.toFixed(0) + 'ms', x, y - 5);
        });
    }

    function registerUser(username, password, email) {
        if (!username || !password) {
            showNotification('warning', 'Username et password requis');
            return;
        }

        showNotification('info', 'Création du compte...');

        fetch('/Authentication/Register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&email=${encodeURIComponent(email)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAuthResult(data, 'register');
                    showNotification('danger', 'Compte créé avec mot de passe stocké en clair!');

                    if (data.storedData) {
                        showNotification('warning', `Password visible: ${data.storedData.plainPassword}`);
                        showNotification('warning', `MD5 Hash: ${data.storedData.md5Hash}`);
                    }

                    addToHistory('insecure-storage', `${username} créé avec password en clair`, true);
                } else {
                    showNotification('error', data.error);
                    if (data.hint) {
                        showNotification('info', data.hint);
                    }
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function performBruteForce(username, passwords) {
        if (bruteForceInProgress) {
            showNotification('warning', 'Brute force déjà en cours...');
            return;
        }

        bruteForceInProgress = true;
        const progressDiv = document.getElementById('bruteProgress');
        const progressBar = progressDiv.querySelector('.progress-bar');
        progressDiv.style.display = 'block';

        showNotification('danger', `Brute force sur ${username} avec ${passwords.length} mots de passe!`);

        fetch('/Authentication/BruteForceTest', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&passwords=${passwords.map(p => encodeURIComponent(p)).join('&passwords=')}`
        })
            .then(response => response.json())
            .then(data => {
                bruteForceInProgress = false;
                progressBar.style.width = '100%';

                if (data.passwordFound) {
                    const found = data.attempts.find(a => a.success);
                    showNotification('danger', `🔓 MOT DE PASSE TROUVÉ: ${found.password}`);
                    showAuthResult({
                        success: true,
                        message: `Brute force réussi! Password: ${found.password}`,
                        attempts: data.totalAttempts,
                        vulnerabilities: data.vulnerabilities
                    }, 'bruteforce');
                } else {
                    showNotification('warning', 'Aucun mot de passe trouvé dans la liste');
                }

                addToHistory('no-account-lockout', `${data.totalAttempts} tentatives sur ${username}`, true);

                setTimeout(() => {
                    progressDiv.style.display = 'none';
                    progressBar.style.width = '0%';
                }, 2000);
            })
            .catch(error => {
                console.error('Erreur:', error);
                bruteForceInProgress = false;
            });
    }

    function createPredictableSession() {
        // Simuler une connexion pour créer une session
        performLogin('admin', 'admin123');
    }

    function hijackSession() {
        showNotification('info', 'Recherche de sessions actives...');

        // Tester les IDs séquentiels
        const sessionsToTest = ['1', '2', '3', '4', '5'];
        const foundSessions = [];

        Promise.all(sessionsToTest.map(id =>
            fetch(`/Authentication/CheckSession?sessionId=${id}`)
                .then(response => response.json())
                .catch(() => null)
        )).then(results => {
            results.forEach((data, index) => {
                if (data && data.success) {
                    foundSessions.push(data.session);
                }
            });

            if (foundSessions.length > 0) {
                showSessionsList(foundSessions);
                showNotification('danger', `${foundSessions.length} sessions trouvées!`);
                addToHistory('weak-session', `${foundSessions.length} sessions hijackables`, true);
            } else {
                showNotification('info', 'Aucune session active trouvée');
            }
        });
    }

    function checkSession() {
        const sessionId = document.getElementById('sessionIdCheck').value;
        if (!sessionId) {
            showNotification('warning', 'Entrez un Session ID');
            return;
        }

        fetch(`/Authentication/CheckSession?sessionId=${sessionId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('danger', `Session ${sessionId} ACTIVE!`);
                    showSessionInfo(data.session);

                    if (data.allSessions) {
                        showNotification('warning', `Sessions actives: ${data.allSessions.join(', ')}`);
                    }
                } else {
                    showNotification('info', data.error);
                    if (data.hint) {
                        showNotification('info', data.hint);
                    }
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function showAuthResult(data, type) {
        const resultsDiv = document.getElementById('authResults');
        const contentDiv = document.getElementById('authResultContent');

        resultsDiv.style.display = 'block';

        let html = `<h6>${data.success ? '✅ Succès' : '❌ Échec'}</h6>`;
        html += `<p>${data.message}</p>`;

        if (data.username) {
            html += `<p><strong>Username:</strong> ${data.username}</p>`;
        }

        if (data.sessionId) {
            html += `<div class="session-id-display">${data.sessionId}</div>`;
        }

        if (data.vulnerabilities) {
            html += `<div class="alert alert-warning mt-3">`;
            html += `<strong>Vulnérabilités exploitées:</strong>`;
            html += `<ul class="mb-0">`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li>${vuln}</li>`;
            });
            html += `</ul></div>`;
        }

        if (data.storedData) {
            html += `<div class="credentials-box">`;
            html += `<strong>Données stockées (EXPOSÉES!):</strong><br>`;
            html += `Password: <code>${data.storedData.plainPassword}</code><br>`;
            html += `<div class="hash-display">${data.storedData.md5Hash}</div>`;
            html += `</div>`;
        }

        if (type === 'bruteforce' && data.attempts) {
            html += `<p><strong>Tentatives:</strong> ${data.attempts}</p>`;
        }

        contentDiv.innerHTML = html;
    }

    function showEnumerationResult(result) {
        const resultsDiv = document.getElementById('authResults');
        const contentDiv = document.getElementById('authResultContent');

        resultsDiv.style.display = 'block';

        const enumClass = result.userExists ? 'enum-found' : 'enum-not-found';

        let html = `<div class="enum-result ${enumClass}">`;
        html += `<strong>${result.username}:</strong> ${result.error}<br>`;
        html += `<small>Timing: ${result.timing}ms</small><br>`;
        html += `<strong>Verdict:</strong> User ${result.userExists ? 'EXISTS' : 'DOES NOT EXIST'}`;
        html += `</div>`;

        if (result.userExists) {
            html += `<div class="alert alert-danger mt-2">`;
            html += `<i class="fas fa-exclamation-triangle"></i> User enumeration réussie!<br>`;
            html += `Le message "Mot de passe incorrect" confirme l'existence de l'utilisateur.`;
            html += `</div>`;
        }

        contentDiv.innerHTML = html;
    }

    function showSessionsList(sessions) {
        const sessionsDiv = document.getElementById('sessionsList');
        const contentDiv = document.getElementById('sessionsContent');

        sessionsDiv.style.display = 'block';

        let html = '<div class="hijack-warning">';
        html += 'Sessions hijackables détectées! IDs prévisibles permettent le vol de session.';
        html += '</div>';

        html += '<div class="mt-3">';
        sessions.forEach(session => {
            const adminClass = session.IsAdmin ? 'admin' : '';
            html += `<div class="session-item ${adminClass}">`;
            html += `<span class="session-id">Session ${session.SessionId}</span>`;
            html += `<span class="session-user">${session.Username}`;
            if (session.IsAdmin) {
                html += ' <span class="badge bg-danger">ADMIN</span>';
            }
            html += `</span>`;
            html += `</div>`;
        });
        html += '</div>';

        contentDiv.innerHTML = html;
    }

    function showSessionInfo(session) {
        const html = `
            <div class="alert alert-danger">
                <h6>Session hijackée!</h6>
                <p><strong>Session ID:</strong> ${session.SessionId}</p>
                <p><strong>Username:</strong> ${session.Username}</p>
                <p><strong>Admin:</strong> ${session.IsAdmin ? 'OUI' : 'Non'}</p>
                <p><strong>Créée:</strong> ${new Date(session.CreatedAt).toLocaleString()}</p>
            </div>
        `;

        showNotification('danger', 'Session compromise!');

        // Ajouter au résultat
        const contentDiv = document.getElementById('authResultContent');
        contentDiv.innerHTML = html;
        document.getElementById('authResults').style.display = 'block';
    }

    function checkPasswordStrength(password) {
        let strength = 0;

        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        // Afficher un indicateur visuel si nécessaire
        console.log(`Password strength: ${strength}/5`);
    }

    function showAuthWarnings() {
        console.group('%c⚠️ Authentication Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ Weak password policy (min 3 chars)');
        console.error('❌ Passwords stored in plaintext');
        console.error('❌ MD5 hashing (broken)');
        console.error('❌ User enumeration possible');
        console.error('❌ Timing attacks reveal users');
        console.error('❌ Sequential session IDs');
        console.error('❌ No account lockout');
        console.error('❌ No rate limiting');
        console.warn('💡 Prevention:');
        console.warn('   - Use bcrypt/Argon2 for passwords');
        console.warn('   - Generic error messages');
        console.warn('   - Constant time comparisons');
        console.warn('   - Cryptographically secure tokens');
        console.warn('   - Implement account lockout');
        console.warn('   - Add rate limiting');
        console.groupEnd();
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'danger' ? 'unlock' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
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
        console.log(`[${timestamp}] Auth ${actionType}: ${details}`);
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: '#loginPassword', title: 'Mots de passe faibles acceptés!' },
            { selector: '#sessionIdCheck', title: 'Essayez 1, 2, 3...' },
            { selector: '#bruteUsername', title: 'Aucune protection contre brute force' }
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

    // Fonctions globales
    window.testMultipleUsers = function () {
        const usernames = ['admin', 'user1', 'test', 'root', 'administrator', 'guest'];
        showNotification('info', `Test de ${usernames.length} usernames...`);

        usernames.forEach((username, index) => {
            setTimeout(() => {
                testUserEnumeration(username, 'test');
            }, index * 500);
        });
    };

    window.runTimingAnalysis = function () {
        const usernames = ['admin', 'user1', 'fakeuser', 'test', 'notexist'];
        timingResults = [];

        showNotification('info', `Analyse timing sur ${usernames.length} users...`);

        usernames.forEach((username, index) => {
            setTimeout(() => {
                performTimingAttack(username);
            }, index * 1500);
        });
    };

    window.loadCommonPasswords = function () {
        document.getElementById('passwordList').value = commonPasswords.slice(0, 50).join('\n');
        showNotification('info', 'Top 50 mots de passe chargés');
    };

    // Exposer certaines fonctions si nécessaire
    window.Authentication = {
        performLogin: performLogin,
        showNotification: showNotification,
        createPredictableSession: createPredictableSession,
        hijackSession: hijackSession,
        checkSession: checkSession
    };

})();