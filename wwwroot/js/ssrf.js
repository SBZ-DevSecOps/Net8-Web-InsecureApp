// ssrf.js - Gestion spécifique pour les vulnérabilités SSRF

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeSSRF();
    });

    function initializeSSRF() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Initialiser les formulaires SSRF
        initializeSSRFForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.ssrfData && window.ssrfData.hasResults) {
            addToHistory(
                window.ssrfData.attackType,
                window.ssrfData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Afficher les avertissements SSRF
        showSSRFWarnings();
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
            'url-fetch': 'http://localhost/admin ou http://192.168.1.1',
            'cloud-metadata': 'http://169.254.169.254/latest/meta-data/',
            'internal-scan': 'Host: 127.0.0.1, Port: 22',
            'file-protocol': 'file:///etc/passwd ou file:///c:/windows/win.ini',
            'bypass-blacklist': '127.1 ou 0x7f000001 ou localtest.me',
            'webhook-ssrf': 'http://internal-api:8080/webhook'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeSSRFForms() {
        // Form: URL Fetch
        const urlFetchForm = document.getElementById('urlFetchForm');
        if (urlFetchForm) {
            urlFetchForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const url = document.getElementById('fetchUrl').value;
                fetchURL(url);
            });
        }

        // Form: Port Scan
        const portScanForm = document.getElementById('portScanForm');
        if (portScanForm) {
            portScanForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const host = document.getElementById('scanHost').value;
                const port = document.getElementById('scanPort').value;
                scanPort(host, port);
            });
        }

        // Form: File Read
        const fileReadForm = document.getElementById('fileReadForm');
        if (fileReadForm) {
            fileReadForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const resource = document.getElementById('resourceUrl').value;
                fetchResource(resource);
            });
        }

        // Form: Webhook
        const webhookForm = document.getElementById('webhookForm');
        if (webhookForm) {
            webhookForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const callbackUrl = document.getElementById('callbackUrl').value;
                registerWebhook(callbackUrl);
            });
        }

        // Form: PDF Generation
        const pdfForm = document.getElementById('pdfForm');
        if (pdfForm) {
            pdfForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const htmlContent = document.getElementById('htmlContent').value;
                generatePDF(htmlContent);
            });
        }

        // Form: DNS Rebinding
        const dnsRebindingForm = document.getElementById('dnsRebindingForm');
        if (dnsRebindingForm) {
            dnsRebindingForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const domain = document.getElementById('rebindDomain').value;
                testDNSRebinding(domain);
            });
        }

        // Form: Redis
        const redisForm = document.getElementById('redisForm');
        if (redisForm) {
            redisForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const command = document.getElementById('redisCommand').value;
                testRedis(command);
            });
        }

        // Form: Blind SSRF
        const blindForm = document.getElementById('blindForm');
        if (blindForm) {
            blindForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const target = document.getElementById('blindTarget').value;
                testBlindSSRF(target);
            });
        }
    }

    function fetchURL(url) {
        showNotification('info', `Récupération de: ${url}`);

        fetch('/SSRF/FetchUrl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodeURIComponent(url)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'url-fetch');
                    showNotification('danger', data.warning || 'SSRF réussi!');
                    addToHistory('url-fetch', url, true);
                } else {
                    showNotification('error', data.error || 'Erreur SSRF');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function scanPort(host, port) {
        showNotification('info', `Scan de ${host}:${port}`);

        fetch('/SSRF/ScanPort', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `host=${encodeURIComponent(host)}&port=${port}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'port-scan');
                    const status = data.status === 'OUVERT' ? 'danger' : 'warning';
                    showNotification(status, `Port ${port} sur ${host}: ${data.status}`);
                    addToHistory('port-scan', `${host}:${port} - ${data.status}`, true);
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function fetchResource(resource) {
        showNotification('info', `Récupération de: ${resource}`);

        fetch('/SSRF/FetchResource', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `resource=${encodeURIComponent(resource)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'file-read');
                    showNotification('danger', data.warning || 'Ressource récupérée!');
                    addToHistory('file-read', `${data.protocol} - ${resource}`, true);
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function registerWebhook(callbackUrl) {
        showNotification('info', `Enregistrement webhook: ${callbackUrl}`);

        fetch('/SSRF/RegisterWebhook', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `callbackUrl=${encodeURIComponent(callbackUrl)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'webhook');
                    showNotification('danger', data.warning || 'Webhook SSRF réussi!');
                    addToHistory('webhook', callbackUrl, true);
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function showSSRFResult(data, type) {
        const resultsDiv = document.getElementById('ssrfResults');
        const contentDiv = document.getElementById('ssrfResultContent');

        resultsDiv.style.display = 'block';

        let html = '<h6>Résultat SSRF :</h6>';

        if (type === 'url-fetch') {
            html += `<div class="mb-3">`;
            html += `<strong>URL:</strong> ${data.url}<br>`;
            html += `<strong>Status:</strong> ${data.statusCode}<br>`;
            if (data.headers) {
                html += `<strong>Headers:</strong><br>`;
                html += `<pre class="bg-light p-2">${JSON.stringify(data.headers, null, 2)}</pre>`;
            }
            if (data.content) {
                html += `<strong>Contenu:</strong><br>`;
                html += `<pre class="bg-light p-2" style="max-height: 300px; overflow-y: auto;">${escapeHtml(data.content)}</pre>`;
            }
            html += `</div>`;
        } else if (type === 'port-scan') {
            html += `<ul>`;
            html += `<li><strong>Host:</strong> ${data.host}</li>`;
            html += `<li><strong>Port:</strong> ${data.port}</li>`;
            html += `<li><strong>Status:</strong> <span class="badge bg-${data.status === 'OUVERT' ? 'danger' : 'secondary'}">${data.status}</span></li>`;
            if (data.responseTime) {
                html += `<li><strong>Temps de réponse:</strong> ${data.responseTime}ms</li>`;
            }
            if (data.server) {
                html += `<li><strong>Server:</strong> ${data.server}</li>`;
            }
            html += `</ul>`;
        } else if (type === 'file-read') {
            html += `<div class="mb-3">`;
            html += `<strong>Protocol:</strong> ${data.protocol}<br>`;
            if (data.filePath) {
                html += `<strong>Fichier:</strong> ${data.filePath}<br>`;
            }
            if (data.content) {
                html += `<strong>Contenu:</strong><br>`;
                html += `<pre class="bg-light p-2">${escapeHtml(data.content)}</pre>`;
            }
            html += `</div>`;
        } else if (type === 'webhook') {
            html += `<ul>`;
            html += `<li><strong>Webhook ID:</strong> ${data.webhookId}</li>`;
            html += `<li><strong>Callback URL:</strong> ${data.callbackUrl}</li>`;
            if (data.testResult) {
                html += `<li><strong>Test Status:</strong> ${data.testResult.statusCode}</li>`;
            }
            html += `</ul>`;
        } else if (type === 'pdf-ssrf') {
            html += `<div class="mb-3">`;
            html += `<strong>Ressources chargées par le générateur PDF:</strong><br>`;
            if (data.loadedResources && data.loadedResources.length > 0) {
                html += `<ul>`;
                data.loadedResources.forEach(resource => {
                    html += `<li>`;
                    html += `<strong>${resource.url}</strong><br>`;
                    if (resource.statusCode) {
                        html += `Status: ${resource.statusCode}, Type: ${resource.contentType || 'N/A'}<br>`;
                    }
                    if (resource.error) {
                        html += `<span class="text-danger">Erreur: ${resource.error}</span><br>`;
                    }
                    html += `</li>`;
                });
                html += `</ul>`;
            }
            html += `</div>`;
        } else if (type === 'dns-rebinding') {
            html += `<ul>`;
            html += `<li><strong>Domaine:</strong> ${data.domain}</li>`;
            html += `<li><strong>Première résolution DNS:</strong> ${data.firstDnsResolution}</li>`;
            html += `<li><strong>Deuxième résolution DNS:</strong> ${data.secondDnsResolution}</li>`;
            html += `<li><strong>DNS changé:</strong> <span class="badge bg-${data.dnsChanged ? 'danger' : 'success'}">${data.dnsChanged ? 'OUI' : 'NON'}</span></li>`;
            html += `<li><strong>Status HTTP:</strong> ${data.responseStatus}</li>`;
            html += `</ul>`;
        } else if (type === 'redis-gopher') {
            html += `<div class="mb-3">`;
            html += `<strong>Protocole:</strong> ${data.protocol}<br>`;
            html += `<strong>Service cible:</strong> ${data.targetService}<br>`;
            html += `<strong>Commande:</strong> ${data.command}<br>`;
            html += `<strong>URL Gopher:</strong><br>`;
            html += `<code class="text-break">${data.gopherUrl}</code><br>`;
            html += `<strong>Commandes dangereuses:</strong><br>`;
            html += `<ul>`;
            data.exampleCommands.forEach(cmd => {
                html += `<li><code>${cmd}</code></li>`;
            });
            html += `</ul>`;
            html += `<small class="text-muted">${data.note}</small>`;
            html += `</div>`;
        } else if (type === 'blind-ssrf') {
            html += `<ul>`;
            html += `<li><strong>Message:</strong> ${data.message}</li>`;
            html += `<li><strong>Temps de réponse serveur:</strong> ${data.responseTime}ms</li>`;
            if (data.clientTime) {
                html += `<li><strong>Temps de réponse client:</strong> ${data.clientTime}ms</li>`;
            }
            if (data.timing) {
                html += `<li><strong>Analyse:</strong> ${data.timing}</li>`;
            }
            html += `</ul>`;
        }

        if (data.warning) {
            html += `<div class="alert alert-danger mt-3">`;
            html += `<i class="fas fa-exclamation-triangle"></i> ${data.warning}`;
            html += `</div>`;
        }

        contentDiv.innerHTML = html;
    }

    // Fonctions globales pour les boutons
    window.checkCloudMetadata = function (provider) {
        showNotification('info', `Vérification des métadonnées ${provider.toUpperCase()}...`);

        fetch(`/SSRF/CheckMetadata?endpoint=${provider}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'metadata');
                    showNotification('danger', `Métadonnées ${provider.toUpperCase()} exposées!`);
                    addToHistory('metadata', `${provider} - ${data.endpoint}`, true);
                }
            });
    };

    window.scanCommonPorts = function () {
        const commonPorts = [22, 80, 443, 3306, 5432, 6379, 8080, 9200];
        const host = document.getElementById('scanHost').value || '127.0.0.1';

        showNotification('info', `Scan des ports communs sur ${host}...`);

        commonPorts.forEach((port, index) => {
            setTimeout(() => {
                scanPort(host, port);
            }, index * 500); // Délai pour éviter le flood
        });
    };

    window.testBypass = function () {
        const bypassURLs = [
            'http://127.1/',
            'http://0x7f000001/',
            'http://2130706433/',
            'http://localtest.me/',
            'http://127.0.0.1.nip.io/'
        ];

        bypassURLs.forEach((url, index) => {
            setTimeout(() => {
                showNotification('info', `Test bypass: ${url}`);

                fetch('/SSRF/FetchWithBypass', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `url=${encodeURIComponent(url)}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showNotification('danger', `Bypass réussi avec: ${url}`);
                            addToHistory('bypass', url, true);
                        }
                    });
            }, index * 1000);
        });
    };

    function showSSRFWarnings() {
        console.group('%c⚠️ SSRF Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ No URL validation - Can access internal resources');
        console.error('❌ Cloud metadata endpoints accessible (169.254.169.254)');
        console.error('❌ Multiple protocols supported (file://, gopher://)');
        console.error('❌ Weak blacklist easily bypassed');
        console.error('❌ Internal port scanning possible');
        console.warn('💡 Prevention:');
        console.warn('   - Use URL whitelist, not blacklist');
        console.warn('   - Block private IP ranges (RFC1918)');
        console.warn('   - Allow only HTTP/HTTPS protocols');
        console.warn('   - Validate after DNS resolution');
        console.warn('   - Use network segmentation');
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
        console.log(`[${timestamp}] SSRF ${actionType}: ${details}`);
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: '#fetchUrl', title: 'Essayez localhost, 127.0.0.1, ou des IPs internes' },
            { selector: '#scanHost', title: 'Scanner les services internes non exposés' },
            { selector: '#resourceUrl', title: 'Utilisez file:// pour lire des fichiers locaux' }
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

    function generatePDF(htmlContent) {
        showNotification('info', 'Génération PDF avec chargement de ressources...');

        fetch('/SSRF/GeneratePDF', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `htmlContent=${encodeURIComponent(htmlContent)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'pdf-ssrf');
                    showNotification('danger', 'SSRF via PDF - Ressources internes chargées!');
                    addToHistory('pdf-ssrf', 'Images chargées via générateur PDF', true);
                }
            });
    }

    function testDNSRebinding(domain) {
        showNotification('info', `Test DNS rebinding: ${domain}`);

        fetch('/SSRF/CheckDomain', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `domain=${encodeURIComponent(domain)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'dns-rebinding');
                    if (data.dnsChanged) {
                        showNotification('danger', 'DNS REBINDING DÉTECTÉ! L\'IP a changé!');
                    }
                    addToHistory('dns-rebinding', `${domain} - DNS changed: ${data.dnsChanged}`, true);
                }
            });
    }

    function testRedis(command) {
        showNotification('info', `Commande Redis: ${command}`);

        fetch('/SSRF/TestRedis', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `command=${encodeURIComponent(command)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSSRFResult(data, 'redis-gopher');
                    showNotification('warning', 'Gopher URL générée pour Redis!');
                    addToHistory('redis-gopher', command, true);
                }
            });
    }

    function testBlindSSRF(target) {
        showNotification('info', `Blind SSRF test: ${target}`);
        const startTime = Date.now();

        fetch('/SSRF/BlindCheck', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `target=${encodeURIComponent(target)}`
        })
            .then(response => response.json())
            .then(data => {
                const clientTime = Date.now() - startTime;
                data.clientTime = clientTime;

                showSSRFResult(data, 'blind-ssrf');
                showNotification('warning', `Temps de réponse: ${data.responseTime}ms - ${data.timing || ''}`);
                addToHistory('blind-ssrf', `${target} - ${data.responseTime}ms`, true);
            });
    }

    // Fonction pour scanner une plage en blind SSRF
    window.blindScanRange = function () {
        showNotification('info', 'Scan blind SSRF de 192.168.1.1 à 192.168.1.10...');

        for (let i = 1; i <= 10; i++) {
            setTimeout(() => {
                const target = `http://192.168.1.${i}:80`;
                testBlindSSRF(target);
            }, i * 1000); // Délai d'1 seconde entre chaque
        }
    };

    // Fonction pour tester les confusions de parseur
    window.testParserConfusion = function () {
        const confusionUrls = [
            'http://expected.com#@localhost:8080/',
            'http://expected.com@localhost:8080/',
            'http://localhost#.expected.com/',
            'http://127.0.0.1:80\\@google.com/',
            'http://[::1]/',
            'http://2130706433/', // 127.0.0.1 en décimal
            'http://0x7f000001/' // 127.0.0.1 en hex
        ];

        confusionUrls.forEach((url, index) => {
            setTimeout(() => {
                showNotification('info', `Test parser: ${url}`);

                fetch('/SSRF/TestParserConfusion', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `url=${encodeURIComponent(url)}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showNotification('danger', `Parser confusion avec: ${url}`);
                            addToHistory('parser-confusion', url, true);
                        }
                    });
            }, index * 1000);
        });
    };

    // Ajouter le support pour l'avatar SSRF
    function testAvatarSSRF() {
        const avatarUrl = prompt('URL de l\'avatar:', 'http://169.254.169.254/latest/meta-data/');
        if (avatarUrl) {
            fetch('/SSRF/UpdateAvatar', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `avatarUrl=${encodeURIComponent(avatarUrl)}`
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showSSRFResult(data, 'avatar-ssrf');
                        showNotification('danger', 'SSRF via avatar URL!');
                    }
                });
        }
    }

    // Exposer certaines fonctions si nécessaire
    window.SSRF = {
        fetchURL: fetchURL,
        scanPort: scanPort,
        showNotification: showNotification,
        testAvatarSSRF: testAvatarSSRF
    };

})();