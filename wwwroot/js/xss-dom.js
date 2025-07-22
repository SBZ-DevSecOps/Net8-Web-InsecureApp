// xss-dom.js - Gestion des vulnérabilités XSS DOM-Based avec payloads avancés

(function () {
    'use strict';

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeXssDom();
    });

    function initializeXssDom() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Charger les commentaires au démarrage (VULNÉRABLE)
        loadComments();

        // Initialiser les handlers postMessage (VULNÉRABLE)
        initializePostMessageHandler();

        // Afficher l'URL actuelle pour le hash demo
        updateCurrentUrl();

        // Vérifier si on a un hash dans l'URL (VULNÉRABLE)
        if (window.location.hash) {
            displayHashContent();
        }

        // Afficher les avertissements
        showXssWarnings();
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

        const selectedOption = attackTypeSelect.options[attackTypeSelect.selectedIndex];
        const payloadExampleFromData = selectedOption.getAttribute('data-payload-example');

        if (payloadExampleFromData) {
            payloadExampleContent.textContent = payloadExampleFromData;
            payloadExample.style.display = 'block';
            updateContextualHelp(attackType, payloadInput);
        }
    }

    function updateContextualHelp(attackType, payloadInput) {
        const placeholders = {
            'dom-innerHTML': '<img src=x onerror=alert("XSS")>',
            'dom-document-write': '<script>alert("XSS")</script>',
            'dom-jquery-html': '<img src=x onerror="$.get(\'/steal?c=\'+document.cookie)">',
            'dom-location-hash': '#<img src=x onerror=alert("XSS")>',
            'dom-eval': 'alert("XSS-" + document.cookie)',
            'dom-postMessage': '{"action":"exec","code":"alert(\'XSS\')"}',
            'dom-encoded-payloads': '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;',
            'dom-svg-payload': '<svg/onload=alert("XSS")>',
            'dom-data-uri': 'data:text/html,<script>alert("XSS")</script>',
            'dom-mutation-xss': '<noscript><p title="</noscript><img src=x onerror=alert(1)>">'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    // === FONCTIONS VULNÉRABLES ORIGINALES ===

    // VULNÉRABLE : innerHTML direct
    window.updateWelcomeMessage = function () {
        const userInput = document.getElementById('userNameInput').value;
        const welcomeDiv = document.getElementById('welcomeMessage');

        // VULNÉRABLE : Injection directe dans innerHTML
        welcomeDiv.innerHTML = 'Bienvenue, ' + userInput + ' !';

        showNotification('danger', 'innerHTML utilisé - XSS possible!');
        addToHistory('innerHTML', userInput, true);
    };

    // VULNÉRABLE : document.write
    window.writeMessage = function () {
        const message = document.getElementById('messageInput').value;
        const outputDiv = document.getElementById('documentWriteOutput');

        // VULNÉRABLE : Créer un iframe et écrire dedans
        const iframe = document.createElement('iframe');
        iframe.style.width = '100%';
        iframe.style.height = '100px';
        iframe.style.border = '1px solid #dc3545';

        outputDiv.innerHTML = '';
        outputDiv.appendChild(iframe);

        // VULNÉRABLE : document.write dans l'iframe
        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
        iframeDoc.open();
        iframeDoc.write('<html><body>' + message + '</body></html>');
        iframeDoc.close();

        showNotification('danger', 'document.write exécuté!');
        addToHistory('document.write', message, true);
    };

    // VULNÉRABLE : jQuery .html()
    window.addComment = function () {
        const comment = document.getElementById('commentInput').value;
        const commentsSection = document.getElementById('commentsSection');

        const commentHtml = `
            <div class="comment">
                <strong>Utilisateur:</strong> ${comment}
                <small class="text-muted ms-2">${new Date().toLocaleTimeString()}</small>
            </div>
        `;

        // VULNÉRABLE : jQuery .html() sans échappement
        $('#commentsSection').append(commentHtml);

        showNotification('danger', 'jQuery .html() utilisé - XSS possible!');
        addToHistory('jQuery.html', comment, true);
    };

    // VULNÉRABLE : location.hash
    window.setMaliciousHash = function () {
        const maliciousHash = '#<img src=x onerror=alert("XSS-via-hash")>';
        window.location.hash = maliciousHash;
        updateCurrentUrl();
        showNotification('warning', 'Hash malveillant défini dans l\'URL');
    };

    window.displayHashContent = function () {
        const hash = window.location.hash.substring(1);
        const hashDisplay = document.getElementById('hashDisplay');

        if (hash) {
            // VULNÉRABLE : Injection directe du hash
            hashDisplay.innerHTML = 'Contenu du hash: ' + decodeURIComponent(hash);
            showNotification('danger', 'Hash injecté dans le DOM!');
            addToHistory('location.hash', hash, true);
        } else {
            hashDisplay.textContent = 'Aucun hash dans l\'URL';
        }
    };

    // VULNÉRABLE : eval()
    window.executeCode = function () {
        const code = document.getElementById('evalInput').value;
        const outputSpan = document.getElementById('evalOutput');

        try {
            // VULNÉRABLE : eval() direct du code utilisateur
            const result = eval(code);
            outputSpan.textContent = String(result);

            showNotification('danger', 'Code exécuté avec eval()!');
            addToHistory('eval', code, true);
        } catch (e) {
            outputSpan.textContent = 'Erreur: ' + e.message;
            showNotification('error', 'Erreur lors de l\'exécution: ' + e.message);
        }
    };

    // VULNÉRABLE : postMessage sans validation
    window.sendPostMessage = function () {
        const messageData = document.getElementById('postMessageInput').value;

        try {
            const data = JSON.parse(messageData);
            // Envoyer à la fenêtre actuelle (self)
            window.postMessage(data, '*'); // VULNÉRABLE : * accepte toute origine

            showNotification('warning', 'postMessage envoyé sans restriction d\'origine!');
            addToHistory('postMessage', messageData, true);
        } catch (e) {
            showNotification('error', 'JSON invalide');
        }
    };

    // === NOUVELLES FONCTIONS VULNÉRABLES POUR PAYLOADS AVANCÉS ===

    // VULNÉRABLE : Fonctions pour les payloads encodés
    window.selectEncodedPayload = function () {
        const select = document.getElementById('encodedPayloadSelect');
        const input = document.getElementById('encodedPayloadInput');
        input.value = select.value;
    };

    window.injectEncodedPayload = function () {
        const payload = document.getElementById('encodedPayloadInput').value;
        const output = document.getElementById('encodedPayloadOutput');

        // VULNÉRABLE : Injection directe du payload encodé
        output.innerHTML = payload;

        showNotification('danger', 'Payload encodé injecté!');
        addToHistory('encoded-payload', payload, true);
    };

    // VULNÉRABLE : Fonctions pour SVG
    window.selectSvgPayload = function () {
        const select = document.getElementById('svgPayloadSelect');
        const input = document.getElementById('svgPayloadInput');
        input.value = select.value;
    };

    window.injectSvgPayload = function () {
        const payload = document.getElementById('svgPayloadInput').value;
        const output = document.getElementById('svgPayloadOutput');

        // VULNÉRABLE : Injection directe SVG
        output.innerHTML = payload;

        showNotification('danger', 'SVG payload injecté!');
        addToHistory('svg-payload', payload, true);
    };

    // VULNÉRABLE : Fonctions pour Data URI
    window.selectDataUri = function () {
        const select = document.getElementById('dataUriSelect');
        const input = document.getElementById('dataUriInput');
        input.value = select.value;
    };

    window.injectDataUri = function () {
        const dataUri = document.getElementById('dataUriInput').value;
        const output = document.getElementById('dataUriOutput');

        // VULNÉRABLE : Création d'iframe avec data URI
        output.innerHTML = `<iframe src="${dataUri}" style="width:100%;height:100px;"></iframe>`;

        showNotification('danger', 'Data URI injecté!');
        addToHistory('data-uri', dataUri, true);
    };

    // VULNÉRABLE : Fonctions pour mXSS
    window.selectMxssPayload = function () {
        const select = document.getElementById('mxssPayloadSelect');
        const input = document.getElementById('mxssPayloadInput');
        input.value = select.value;
    };

    window.injectMxssPayload = function () {
        const payload = document.getElementById('mxssPayloadInput').value;
        const output = document.getElementById('mxssPayloadOutput');

        // VULNÉRABLE : Double parsing qui peut causer des mutations
        const temp = document.createElement('div');
        temp.innerHTML = payload;
        output.innerHTML = temp.innerHTML;

        showNotification('danger', 'mXSS payload injecté avec double parsing!');
        addToHistory('mutation-xss', payload, true);
    };

    // Afficher les payloads avancés
    window.showAdvancedPayloads = function () {
        const advancedPayloads = {
            'Encoding Bypass': [
                'String.fromCharCode(88,83,83)',
                'eval(atob("YWxlcnQoMSk="))',
                '\\u0061\\u006c\\u0065\\u0072\\u0074(1)',
                '&#x61;&#x6c;&#x65;&#x72;&#x74;(1)'
            ],
            'Filter Bypass': [
                'alert`1`',
                'alert.call`${1}`',
                'top[/al/.source+/ert/.source](1)',
                'top[String.fromCharCode(97,108,101,114,116)](1)'
            ],
            'Template Literals': [
                '${alert(1)}',
                '`${alert(1)}`',
                'eval`alert(1)`',
                '(function`alert(1)`)'
            ],
            'DOM Clobbering': [
                '<form id=test><input id=attributes><input id=attributes>',
                '<img name=body><object name=alert data=x:x>',
                '<svg><use id=x href=#x></svg>',
                '<input id=defaultStatus value="XSS">'
            ]
        };

        const dynamicDemo = document.getElementById('dynamicDemo');
        dynamicDemo.style.display = 'block';

        const outputZone = document.getElementById('xssOutputZone');
        outputZone.innerHTML = '<h5>Payloads XSS Avancés:</h5>';

        Object.entries(advancedPayloads).forEach(([category, payloads]) => {
            const categoryDiv = document.createElement('div');
            categoryDiv.className = 'mb-3 p-3 border rounded';
            categoryDiv.innerHTML = `
                <h6 class="text-danger">${category}:</h6>
                <ul class="list-unstyled mb-0">
                    ${payloads.map(payload => `
                        <li class="mb-1">
                            <code class="text-dark bg-light p-1 rounded">${payload}</code>
                            <button class="btn btn-sm btn-danger ms-2" onclick="executeAdvancedPayload('${payload.replace(/'/g, "\\'")}')">
                                Test
                            </button>
                        </li>
                    `).join('')}
                </ul>
            `;
            outputZone.appendChild(categoryDiv);
        });

        showNotification('info', 'Payloads avancés chargés - Attention aux exécutions!');
    };

    // VULNÉRABLE : Exécution de payloads avancés
    window.executeAdvancedPayload = function (payload) {
        const outputDiv = document.createElement('div');
        outputDiv.className = 'alert alert-danger mt-2';
        outputDiv.innerHTML = `Payload exécuté: <code>${payload}</code>`;

        try {
            // VULNÉRABLE : Diverses méthodes d'exécution
            if (payload.includes('eval')) {
                eval(payload);
            } else if (payload.includes('innerHTML')) {
                document.body.innerHTML += payload;
            } else if (payload.includes('String.fromCharCode')) {
                eval(payload);
            } else {
                // VULNÉRABLE : Injection générique
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = payload;
                document.body.appendChild(tempDiv);
            }

            showNotification('danger', `Payload avancé exécuté: ${payload.substring(0, 50)}...`);
            addToHistory('advanced-payload', payload, true);
        } catch (e) {
            showNotification('error', 'Erreur dans le payload avancé: ' + e.message);
        }
    };

    // === FONCTIONS VULNÉRABLES SUPPLÉMENTAIRES ===

    // VULNÉRABLE : Handler postMessage sans vérification
    function initializePostMessageHandler() {
        window.addEventListener('message', function (event) {
            // VULNÉRABLE : Pas de vérification de l'origine
            const receiver = document.getElementById('postMessageReceiver');

            if (receiver && event.data) {
                if (event.data.action === 'display' && event.data.html) {
                    // VULNÉRABLE : Injection directe
                    receiver.innerHTML = event.data.html;
                    showNotification('danger', 'postMessage reçu et exécuté sans validation!');
                } else if (event.data.action === 'exec' && event.data.code) {
                    // ENCORE PLUS VULNÉRABLE : eval du code reçu
                    try {
                        eval(event.data.code);
                    } catch (e) {
                        console.error('Erreur eval:', e);
                    }
                } else if (event.data.action === 'domManipulation') {
                    // VULNÉRABLE : Manipulation DOM directe
                    const selector = event.data.selector;
                    const content = event.data.content;
                    const elements = document.querySelectorAll(selector);
                    elements.forEach(el => {
                        el.innerHTML = content; // VULNÉRABLE
                    });
                }
            }
        });
    }

    // VULNÉRABLE : Charger et afficher les commentaires
    function loadComments() {
        const commentsList = document.getElementById('commentsList');

        if (commentsList && window.serverComments) {
            let html = '';

            window.serverComments.forEach(comment => {
                // VULNÉRABLE : Pas d'échappement
                html += `
                    <div class="comment" data-id="${comment.Id}">
                        <strong>${comment.Author}</strong>
                        <small class="text-muted ms-2">${comment.CreatedAt}</small>
                        <p>${comment.Content}</p>
                    </div>
                `;
            });

            // VULNÉRABLE : innerHTML avec données du serveur
            commentsList.innerHTML = html;
        }

        // VULNÉRABLE : Afficher les données utilisateur si présentes
        if (window.userData) {
            console.log('User data loaded:', window.userData);
            // VULNÉRABLE : Potentiellement dangereux si affiché dans le DOM
            const userDisplayDiv = document.getElementById('userDisplay');
            if (userDisplayDiv) {
                userDisplayDiv.innerHTML = `User: ${window.userData.username}`; // VULNÉRABLE
            }
        }
    }

    // Afficher toutes les vulnérabilités
    window.showAllVulnerabilities = function () {
        const demos = [
            { type: 'innerHTML', demo: updateWelcomeMessage },
            { type: 'document.write', demo: writeMessage },
            { type: 'jQuery.html', demo: addComment },
            { type: 'location.hash', demo: displayHashContent },
            { type: 'eval', demo: executeCode },
            { type: 'postMessage', demo: sendPostMessage },
            { type: 'encoded-payloads', demo: () => injectEncodedPayload() },
            { type: 'svg-payload', demo: () => injectSvgPayload() },
            { type: 'data-uri', demo: () => injectDataUri() },
            { type: 'mutation-xss', demo: () => injectMxssPayload() }
        ];

        showNotification('info', 'Démonstration de toutes les vulnérabilités XSS DOM');

        // Créer une zone de démo dynamique
        const dynamicDemo = document.getElementById('dynamicDemo');
        if (dynamicDemo) {
            dynamicDemo.style.display = 'block';

            const outputZone = document.getElementById('xssOutputZone');
            outputZone.innerHTML = '<h5>Vulnérabilités XSS DOM actives:</h5>';

            demos.forEach(({ type, demo }) => {
                const demoDiv = document.createElement('div');
                demoDiv.className = 'mb-3 p-2 border rounded';
                demoDiv.innerHTML = `
                    <strong>${type}:</strong>
                    <span class="xss-payload">Prêt pour injection</span>
                    <button class="btn btn-sm btn-danger ms-2" onclick="(${demo.toString()})()">
                        Test ${type}
                    </button>
                `;
                outputZone.appendChild(demoDiv);
            });
        }
    };

    // === FONCTIONS UTILITAIRES ===

    function updateCurrentUrl() {
        const urlSpan = document.getElementById('currentUrl');
        if (urlSpan) {
            urlSpan.textContent = window.location.href;
        }
    }

    function showNotification(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            <i class="fas fa-${type === 'danger' ? 'bug' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }

    function addToHistory(vulnerabilityType, payload, isVulnerable) {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[${timestamp}] XSS DOM ${vulnerabilityType}: ${payload}`);

        // Créer un indicateur visuel d'injection
        if (isVulnerable && (payload.includes('<') || payload.includes('javascript:') || payload.includes('data:'))) {
            const indicator = document.createElement('div');
            indicator.className = 'xss-active-alert';
            indicator.innerHTML = '<i class="fas fa-skull-crossbones"></i> XSS Injecté!';
            document.body.appendChild(indicator);

            setTimeout(() => indicator.remove(), 2000);
        }
    }

    function showXssWarnings() {
        console.group('%c⚠️ XSS DOM-Based Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ innerHTML usage without sanitization');
        console.error('❌ document.write() with user input');
        console.error('❌ jQuery .html() without encoding');
        console.error('❌ location.hash injection');
        console.error('❌ eval() with user input');
        console.error('❌ postMessage without origin validation');
        console.error('❌ Base64 decoding (atob) with user input');
        console.error('❌ String.fromCharCode manipulation');
        console.error('❌ SVG injection vectors');
        console.error('❌ Data URI protocol usage');
        console.error('❌ Template literal injections');
        console.error('❌ DOM clobbering possibilities');
        console.warn('💡 Prevention:');
        console.warn('   - Use textContent instead of innerHTML');
        console.warn('   - Sanitize with DOMPurify');
        console.warn('   - Implement Content-Security-Policy');
        console.warn('   - Use Trusted Types API');
        console.warn('   - Always validate postMessage origin');
        console.warn('   - Never use eval() with user input');
        console.warn('   - Validate and sanitize SVG content');
        console.warn('   - Restrict data URI usage');
        console.groupEnd();
    }

    // Event listeners pour les changements de hash
    window.addEventListener('hashchange', function () {
        updateCurrentUrl();
        if (window.xssDomData && window.xssDomData.attackType === 'dom-location-hash') {
            displayHashContent();
        }
    });

    // VULNÉRABLE : Si on a un payload du serveur, l'exécuter
    if (window.serverPayload) {
        console.warn('Server payload detected:', window.serverPayload);
        // VULNÉRABLE : Exécution automatique du payload serveur
        setTimeout(() => {
            try {
                eval(window.serverPayload); // EXTRÊMEMENT VULNÉRABLE
            } catch (e) {
                console.error('Server payload execution failed:', e);
            }
        }, 1000);
    }

    // VULNÉRABLE : Fonction globale pour injection dynamique
    window.dynamicInject = function (content, target) {
        const element = document.getElementById(target) || document.body;
        element.innerHTML += content; // VULNÉRABLE
        showNotification('danger', 'Contenu injecté dynamiquement!');
    };

    // VULNÉRABLE : Fonction pour créer des éléments avec contenu non sanitisé
    window.createUnsafeElement = function (tagName, content, attributes = {}) {
        const element = document.createElement(tagName);

        // VULNÉRABLE : Attribution directe des attributs
        Object.entries(attributes).forEach(([key, value]) => {
            element.setAttribute(key, value); // VULNÉRABLE si value contient du JavaScript
        });

        // VULNÉRABLE : Contenu non sanitisé
        element.innerHTML = content;

        document.body.appendChild(element);
        return element;
    };

})();