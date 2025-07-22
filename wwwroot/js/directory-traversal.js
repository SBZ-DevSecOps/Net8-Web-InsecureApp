// directory-traversal.js - Gestion spécifique pour les vulnérabilités Directory Traversal

(function () {
    'use strict';

    // Variables globales
    let currentPath = '.';
    let exploitedFiles = [];

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeDirectoryTraversal();
    });

    function initializeDirectoryTraversal() {
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
        initializeTraversalForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.traversalData && window.traversalData.hasResults) {
            addToHistory(
                window.traversalData.attackType,
                window.traversalData.payload,
                true
            );
        }

        // Afficher les avertissements
        showTraversalWarnings();
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
            'basic-traversal': '../../../../etc/passwd',
            'download-files': '../../config/appsettings.json',
            'include-files': '../../../Controllers/AdminController.cs',
            'encoding-bypass': '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            'null-byte': '../../../../etc/passwd%00.jpg',
            'template-injection': '{{file:/etc/passwd}}',
            'backup-files': 'web.config',
            'windows-paths': '..\\..\\windows\\system32\\drivers\\etc\\hosts'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeTraversalForms() {
        // Form: Basic Traversal
        const basicTraversalForm = document.getElementById('basicTraversalForm');
        if (basicTraversalForm) {
            basicTraversalForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const filename = document.getElementById('basicFilename').value;
                readFileTraversal(filename);
            });
        }

        // Form: Include
        const includeForm = document.getElementById('includeForm');
        if (includeForm) {
            includeForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const page = document.getElementById('includePage').value;
                includeFile(page);
            });
        }

        // Form: Null Byte
        const nullByteForm = document.getElementById('nullByteForm');
        if (nullByteForm) {
            nullByteForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const file = document.getElementById('nullByteFile').value;
                exploitNullByte(file);
            });
        }

        // Form: Template
        const templateForm = document.getElementById('templateForm');
        if (templateForm) {
            templateForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const expr = document.getElementById('templateExpr').value;
                exploitTemplate(expr);
            });
        }

        // Form: Backup
        const backupForm = document.getElementById('backupForm');
        if (backupForm) {
            backupForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const file = document.getElementById('backupFile').value;
                findBackupFiles(file);
            });
        }

        // Form: ZIP Slip
        const zipSlipForm = document.getElementById('zipSlipForm');
        if (zipSlipForm) {
            zipSlipForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('zipFile');
                if (fileInput.files.length > 0) {
                    testZipSlip(fileInput.files[0]);
                } else {
                    showNotification('warning', 'Sélectionnez un fichier ZIP');
                }
            });
        }
    }

    function readFileTraversal(filename) {
        showNotification('info', `Tentative de lecture: ${filename}`);

        fetch('/DirectoryTraversal/ReadFile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `filename=${encodeURIComponent(filename)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'file-read');
                    showNotification('danger', data.warning);
                    addToHistory('file-read', filename, true);
                    exploitedFiles.push(filename);
                } else {
                    showNotification('error', data.error || 'Fichier non trouvé');
                    if (data.attemptedPath) {
                        console.log('Attempted path:', data.attemptedPath);
                    }
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function includeFile(page) {
        showNotification('info', `Inclusion de: ${page}`);

        fetch('/DirectoryTraversal/IncludePage', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `page=${encodeURIComponent(page)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'file-include');
                    showNotification('danger', 'Code source exposé!');
                    addToHistory('file-include', page, true);
                }
            });
    }

    function exploitNullByte(file) {
        showNotification('info', `Null byte injection: ${file}`);

        fetch('/DirectoryTraversal/ReadFileNullByte', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `file=${encodeURIComponent(file)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'null-byte');
                    showNotification('danger', data.warning);
                    addToHistory('null-byte', file, true);
                }
            });
    }

    function exploitTemplate(template) {
        showNotification('info', `Template injection: ${template}`);

        fetch('/DirectoryTraversal/RenderTemplate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `template=${encodeURIComponent(template)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.evaluation) {
                    showTraversalResult(data, 'template');
                    showNotification('danger', data.warning || 'Template injection réussie!');
                    addToHistory('template-injection', template, true);
                } else {
                    showNotification('info', data.message || 'Template traité');
                }
            });
    }

    function findBackupFiles(file) {
        showNotification('info', `Recherche de backups pour: ${file}`);

        fetch('/DirectoryTraversal/AccessBackup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `file=${encodeURIComponent(file)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'backup-files');
                    if (data.foundBackups && data.foundBackups.length > 0) {
                        showNotification('danger', 'Fichiers backup trouvés!');
                    } else {
                        showNotification('warning', 'Aucun backup trouvé');
                    }
                    addToHistory('backup-search', file, data.foundBackups.length > 0);
                }
            });
    }

    function testZipSlip(file) {
        showNotification('info', `Test ZIP Slip avec: ${file.name}`);

        const formData = new FormData();
        formData.append('zipFile', file);

        fetch('/DirectoryTraversal/ExtractZip', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'zip-slip');
                    showNotification('danger', data.warning);
                    addToHistory('zip-slip', file.name, true);
                }
            });
    }

    function showTraversalResult(data, type) {
        const resultsDiv = document.getElementById('traversalResults');
        const contentDiv = document.getElementById('traversalResultContent');

        resultsDiv.style.display = 'block';

        let html = '<h6>Résultat Directory Traversal :</h6>';

        if (type === 'file-read') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier:</strong> ${data.filename}<br>`;
            html += `<strong>Chemin complet:</strong> <code>${data.fullPath}</code><br>`;
            html += `<strong>Chemin normalisé:</strong> <code>${data.normalizedPath}</code><br>`;
            html += `<strong>Taille:</strong> ${data.size} octets<br>`;
            html += `<strong>Modifié:</strong> ${new Date(data.lastModified).toLocaleString()}<br>`;
            html += `<strong>Contenu:</strong><br>`;
            html += `<pre class="bg-light p-2" style="max-height: 300px; overflow-y: auto;">${escapeHtml(data.content)}</pre>`;
            html += `</div>`;
        } else if (type === 'file-include') {
            html += `<div class="mb-3">`;
            html += `<strong>Page incluse:</strong> ${data.page}<br>`;
            html += `<strong>Type de fichier:</strong> ${data.fileType}<br>`;
            html += `<strong>Chemin réel:</strong> <code>${data.realPath}</code><br>`;
            html += `<strong>Code source exposé:</strong><br>`;
            html += `<pre class="bg-light p-2" style="max-height: 300px; overflow-y: auto;"><code>${escapeHtml(data.content)}</code></pre>`;
            html += `</div>`;
        } else if (type === 'directory-listing') {
            html += `<div class="mb-3">`;
            html += `<strong>Répertoire:</strong> <code>${data.path}</code><br>`;
            html += `<strong>Chemin complet:</strong> <code>${data.fullPath}</code><br>`;
            if (data.parentPath) {
                html += `<strong>Parent:</strong> <code>${data.parentPath}</code><br>`;
            }
            html += `<strong>Utilisateur:</strong> ${data.currentUser}<br>`;
            html += `<strong>Contenu du répertoire:</strong><br>`;
            html += `<div class="mt-2">`;
            data.entries.forEach(entry => {
                if (entry.type === 'directory') {
                    html += `<div><i class="fas fa-folder text-warning"></i> ${entry.name}/</div>`;
                } else {
                    html += `<div><i class="fas fa-file text-secondary"></i> ${entry.name} (${entry.size} bytes)</div>`;
                }
            });
            html += `</div>`;
            html += `</div>`;
        } else if (type === 'encoding-bypass') {
            html += `<div class="mb-3">`;
            html += `<strong>Path encodé:</strong> <code>${data.encodedPath}</code><br>`;
            html += `<strong>Path décodé:</strong> <code>${data.decodedPath}</code><br>`;
            html += `<strong>Contenu lu:</strong><br>`;
            html += `<pre class="bg-light p-2">${escapeHtml(data.content)}</pre>`;
            html += `<strong>Méthodes de bypass:</strong><br>`;
            html += `<ul>`;
            data.bypassMethods.forEach(method => {
                html += `<li><code>${method}</code></li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'null-byte') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier demandé:</strong> <code>${data.requestedFile}</code><br>`;
            html += `<strong>Fichier réel lu:</strong> <code>${data.actualFile}</code><br>`;
            html += `<strong>Technique:</strong> ${data.technique}<br>`;
            html += `<strong>Contenu:</strong><br>`;
            html += `<pre class="bg-light p-2">${escapeHtml(data.content)}</pre>`;
            html += `</div>`;
        } else if (type === 'template') {
            html += `<div class="mb-3">`;
            html += `<strong>Template:</strong> <code>${data.template}</code><br>`;
            html += `<strong>Évaluation:</strong><br>`;
            html += `<pre class="bg-light p-2">${escapeHtml(data.evaluation)}</pre>`;
            if (data.examples) {
                html += `<strong>Autres exemples:</strong><br>`;
                html += `<ul>`;
                data.examples.forEach(ex => {
                    html += `<li><code>${ex}</code></li>`;
                });
                html += `</ul>`;
            }
            html += `</div>`;
        } else if (type === 'backup-files') {
            html += `<div class="mb-3">`;
            html += `<strong>Fichier original:</strong> ${data.requestedFile}<br>`;
            if (data.foundBackups && data.foundBackups.length > 0) {
                html += `<strong>Backups trouvés:</strong><br>`;
                data.foundBackups.forEach(backup => {
                    html += `<div class="mt-2 p-2 border rounded">`;
                    html += `<strong>Path:</strong> <code>${backup.path}</code><br>`;
                    html += `<strong>Taille:</strong> ${backup.size} octets<br>`;
                    html += `<strong>Contenu:</strong><br>`;
                    html += `<pre class="bg-light p-2 small">${escapeHtml(backup.content)}</pre>`;
                    html += `</div>`;
                });
            } else {
                html += `<p class="text-muted">Aucun fichier backup trouvé</p>`;
            }
            html += `<strong>Patterns de backup communs:</strong><br>`;
            html += `<ul>`;
            data.commonBackupPatterns.forEach(pattern => {
                html += `<li><code>${pattern}</code></li>`;
            });
            html += `</ul>`;
            html += `</div>`;
        } else if (type === 'zip-slip') {
            html += `<div class="mb-3">`;
            html += `<strong>Archive:</strong> ${data.filename}<br>`;
            html += `<strong>Fichiers dans l'archive:</strong><br>`;
            html += `<div class="table-responsive mt-2">`;
            html += `<table class="table table-sm">`;
            html += `<thead><tr><th>Entrée</th><th>Destination</th><th>Dangereux</th></tr></thead>`;
            html += `<tbody>`;
            data.extractedFiles.forEach(file => {
                const rowClass = file.isDangerous ? 'table-danger' : '';
                html += `<tr class="${rowClass}">`;
                html += `<td><code>${file.entryName}</code></td>`;
                html += `<td><code class="small">${file.normalizedPath}</code></td>`;
                html += `<td>${file.wouldEscape ? '<span class="badge bg-danger">ESCAPE!</span>' : '<span class="badge bg-success">OK</span>'}</td>`;
                html += `</tr>`;
            });
            html += `</tbody></table></div>`;
            html += `<strong>Exemple malveillant:</strong><br>`;
            html += `<code>${data.maliciousExample.entry}</code> → <code>${data.maliciousExample.wouldExtractTo}</code>`;
            html += `</div>`;
        } else if (type === 'windows-paths') {
            html += `<div class="mb-3">`;
            html += `<strong>Path original:</strong> <code>${data.originalPath}</code><br>`;
            html += `<strong>Résultats des différentes syntaxes:</strong><br>`;
            Object.entries(data.results).forEach(([method, result]) => {
                html += `<div class="mt-2 p-2 border rounded">`;
                html += `<strong>${method}:</strong><br>`;
                if (result.error) {
                    html += `<span class="text-danger">Erreur: ${result.error}</span>`;
                } else {
                    html += `Path: <code>${result.path}</code><br>`;
                    html += `Existe: <span class="badge bg-${result.exists ? 'success' : 'secondary'}">${result.exists ? 'OUI' : 'NON'}</span><br>`;
                    html += `Normalisé: <code>${result.normalized}</code>`;
                }
                html += `</div>`;
            });
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
    window.downloadTraversalFile = function () {
        const file = document.getElementById('downloadFile').value;
        if (!file) {
            showNotification('warning', 'Entrez un chemin de fichier');
            return;
        }

        // Ouvrir directement l'URL de téléchargement
        const downloadUrl = `/DirectoryTraversal/DownloadFile?file=${encodeURIComponent(file)}`;
        window.open(downloadUrl, '_blank');

        showNotification('info', `Téléchargement: ${file}`);
        addToHistory('file-download', file, true);
    };

    window.tryCommonFiles = function () {
        const commonFiles = [
            '../../appsettings.json',
            '../../Program.cs',
            '../.env',
            '../../web.config',
            'secret/passwords.txt',
            'private/api-keys.json',
            'backup/users.csv',
            '../config.json',
            '../../bin/Debug/InsecureAppWebNet8.dll',
            '../../InsecureAppWebNet8.csproj'
        ];

        showNotification('info', 'Test des fichiers sensibles de l\'application...');

        commonFiles.forEach((file, index) => {
            setTimeout(() => {
                readFileTraversal(file);
            }, index * 1000);
        });
    };

    window.testEncodingBypass = function () {
        const encodings = [
            { encoded: '%2e%2e%2f%2e%2e%2fappsettings.json', description: 'URL encoding simple' },
            { encoded: '%252e%252e%252f%252e%252e%252fappsettings.json', description: 'Double URL encoding' },
            { encoded: '..%2fconfig.json', description: 'Partial URL encoding' },
            { encoded: '..%5c..%5cProgram.cs', description: 'Backslash encoding' }
        ];

        encodings.forEach((encoding, index) => {
            setTimeout(() => {
                showNotification('info', `Test ${encoding.description}`);

                fetch('/DirectoryTraversal/ReadFileEncoded', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `encodedPath=${encoding.encoded}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showTraversalResult(data, 'encoding-bypass');
                            showNotification('danger', `Bypass réussi avec ${encoding.description}!`);
                        }
                    });
            }, index * 1500);
        });
    };

    window.testWindowsPaths = function () {
        const windowsPaths = [
            '..\\..\\appsettings.json',
            '..\\..\\Program.cs',
            '..\\config.json',
            'secret\\passwords.txt',
            '..\\..\\web.config',
            '..\\..\\bin\\Debug\\InsecureAppWebNet8.dll'
        ];

        showNotification('info', 'Test des syntaxes Windows...');

        windowsPaths.forEach((path, index) => {
            setTimeout(() => {
                fetch('/DirectoryTraversal/WindowsTraversal', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `path=${encodeURIComponent(path)}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showTraversalResult(data, 'windows-paths');
                        }
                    });
            }, index * 1000);
        });
    };

    window.listCurrentDirectory = function () {
        showNotification('info', `Listing du répertoire: ${currentPath}`);

        fetch('/DirectoryTraversal/ListDirectory', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `path=${encodeURIComponent(currentPath)}`
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showTraversalResult(data, 'directory-listing');
                    showFileBrowser(data);
                    showNotification('warning', 'Directory listing exposé!');
                    addToHistory('directory-listing', currentPath, true);
                }
            });
    };

    function showFileBrowser(data) {
        const fileBrowser = document.getElementById('fileBrowser');
        const pathDisplay = document.getElementById('pathDisplay');
        const fileList = document.getElementById('fileList');

        fileBrowser.style.display = 'block';
        pathDisplay.textContent = data.fullPath;
        currentPath = data.path;

        let html = '';

        // Bouton parent
        if (data.parentPath) {
            html += `<div class="file-entry" onclick="navigateToParent()">`;
            html += `<i class="fas fa-level-up-alt text-primary"></i> ..`;
            html += `</div>`;
        }

        // Dossiers
        data.entries.filter(e => e.type === 'directory').forEach(dir => {
            html += `<div class="file-entry" onclick="navigateToDirectory('${currentPath}/${dir.name}')">`;
            html += `<i class="fas fa-folder text-warning"></i> ${dir.name}/`;
            html += `</div>`;
        });

        // Fichiers
        data.entries.filter(e => e.type === 'file').forEach(file => {
            html += `<div class="file-entry" onclick="readFileFromBrowser('${currentPath}/${file.name}')">`;
            html += `<i class="fas fa-file text-secondary"></i> ${file.name}`;
            html += `<span class="file-size">(${formatBytes(file.size)})</span>`;
            html += `</div>`;
        });

        fileList.innerHTML = html;
    }

    window.navigateToDirectory = function (path) {
        currentPath = path;
        listCurrentDirectory();
    };

    window.navigateToParent = function () {
        currentPath = currentPath.includes('/')
            ? currentPath.substring(0, currentPath.lastIndexOf('/')) || '.'
            : '..';
        listCurrentDirectory();
    };

    window.readFileFromBrowser = function (path) {
        readFileTraversal(path);
    };

    window.createMaliciousZip = function () {
        showNotification('info', 'Génération d\'un ZIP malveillant (simulation)');

        const maliciousEntries = [
            '../../evil.aspx',
            '../../../inetpub/wwwroot/shell.aspx',
            '../../../../windows/system32/evil.dll',
            'normal.txt'
        ];

        const html = `
            <h6>Structure ZIP malveillante :</h6>
            <pre>${maliciousEntries.join('\n')}</pre>
            <p class="text-danger">Ce ZIP pourrait écraser des fichiers système lors de l'extraction!</p>
        `;

        showCustomResult(html);
    };

    function showCustomResult(html) {
        const resultsDiv = document.getElementById('traversalResults');
        const contentDiv = document.getElementById('traversalResultContent');

        resultsDiv.style.display = 'block';
        contentDiv.innerHTML = html;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function showTraversalWarnings() {
        console.group('%c⚠️ Directory Traversal Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ No path validation - ../../../ accepted');
        console.error('❌ Path.Combine with user input');
        console.error('❌ No canonical path checking');
        console.error('❌ Directory listing enabled');
        console.error('❌ Backup files accessible (.bak, ~, .old)');
        console.error('❌ Multiple encoding bypasses possible');
        console.error('❌ ZIP extraction without validation');
        console.warn('💡 Prevention:');
        console.warn('   - Validate and sanitize all file paths');
        console.warn('   - Use GetFullPath() and verify it stays in allowed directory');
        console.warn('   - Whitelist allowed files');
        console.warn('   - Never use user input directly in file operations');
        console.warn('   - Disable directory listing');
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
        console.log(`[${timestamp}] Directory Traversal ${actionType}: ${details}`);
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
    window.DirectoryTraversal = {
        readFileTraversal: readFileTraversal,
        showNotification: showNotification,
        listCurrentDirectory: listCurrentDirectory
    };

})();