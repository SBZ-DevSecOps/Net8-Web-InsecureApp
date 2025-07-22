// file-upload.js - Gestion spécifique pour les vulnérabilités File Upload

(function () {
    'use strict';

    // Variable pour stocker le MIME type falsifié
    let spoofedMimeType = null;

    // Initialisation
    document.addEventListener('DOMContentLoaded', function () {
        initializeFileUpload();
    });

    function initializeFileUpload() {
        // Gestionnaire pour le changement de type d'attaque
        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.addEventListener('change', handleAttackTypeChange);
            // Déclencher l'événement si une valeur est déjà sélectionnée
            if (attackTypeSelect.value) {
                setTimeout(() => handleAttackTypeChange(), 100);
            }
        }

        // Initialiser les formulaires d'upload
        initializeUploadForms();

        // Ajouter à l'historique si nous avons des résultats
        if (window.fileUploadData && window.fileUploadData.hasResults) {
            addToHistory(
                window.fileUploadData.attackType,
                window.fileUploadData.payload,
                true
            );
        }

        // Initialiser les tooltips
        initializeTooltips();

        // Afficher les avertissements
        showFileUploadWarnings();
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
            'no-validation': 'virus.exe, shell.aspx, malware.php',
            'path-traversal': '../../wwwroot/web.config',
            'executable-upload': 'webshell.aspx, backdoor.php',
            'mime-bypass': 'shell.php avec Content-Type: image/jpeg',
            'dos-large-file': 'huge_file_2gb.bin',
            'double-extension': 'exploit.jpg.aspx, script.pdf.exe'
        };

        if (placeholders[attackType]) {
            payloadInput.placeholder = placeholders[attackType];
        }
    }

    function initializeUploadForms() {
        // Form: No validation
        const noValidationForm = document.getElementById('noValidationForm');
        if (noValidationForm) {
            noValidationForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('anyFile');
                uploadFile('/FileUpload/UploadNoValidation', fileInput.files[0], 'no-validation');
            });
        }

        // Form: Path traversal
        const pathTraversalForm = document.getElementById('pathTraversalForm');
        if (pathTraversalForm) {
            pathTraversalForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('pathFile');
                const customPath = document.getElementById('customPath').value;
                uploadFileWithPath('/FileUpload/UploadWithPathTraversal', fileInput.files[0], customPath);
            });
        }

        // Form: Executable
        const executableForm = document.getElementById('executableForm');
        if (executableForm) {
            executableForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('execFile');
                uploadFile('/FileUpload/UploadExecutable', fileInput.files[0], 'executable');
            });
        }

        // Form: MIME bypass
        const mimeBypassForm = document.getElementById('mimeBypassForm');
        if (mimeBypassForm) {
            mimeBypassForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('mimeFile');
                uploadFileWithMimeSpoof('/FileUpload/UploadWithWeakMime', fileInput.files[0]);
            });
        }

        // Form: Large file
        const largeFileForm = document.getElementById('largeFileForm');
        if (largeFileForm) {
            largeFileForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('largeFile');
                uploadLargeFile('/FileUpload/UploadLargeFile', fileInput.files[0]);
            });
        }

        // Form: Double extension
        const doubleExtForm = document.getElementById('doubleExtForm');
        if (doubleExtForm) {
            doubleExtForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const fileInput = document.getElementById('doubleExtFile');
                uploadFile('/FileUpload/UploadDoubleExtension', fileInput.files[0], 'double-ext');
            });
        }
    }

    function uploadFile(url, file, type) {
        if (!file) {
            showNotification('warning', 'Veuillez sélectionner un fichier');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        showNotification('info', `Upload de ${file.name} en cours...`);

        fetch(url, {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showUploadResult(data, file, type);
                    showNotification('danger', data.warning || 'Fichier uploadé avec succès!');
                    addToHistory(type, `${file.name} uploadé`, true);
                } else {
                    showNotification('error', data.error || 'Erreur lors de l\'upload');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
                showNotification('error', 'Erreur lors de l\'upload');
            });
    }

    function uploadFileWithPath(url, file, customPath) {
        if (!file) {
            showNotification('warning', 'Veuillez sélectionner un fichier');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('customPath', customPath);

        showNotification('info', `Path traversal: ${customPath}`);

        fetch(url, {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showUploadResult(data, file, 'path-traversal');
                    showNotification('danger', 'Path traversal exploité!');
                    addToHistory('path-traversal', `${customPath} créé`, true);
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function uploadFileWithMimeSpoof(url, file) {
        if (!file) {
            showNotification('warning', 'Veuillez sélectionner un fichier');
            return;
        }

        // Créer un nouveau fichier avec un MIME type falsifié
        const blob = new Blob([file], { type: spoofedMimeType || 'image/jpeg' });
        const spoofedFile = new File([blob], file.name, { type: spoofedMimeType || 'image/jpeg' });

        const formData = new FormData();
        formData.append('file', spoofedFile);

        showNotification('info', `Upload avec MIME falsifié: ${spoofedFile.type}`);

        fetch(url, {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showUploadResult(data, file, 'mime-bypass');
                    showNotification('danger', 'MIME type bypass réussi!');
                    addToHistory('mime-bypass', `${file.name} avec faux MIME`, true);
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
            });
    }

    function uploadLargeFile(url, file) {
        if (!file) {
            showNotification('warning', 'Veuillez sélectionner un fichier');
            return;
        }

        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        showNotification('warning', `Upload de fichier volumineux: ${sizeMB} MB`);

        const formData = new FormData();
        formData.append('file', file);

        // Afficher la progression
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', function (e) {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                showNotification('info', `Upload: ${percentComplete.toFixed(0)}%`);
            }
        });

        xhr.onload = function () {
            if (xhr.status === 200) {
                const data = JSON.parse(xhr.responseText);
                if (data.success) {
                    showUploadResult(data, file, 'dos-large');
                    showNotification('danger', `DoS: ${sizeMB} MB uploadés!`);
                    addToHistory('dos-large', `${file.name} (${sizeMB} MB)`, true);
                }
            }
        };

        xhr.open('POST', url);
        xhr.send(formData);
    }

    function showUploadResult(data, file, type) {
        const resultsDiv = document.getElementById('uploadResults');
        const contentDiv = document.getElementById('uploadResultContent');

        resultsDiv.style.display = 'block';

        let html = `<h6>Fichier uploadé avec succès!</h6>`;
        html += `<ul class="mb-0">`;
        html += `<li><strong>Nom:</strong> ${file.name}</li>`;
        html += `<li><strong>Taille:</strong> ${(file.size / 1024).toFixed(2)} KB</li>`;
        html += `<li><strong>Type déclaré:</strong> ${file.type || 'Aucun'}</li>`;

        if (data.webPath || data.filePath || data.directLink) {
            const link = data.webPath || data.filePath || data.directLink;
            html += `<li><strong>Accès web:</strong> <a href="${link}" target="_blank" class="text-danger">${link}</a></li>`;
        }

        if (data.isDangerous) {
            html += `<li class="text-danger"><strong>⚠️ FICHIER DANGEREUX DÉTECTÉ!</strong></li>`;
        }

        if (data.warning) {
            html += `<li class="text-warning"><strong>Avertissement:</strong> ${data.warning}</li>`;
        }

        html += `</ul>`;

        if (type === 'executable' && (file.name.endsWith('.aspx') || file.name.endsWith('.php'))) {
            html += `<div class="alert alert-danger mt-3">`;
            html += `<strong>🚨 Web Shell uploadé!</strong><br>`;
            html += `Le fichier est maintenant accessible et exécutable sur le serveur!`;
            html += `</div>`;
        }

        contentDiv.innerHTML = html;
    }

    function showFileUploadWarnings() {
        console.group('%c⚠️ File Upload Vulnerabilities Detected', 'color: red; font-size: 16px; font-weight: bold');
        console.error('❌ No file type validation');
        console.error('❌ Path traversal in filenames allowed');
        console.error('❌ Executable files in web-accessible directory');
        console.error('❌ MIME type validation bypass possible');
        console.error('❌ No file size limits (DoS)');
        console.error('❌ Double extension bypass');
        console.warn('💡 Prevention:');
        console.warn('   - Whitelist allowed extensions');
        console.warn('   - Validate file content, not just MIME');
        console.warn('   - Store files outside wwwroot');
        console.warn('   - Generate random filenames');
        console.warn('   - Implement file size limits');
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
        console.log(`[${timestamp}] File Upload ${actionType}: ${details}`);
    }

    function initializeTooltips() {
        // Ajouter des tooltips informatifs
        const tooltips = [
            { selector: 'input[type="file"]', title: 'Sélectionnez n\'importe quel fichier - aucune validation!' },
            { selector: '#customPath', title: 'Utilisez ../ pour sortir du dossier uploads' },
            { selector: '.btn-danger', title: 'Upload le fichier avec la vulnérabilité sélectionnée' }
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

    // Fonction globale pour le spoofing MIME
    window.spoofMimeType = function () {
        spoofedMimeType = 'image/jpeg';
        showNotification('warning', 'Content-Type sera forcé à: image/jpeg');
    };

    // Exposer certaines fonctions si nécessaire
    window.FileUpload = {
        uploadFile: uploadFile,
        showNotification: showNotification
    };

})();