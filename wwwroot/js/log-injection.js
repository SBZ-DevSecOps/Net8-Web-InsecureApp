// wwwroot/js/log-injection.js

(function () {
    'use strict';

    // --- Coloration ANSI dans la zone logs ---
    function highlightLogOutput() {
        const pre = document.getElementById('logs-pre');
        if (!pre) return;
        let html = pre.textContent
            .replace(/\u001b\[31m/g, '<span class="ansi-red">')
            .replace(/\u001b\[32m/g, '<span class="ansi-green">')
            .replace(/\u001b\[33m/g, '<span class="ansi-yellow">')
            .replace(/\u001b\[34m/g, '<span class="ansi-blue">')
            .replace(/\u001b\[1m/g, '<span class="ansi-bold">')
            .replace(/\u001b\[2J/g, '<span class="ansi-clear">')
            .replace(/\u001b\[H/g, '')
            .replace(/\u001b\[0m/g, '</span>');
        pre.innerHTML = html;
    }

    // --- Export des résultats logs + contexte au format JSON ---
    window.exportLogResults = function () {
        if (!window.logInjectionData?.results?.length) {
            alert('Aucun résultat à exporter');
            return;
        }
        const report = {
            timestamp: new Date().toISOString(),
            attackType: window.logInjectionData.attackType,
            payload: window.logInjectionData.payload,
            logs: window.logInjectionData.results,
            indicators: window.logInjectionData.errorExplanations || {}
        };
        const json = JSON.stringify(report, null, 2);
        const blob = new Blob([json], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `log_injection_report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    // --- Mise à jour du payload lors du changement d'attaque (utile si tu veux séparer la logique) ---
    window.insertLogPayloadExample = function (key) {
        if (window.logAttackInfos && window.logAttackInfos[key]) {
            const payload = window.logAttackInfos[key].PayloadExample;
            const input = document.getElementById('payload');
            if (input) {
                input.value = payload;
                input.dispatchEvent(new Event("input"));
            }
        }
    };

    // --- Coloration à chaque affichage de logs ---
    document.addEventListener('DOMContentLoaded', function () {
        highlightLogOutput();
    });

    // Si logs mis à jour dynamiquement, relancer la coloration
    window.addEventListener('logResultsUpdated', highlightLogOutput);

    window.clearLogFile = function () {
        if (confirm("Confirmer la purge visuelle des logs ?")) {
            fetch('/InjectionLog/ClearLogs', { method: 'POST' })
                .then(res => {
                    if (res.ok) {
                        // Purge uniquement côté UI (visuel)
                        var pre = document.getElementById('logs-pre');
                        if (pre) pre.textContent = '';
                    }
                    else {
                        alert("Erreur lors de la demande de purge.");
                    }
                });
        }
    };

})();
