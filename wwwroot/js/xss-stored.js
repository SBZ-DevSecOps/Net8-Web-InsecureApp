// Variables globales pour le contenu stocké
window.storedComments = [
    { "Id": 1, "Author": "Admin", "Content": "Bienvenue sur notre blog!", "CreatedAt": "2024-01-01", "IsApproved": true },
    { "Id": 2, "Author": "User1", "Content": "Excellent article, merci !", "CreatedAt": "2024-01-02", "IsApproved": true },
    { "Id": 3, "Author": "Hacker<script>alert('Stored-XSS')</script>", "Content": "<img src=x onerror=alert('Persistent XSS!')>", "CreatedAt": "2024-01-03", "IsApproved": false }
];

window.storedProfiles = [
    { "Id": 1, "Username": "admin", "DisplayName": "Administrator", "Bio": "Site administrator", "Website": "https://example.com" },
    { "Id": 2, "Username": "user1", "DisplayName": "John Doe", "Bio": "Regular user", "Website": "https://johndoe.com" }
];

// Fonctions de stockage XSS
function setPayload(payload) {
    var input = document.getElementById('payload');
    if (input) {
        input.value = payload;
        alert('Payload XSS Stored défini: ' + payload.substring(0, 50));
    }
}

function addStoredComment() {
    var author = document.getElementById('commentAuthor').value || 'Anonyme';
    var content = document.getElementById('commentContent').value || document.getElementById('commentContent').placeholder;
    var result = document.getElementById('commentResult');

    if (result) {
        // VULNÉRABLE : Stockage et affichage direct
        var newComment = {
            Id: window.storedComments.length + 1,
            Author: author,
            Content: content,
            CreatedAt: new Date().toISOString(),
            IsApproved: true
        };

        window.storedComments.push(newComment);

        // VULNÉRABLE : innerHTML avec contenu non échappé
        result.innerHTML = '<strong>Commentaire stocké :</strong><br>' +
            '<div class="border p-2 mt-1">' +
            '<strong>' + newComment.Author + '</strong><br>' +
            newComment.Content +
            '</div>';

        // Recharger l'affichage des commentaires
        loadStoredComments();

        alert('Commentaire XSS stocké de manière permanente !');
    }
}

function updateStoredProfile() {
    var username = document.getElementById('profileUsername').value || 'user';
    var bio = document.getElementById('profileBio').value || document.getElementById('profileBio').placeholder;
    var website = document.getElementById('profileWebsite').value || document.getElementById('profileWebsite').placeholder;
    var result = document.getElementById('profileResult');

    if (result) {
        // VULNÉRABLE : Stockage de profil
        var newProfile = {
            Id: window.storedProfiles.length + 1,
            Username: username,
            DisplayName: username,
            Bio: bio,
            Website: website
        };

        window.storedProfiles.push(newProfile);

        // VULNÉRABLE : Affichage avec innerHTML
        result.innerHTML = '<strong>Profil stocké :</strong><br>' +
            '<div class="border p-2 mt-1">' +
            '<h6>' + newProfile.DisplayName + '</h6>' +
            '<p>Bio: ' + newProfile.Bio + '</p>' +
            '<p>Site: <a href="' + newProfile.Website + '">' + newProfile.Website + '</a></p>' +
            '</div>';

        // Recharger l'affichage des profils
        loadStoredProfiles();

        alert('Profil XSS stocké de manière permanente !');
    }
}

function createStoredPost() {
    var title = document.getElementById('forumTitle').value || document.getElementById('forumTitle').placeholder;
    var content = document.getElementById('forumContent').value || document.getElementById('forumContent').placeholder;
    var result = document.getElementById('forumResult');

    if (result) {
        // VULNÉRABLE : Stockage de post forum
        result.innerHTML = '<strong>Post forum stocké :</strong><br>' +
            '<div class="border p-2 mt-1">' +
            '<h6>' + title + '</h6>' +
            '<div>' + content + '</div>' +
            '</div>';

        alert('Post forum XSS stocké de manière permanente !');
    }
}

function addGuestEntry() {
    var name = document.getElementById('guestName').value || 'Visiteur';
    var message = document.getElementById('guestMessage').value || document.getElementById('guestMessage').placeholder;
    var result = document.getElementById('guestResult');

    if (result) {
        // VULNÉRABLE : Stockage livre d'or
        result.innerHTML = '<strong>Message livre d\'or stocké :</strong><br>' +
            '<div class="border p-2 mt-1">' +
            '<strong>' + name + '</strong><br>' +
            message +
            '</div>';

        alert('Message livre d\'or XSS stocké de manière permanente !');
    }
}

function loadStoredComments() {
    var container = document.getElementById('storedComments');
    if (container && window.storedComments) {
        var html = '';
        window.storedComments.forEach(function (comment) {
            // VULNÉRABLE : Affichage direct sans échappement
            html += '<div class="stored-comment border-bottom pb-2 mb-2">';
            html += '<strong>' + comment.Author + '</strong>';
            html += '<small class="text-muted ms-2">' + comment.CreatedAt + '</small>';
            html += '<div>' + comment.Content + '</div>';
            html += '</div>';
        });
        // VULNÉRABLE : innerHTML avec contenu stocké
        container.innerHTML = html;
    }
}

function loadStoredProfiles() {
    var container = document.getElementById('storedProfiles');
    if (container && window.storedProfiles) {
        var html = '';
        window.storedProfiles.forEach(function (profile) {
            // VULNÉRABLE : Affichage direct des profils
            html += '<div class="stored-profile border-bottom pb-2 mb-2">';
            html += '<h6>' + profile.DisplayName + ' (@' + profile.Username + ')</h6>';
            html += '<p>Bio: ' + profile.Bio + '</p>';
            if (profile.Website) {
                html += '<p>Site: <a href="' + profile.Website + '" target="_blank">' + profile.Website + '</a></p>';
            }
            html += '</div>';
        });
        // VULNÉRABLE : innerHTML avec profils stockés
        container.innerHTML = html;
    }
}

// Initialisation
document.addEventListener('DOMContentLoaded', function () {
    loadStoredComments();
    loadStoredProfiles();
    console.log('Module XSS Stored chargé - VULNÉRABILITÉS PERMANENTES ACTIVES');
});