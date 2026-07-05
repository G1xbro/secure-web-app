const BASE_URL = 'http://127.0.0.1:5000';

// Handle login or registration requests
async function handleAuth(action) {
    const usernameInput = document.getElementById('username').value;
    const passwordInput = document.getElementById('password').value;

    if (!usernameInput || !passwordInput) {
        alert('Please fill out all credentials fields.');
        return;
    }

    const endpoint = action === 'login' ? '/api/auth/login' : '/api/auth/register';
    
    try {
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: usernameInput, password: passwordInput })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || 'Authentication action failed.');
            return;
        }

        if (action === 'login') {
            // Secure Session Control: Store the token in sessionStorage (in-memory per tab window lifecycle)
            sessionStorage.setItem('jwt_token', data.token);
            showDashboard(usernameInput);
            fetchNotes();
        } else {
            alert('Registration successful! You can now log in.');
        }
    } catch (err) {
        console.error('Network transaction error:', err);
    }
}

// Fetch user notes with authorization headers attached
async function fetchNotes() {
    const token = sessionStorage.getItem('jwt_token');
    
    try {
        const response = await fetch(`${BASE_URL}/api/notes`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401 || response.status === 403) {
            logout();
            return;
        }

        const data = await response.json();
        const container = document.getElementById('notes-container');
        container.innerHTML = '';

        if(data.notes.length === 0) {
            container.innerHTML = '<p style="color: #999;">No secure notes found.</p>';
        }

        data.notes.forEach(note => {
            const div = document.createElement('div');
            div.className = 'note';
            // Secure DOM Output: textContent natively escapes potential XSS injection strings!
            const titleElem = document.createElement('strong');
            titleElem.textContent = note.title;
            const contentElem = document.createElement('p');
            contentElem.textContent = note.content;
            
            div.appendChild(titleElem);
            div.appendChild(contentElem);
            container.appendChild(div);
        });
    } catch (err) {
        console.error('Error fetching notes:', err);
    }
}

// Create a new private note
async function submitNote() {
    const token = sessionStorage.getItem('jwt_token');
    const title = document.getElementById('note-title').value;
    const content = document.getElementById('note-content').value;

    if(!title || !content) return alert('Note fields cannot be blank');

    try {
        const response = await fetch(`${BASE_URL}/api/notes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ title, content })
        });

        if(response.ok) {
            document.getElementById('note-title').value = '';
            document.getElementById('note-content').value = '';
            fetchNotes();
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to securely post note.');
        }
    } catch (err) {
        console.error('Submission failure:', err);
    }
}

function showDashboard(username) {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('dashboard-section').classList.remove('hidden');
    document.getElementById('auth-status').textContent = `Authenticated as: ${username}`;
}

function logout() {
    sessionStorage.removeItem('jwt_token');
    document.getElementById('auth-section').classList.remove('hidden');
    document.getElementById('dashboard-section').classList.add('hidden');
    document.getElementById('auth-status').textContent = 'Status: Not Authenticated';
    document.getElementById('notes-container').innerHTML = '';
}

document.addEventListener('DOMContentLoaded', () => {
    // Securely bind authentication events
    document.getElementById('btn-login').addEventListener('click', () => handleAuth('login'));
    document.getElementById('btn-register').addEventListener('click', () => handleAuth('register'));

    // Securely bind note application dashboard events
    document.getElementById('btn-save').addEventListener('click', submitNote);
    document.getElementById('btn-refresh').addEventListener('click', fetchNotes);
    document.getElementById('btn-logout').addEventListener('click', logout);
});