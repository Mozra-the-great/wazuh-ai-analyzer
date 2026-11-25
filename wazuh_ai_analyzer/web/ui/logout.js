// Logging out is a POST with the CSRF token (a GET link must not log anybody out).
'use strict';

const button = document.getElementById('logout');
const errorBox = document.getElementById('error');

async function csrfToken() {
  const response = await fetch('/api/session', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  const session = await response.json().catch(() => ({}));
  if (!session.authenticated) {
    location.replace('/login');
    return '';
  }
  return session.csrf_token;
}

button.addEventListener('click', async () => {
  button.disabled = true;
  try {
    const token = await csrfToken();
    if (!token) return;
    const response = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: '{}',
    });
    if (!response.ok) throw new Error(String(response.status));
    location.assign('/login');
  } catch (error) {
    errorBox.textContent = 'Abmelden fehlgeschlagen.';
    errorBox.hidden = false;
    button.disabled = false;
  }
});
