// Login page of the test fixture UI. Talks JSON to /api/session and /api/login.
'use strict';

const form = document.getElementById('login-form');
const errorBox = document.getElementById('error');
const submit = document.getElementById('submit');
let csrf = '';

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

async function loadSession() {
  const response = await fetch('/api/session', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  if (response.status === 503) {
    showError('Kein Passwort konfiguriert. Bitte DASHBOARD_PASSWORD_HASH in der env-Datei setzen.');
    submit.disabled = true;
    return;
  }
  const session = await response.json();
  if (session.authenticated) {
    location.replace('/');
    return;
  }
  csrf = session.csrf_token;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  submit.disabled = true;
  try {
    if (!csrf) await loadSession();
    const next = new URLSearchParams(location.search).get('next') || '/';
    const response = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, Accept: 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        next,
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (response.ok) {
      // `next` was validated by the server: a local path only.
      location.assign(body.next || '/');
      return;
    }
    if (response.status === 429) {
      showError(`Zu viele Fehlversuche. Bitte ${Number(body.retry_after) || 60}s warten.`);
    } else if (response.status === 401) {
      showError(`Falscher Benutzername oder Passwort. (${Number(body.remaining_attempts) || 0} Versuch(e) verbleibend)`);
    } else if (response.status === 403) {
      csrf = '';
      await loadSession();
      showError('Die Sitzung der Anmeldeseite ist abgelaufen. Bitte erneut versuchen.');
    } else {
      showError('Anmeldung nicht möglich.');
    }
  } catch (error) {
    showError('Backend nicht erreichbar.');
  } finally {
    submit.disabled = false;
  }
});

loadSession().catch(() => showError('Backend nicht erreichbar.'));
