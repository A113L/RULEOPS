(() => {
  const $ = id => document.getElementById(id);
  let setup = false;
  const showError = message => { $('error').textContent = message; $('error').classList.add('show'); };
  document.querySelectorAll('[data-reveal]').forEach(button => button.addEventListener('click', () => {
    const input = $(button.dataset.reveal); input.type = input.type === 'password' ? 'text' : 'password';
    button.textContent = input.type === 'password' ? 'SHOW' : 'HIDE';
  }));
  async function initialize() {
    try {
      const response = await fetch('/api/auth/me', { cache: 'no-store' });
      const data = await response.json();
      if (data.authenticated) { location.replace('/'); return; }
      setup = !!data.setup_required;
      if (setup) {
        $('title').textContent = 'Create your password.';
        $('intro').textContent = 'Set the administrator password for this RULEOPS installation. There is no default password.';
        $('password-label').textContent = 'Create application password';
        $('password').autocomplete = 'new-password';
        $('password').minLength = 12;
        $('password-hint').classList.remove('hidden');
        $('confirm-field').classList.remove('hidden');
        $('submit').innerHTML = 'Create password <span aria-hidden="true">→</span>';
        $('notice').textContent = 'Only a salted PBKDF2 password hash is stored. Complete this one-time setup from a trusted device before sharing the LAN address.';
      }
    } catch (error) { showError('Could not reach the RULEOPS server. Refresh the page or check the server process.'); }
  }
  $('auth-form').addEventListener('submit', async event => {
    event.preventDefault(); $('error').classList.remove('show');
    const password = $('password').value;
    if (setup && password.length < 12) { showError('Choose a password with at least 12 characters.'); return; }
    if (setup && password !== $('confirm-password').value) { showError('The passwords do not match.'); return; }
    $('submit').disabled = true;
    $('submit').textContent = setup ? 'Creating password…' : 'Signing in…';
    try {
      const response = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Authentication failed.');
      location.replace('/');
    } catch (error) {
      showError(error.message);
      $('submit').disabled = false;
      $('submit').innerHTML = setup ? 'Create password <span aria-hidden="true">→</span>' : 'Sign in <span aria-hidden="true">→</span>';
    }
  });
  initialize();
})();
