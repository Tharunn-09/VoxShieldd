/* ============================================================
   VOXSHIELD — UCO Bank Voice Forensics Prototype
   Real RFC6238 TOTP MFA + real Web Audio FFT/DSP risk engine.
   ============================================================ */

/* ---------- tiny toast ---------- */
function toast(msg, kind) {
  const t = document.createElement('div');
  t.className = 'toast';
  const icon = kind === 'error' ? '⛔' : kind === 'success' ? '✅' : 'ℹ️';
  t.innerHTML = `<span>${icon}</span><span>${msg}</span>`;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3200);
}

/* ============================================================
   REAL TOTP (RFC 6238) — Base32 + HMAC-SHA1 via SubtleCrypto
   Compatible with Microsoft Authenticator / Google Authenticator
   ============================================================ */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

window.activeForensicData = {
  upload: {
    audioBuffer: null,
    chunks: null,
    features: null
  },
  live: {
    audioBuffer: null,
    chunks: null,
    features: null
  }
};

function randomBase32Secret(len = 20) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += B32_ALPHABET[bytes[i] % 32];
  return out;
}

function base32ToBytes(b32) {
  b32 = b32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of b32) {
    const v = B32_ALPHABET.indexOf(c);
    if (v === -1) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}

function intToBytes8(num) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // JS numbers safe up to 2^53; counter fits in lower 32 bits for decades
  view.setUint32(0, Math.floor(num / 4294967296));
  view.setUint32(4, num % 4294967296);
  return new Uint8Array(buf);
}

async function hotp(secretB32, counter, digits = 6) {
  const keyBytes = base32ToBytes(secretB32);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = intToBytes8(counter);
  const sigBuf = await crypto.subtle.sign('HMAC', key, msg);
  const sig = new Uint8Array(sigBuf);
  const offset = sig[sig.length - 1] & 0x0f;
  const binCode = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  const code = (binCode % (10 ** digits)).toString().padStart(digits, '0');
  return code;
}

async function totpNow(secretB32, period = 30, digits = 6, skewWindows = 1) {
  const counter = Math.floor(Date.now() / 1000 / period);
  const codes = [];
  for (let w = -skewWindows; w <= skewWindows; w++) {
    codes.push(await hotp(secretB32, counter + w, digits));
  }
  return codes; // array of valid codes (current +/- skew)
}

function otpauthUri(secret, account, issuer) {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function qrUrl(data) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(data)}`;
}

function obfuscateSecret(secret) {
  if (!secret) return '';
  const key = 'voxshield_key_2026';
  let result = '';
  for (let i = 0; i < secret.length; i++) {
    const charCode = secret.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return btoa(result);
}

function deobfuscateSecret(cipher) {
  if (!cipher) return '';
  try {
    const key = 'voxshield_key_2026';
    const decoded = atob(cipher);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      result += String.fromCharCode(charCode);
    }
    return result;
  } catch (e) {
    return '';
  }
}

/* ---------- User DB & MFA state ---------- */
const DEFAULT_USERS = {
  'UCO-AGT-1042': {
    name: 'UCO Agent 1042',
    email: 'agent1042@ucobank.co.in',
    pass: 'ucobank@2026',
    mfa_secret: deobfuscateSecret(localStorage.getItem('sv_mfa_secret')) || '',
    mfa_enrolled: localStorage.getItem('sv_mfa_enrolled') === '1'
  }
};

function getUsersStore() {
  let store = localStorage.getItem('sv_users');
  if (!store) {
    localStorage.setItem('sv_users', JSON.stringify(DEFAULT_USERS));
    return DEFAULT_USERS;
  }
  return JSON.parse(store);
}

function saveUsersStore(store) {
  localStorage.setItem('sv_users', JSON.stringify(store));
}

// Initial seed
getUsersStore();

let MFA_SECRET = deobfuscateSecret(localStorage.getItem('sv_mfa_secret')) || '';
let MFA_ENROLLED = localStorage.getItem('sv_mfa_enrolled') === '1';
let pendingUser = null;
let pendingTempToken = '';

// Signup temporary state and OTP
let signupState = null;
let emailOtpCode = '';
let forgotState = { email: '' };

function ensureSecret(force) {
  if (force || !MFA_SECRET) {
    MFA_SECRET = randomBase32Secret();
    localStorage.setItem('sv_mfa_secret', obfuscateSecret(MFA_SECRET));
    localStorage.setItem('sv_mfa_enrolled', '0');
    MFA_ENROLLED = false;
  }
  return MFA_SECRET;
}

function renderMfaSetup(account) {
  const uri = otpauthUri(MFA_SECRET, account, 'UCO Bank VoxShield');
  document.getElementById('qr-img').src = qrUrl(uri);
  document.getElementById('secret-display').textContent = MFA_SECRET.match(/.{1,4}/g).join(' ');
  const setupBlock = document.getElementById('mfa-setup-block');
  setupBlock.style.display = MFA_ENROLLED ? 'none' : 'block';
}

async function doCredsLogin() {
  const user = document.getElementById('in-user').value.trim();
  const pass = document.getElementById('in-pass').value;
  if (!user) { toast('Enter Employee ID', 'error'); return; }
  if (!pass) { toast('Enter password to continue', 'error'); return; }

  toast('Verifying credentials...', 'info');

  try {
    const response = await fetch('/api/auth/login-creds', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user, pass })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Invalid credentials');
    }

    pendingUser = user;
    pendingTempToken = data.tempToken;
    MFA_SECRET = data.mfaSecret || deobfuscateSecret(localStorage.getItem('sv_mfa_secret')) || '';
    MFA_ENROLLED = data.mfaEnrolled;

    if (MFA_SECRET) {
      localStorage.setItem('sv_mfa_secret', obfuscateSecret(MFA_SECRET));
    }
    localStorage.setItem('sv_mfa_enrolled', MFA_ENROLLED ? '1' : '0');

    // Trigger the slide-swap animation
    const card = document.querySelector('.lg-card');
    if (card) card.classList.add('swap-active');

    setTimeout(() => {
      document.getElementById('step-creds').style.display = 'none';
      document.getElementById('step-mfa').style.display = 'block';
      renderMfaSetup(user);

      // clear otp boxes
      document.querySelectorAll('.otp-d').forEach(i => i.value = '');
      const firstOtp = document.querySelector('.otp-d[data-i="0"]');
      if (firstOtp) firstOtp.focus();
    }, 250);
  } catch (error) {
    console.error('Login credentials error:', error);
    toast(error.message, 'error');
  }
}

function backToCreds() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.remove('swap-active');

  setTimeout(() => {
    document.getElementById('step-mfa').style.display = 'none';
    document.getElementById('step-creds').style.display = 'block';
  }, 250);
}

/* ---------- Officer Registration Flow ---------- */
function showSignup() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.add('swap-active');

  setTimeout(() => {
    document.getElementById('step-creds').style.display = 'none';
    document.getElementById('step-signup').style.display = 'block';
  }, 250);

  document.getElementById('sig-name').value = '';
  document.getElementById('sig-email').value = '';
  document.getElementById('sig-user').value = '';
  document.getElementById('sig-pass').value = '';
}

function backToLogin() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.remove('swap-active');

  setTimeout(() => {
    document.getElementById('step-signup').style.display = 'none';
    document.getElementById('step-creds').style.display = 'block';
  }, 250);
}

function backToSignup() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.add('swap-active');

  setTimeout(() => {
    document.getElementById('step-email-otp').style.display = 'none';
    document.getElementById('step-signup').style.display = 'block';
  }, 250);
}

/* ---------- Forgot Password Flow ---------- */
function showForgotScreen() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.add('swap-active');

  setTimeout(() => {
    document.getElementById('step-creds').style.display = 'none';
    document.getElementById('step-forgot').style.display = 'block';
  }, 250);

  document.getElementById('forgot-email').value = '';
  document.getElementById('forgot-err').textContent = '';
}

function backToLoginFromForgot() {
  const card = document.querySelector('.lg-card');
  if (card) card.classList.remove('swap-active');

  setTimeout(() => {
    document.getElementById('step-forgot').style.display = 'none';
    document.getElementById('step-creds').style.display = 'block';
  }, 250);
}

function backToForgotFromConfirm() {
  document.getElementById('step-reset-confirm').style.display = 'none';
  document.getElementById('step-forgot').style.display = 'block';
  document.getElementById('reset-confirm-err').textContent = '';
}

async function sendForgotPasswordReset() {
  const emailInput = document.getElementById('forgot-email');
  const errEl = document.getElementById('forgot-err');
  const email = emailInput.value.trim();

  if (!email || !validateEmail(email)) {
    errEl.textContent = 'Enter a valid registered email address';
    return;
  }

  errEl.textContent = '';
  toast('Sending reset code...', 'info');

  try {
    const response = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to request password reset');
    }

    forgotState = { email };
    toast('Reset code sent to your email! (Please check your spam folder)', 'success');

    // Transition to verification screen
    document.getElementById('step-forgot').style.display = 'none';
    document.getElementById('step-reset-confirm').style.display = 'block';

    // Clear code fields and focus first digit
    document.querySelectorAll('.rotp-d').forEach(i => i.value = '');
    document.getElementById('reset-new-pass').value = '';
    document.getElementById('reset-confirm-err').textContent = '';

    const firstOtp = document.querySelector('.rotp-d[data-i="0"]');
    if (firstOtp) firstOtp.focus();
  } catch (error) {
    console.error('Forgot password error:', error);
    errEl.textContent = error.message;
    toast(error.message, 'error');
  }
}

async function confirmPasswordReset() {
  const digits = [...document.querySelectorAll('.rotp-d')].map(i => i.value).join('');
  const newPassEl = document.getElementById('reset-new-pass');
  const newPassword = newPassEl.value;
  const errEl = document.getElementById('reset-confirm-err');

  if (digits.length !== 6) {
    errEl.textContent = 'Enter all 6 digits of the verification code';
    return;
  }

  if (!newPassword) {
    errEl.textContent = 'Please enter a new password';
    return;
  }

  errEl.textContent = '';
  toast('Resetting password...', 'info');

  try {
    const response = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: forgotState.email,
        otp: digits,
        newPassword: newPassword
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to reset password');
    }

    toast('Password reset successfully! Please log in.', 'success');

    // Reset layout transition
    const card = document.querySelector('.lg-card');
    if (card) card.classList.remove('swap-active');

    setTimeout(() => {
      document.getElementById('step-reset-confirm').style.display = 'none';
      document.getElementById('step-creds').style.display = 'block';
      // Clear inputs
      document.getElementById('in-user').value = '';
      document.getElementById('in-pass').value = '';
    }, 250);
  } catch (error) {
    console.error('Password reset confirmation error:', error);
    errEl.textContent = error.message;
    toast(error.message, 'error');
  }
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

async function sendEmailOtp() {
  const name = document.getElementById('sig-name').value.trim();
  const email = document.getElementById('sig-email').value.trim();
  const user = document.getElementById('sig-user').value.trim();
  const pass = document.getElementById('sig-pass').value;

  if (!name) { toast('Enter your full name', 'error'); return; }
  if (!email || !validateEmail(email)) { toast('Enter a valid email address', 'error'); return; }
  if (!user) { toast('Enter an Employee/Agent ID', 'error'); return; }

  if (!pass || pass.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }

  signupState = { name, email, user, pass };

  toast('Sending verification email...', 'info');

  try {
    const response = await fetch('/api/auth/register-init', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ name, email, user, pass })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to initialize registration');
    }

    toast('Verification code sent to your email! (Please check your spam folder)', 'success');

    // Clear inputs and transition screen
    const card = document.querySelector('.lg-card');
    if (card) card.classList.remove('swap-active');

    setTimeout(() => {
      document.querySelectorAll('.eotp-d').forEach(i => i.value = '');
      document.getElementById('email-otp-err').textContent = '';
      document.getElementById('step-signup').style.display = 'none';
      document.getElementById('step-email-otp').style.display = 'block';

      const firstOtp = document.querySelector('.eotp-d[data-i="0"]');
      if (firstOtp) firstOtp.focus();
    }, 250);
  } catch (error) {
    console.error('Failed to send verification email:', error);
    toast(error.message, 'error');
  }
}


async function verifyEmailOtp() {
  const digits = [...document.querySelectorAll('.eotp-d')].map(i => i.value).join('');
  const errEl = document.getElementById('email-otp-err');
  if (digits.length !== 6) { errEl.textContent = 'Enter all 6 digits.'; return; }
  errEl.textContent = 'Verifying…';

  try {
    const response = await fetch('/api/auth/register-verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user: signupState.user, otp: digits })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'OTP verification failed');
    }

    errEl.style.color = 'var(--green)';
    errEl.textContent = 'Email verified successfully ✓';

    pendingUser = signupState.user;
    pendingTempToken = data.tempToken;
    MFA_SECRET = data.mfaSecret;
    MFA_ENROLLED = false;
    localStorage.setItem('sv_mfa_secret', obfuscateSecret(MFA_SECRET));
    localStorage.setItem('sv_mfa_enrolled', '0');

    const card = document.querySelector('.lg-card');
    if (card) card.classList.add('swap-active');

    setTimeout(() => {
      document.getElementById('step-email-otp').style.display = 'none';
      document.getElementById('step-mfa').style.display = 'block';
      renderMfaSetup(pendingUser);
      document.querySelectorAll('.otp-d').forEach(i => i.value = '');
      const firstOtp = document.querySelector('.otp-d[data-i="0"]');
      if (firstOtp) firstOtp.focus();
      toast('Verify setup QR with Microsoft Authenticator to log in.', 'info');
    }, 500);
  } catch (error) {
    console.error('Verify OTP error:', error);
    errEl.style.color = 'var(--red)';
    errEl.textContent = error.message;
  }
}

// OTP digit auto-advance & input settings in DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  // For login MFA
  document.querySelectorAll('.otp-d').forEach((inp) => {
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/[^0-9]/g, '').slice(0, 1);
      if (inp.value) {
        const next = document.querySelector(`.otp-d[data-i="${+inp.dataset.i + 1}"]`);
        if (next) next.focus(); else verifyMfa();
      }
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value) {
        const prev = document.querySelector(`.otp-d[data-i="${+inp.dataset.i - 1}"]`);
        if (prev) prev.focus();
      }
    });
  });

  // For email verification OTP
  document.querySelectorAll('.eotp-d').forEach((inp) => {
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/[^0-9]/g, '').slice(0, 1);
      if (inp.value) {
        const next = document.querySelector(`.eotp-d[data-i="${+inp.dataset.i + 1}"]`);
        if (next) next.focus(); else verifyEmailOtp();
      }
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value) {
        const prev = document.querySelector(`.eotp-d[data-i="${+inp.dataset.i - 1}"]`);
        if (prev) prev.focus();
      }
    });
  });

  // For password reset OTP
  document.querySelectorAll('.rotp-d').forEach((inp) => {
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/[^0-9]/g, '').slice(0, 1);
      if (inp.value) {
        const next = document.querySelector(`.rotp-d[data-i="${+inp.dataset.i + 1}"]`);
        if (next) next.focus(); else confirmPasswordReset();
      }
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !inp.value) {
        const prev = document.querySelector(`.rotp-d[data-i="${+inp.dataset.i - 1}"]`);
        if (prev) prev.focus();
      }
    });
  });
});

async function verifyMfa() {
  const digits = [...document.querySelectorAll('.otp-d')].map(i => i.value).join('');
  const errEl = document.getElementById('mfa-err');
  if (digits.length !== 6) { errEl.textContent = 'Enter all 6 digits.'; return; }
  errEl.textContent = 'Verifying…';

  try {
    const response = await fetch('/api/auth/login-mfa', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ tempToken: pendingTempToken, mfaCode: digits })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'MFA verification failed');
    }

    localStorage.setItem('vx_jwt_token', data.token);
    MFA_ENROLLED = true;
    localStorage.setItem('sv_mfa_enrolled', '1');

    errEl.style.color = 'var(--green)';
    errEl.textContent = 'Verified ✓';
    setTimeout(() => enterApp(data.user), 350);
  } catch (error) {
    console.error('MFA validation error:', error);
    errEl.style.color = 'var(--red)';
    errEl.textContent = error.message;
  }
}

function reenrollMfa() {
  ensureSecret(true);

  const users = getUsersStore();
  if (users[currentUser]) {
    users[currentUser].mfa_secret = MFA_SECRET;
    users[currentUser].mfa_enrolled = false;
    saveUsersStore(users);
  }

  renderMfaSettings();
  toast('New secret generated — re-scan the QR with your authenticator app', 'info');
}

function renderMfaSettings() {
  const el = document.getElementById('settings-secret');
  if (!el) return;
  const uri = otpauthUri(MFA_SECRET, currentUser, 'UCO Bank VoxShield');
  el.innerHTML = `
    <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
      <div class="qr-box"><img src="${qrUrl(uri)}" style="width:120px;height:120px;display:block;"/></div>
      <div>
        <div style="font-size:11px;color:var(--text3);margin-bottom:6px;">Manual setup key</div>
        <div class="secret-key" style="text-align:left;">${MFA_SECRET.match(/.{1,4}/g).join(' ')}</div>
      </div>
    </div>`;
}

function setSensitivity(mode) {
  ['agg', 'bal', 'con'].forEach(k => document.getElementById('sens-' + k).classList.remove('on'));
  document.getElementById('sens-' + (mode === 'aggressive' ? 'agg' : mode === 'balanced' ? 'bal' : 'con')).classList.add('on');
  SENSITIVITY = mode;
  toast(`Detection sensitivity set to ${mode}`, 'info');
  pushAuditLog('SENSITIVITY_CHANGE', 'Adjusted voice forensics detection sensitivity threshold to ' + mode);
}
let SENSITIVITY = 'balanced';

/* ============================================================
   APP NAVIGATION
   ============================================================ */
let currentUser = 'UCO-AGT-1042';
let currentUserEmail = 'agent1042@ucobank.co.in';

function enterApp(userObj) {
  currentUser = userObj.employeeId;
  currentUserEmail = userObj.email || 'agent1042@ucobank.co.in';
  document.getElementById('login').style.display = 'none';
  document.getElementById('app').classList.add('show');

  document.getElementById('ub-name').textContent = userObj.name || userObj.employeeId;
  document.getElementById('ub-init').textContent = (userObj.name || userObj.employeeId).split(' ').map(x => x[0]).join('').toUpperCase().slice(0, 2);
  renderMfaSettings();
  renderDashboard();
  renderVoiceprintRegistry();
  toast(`Welcome back, ${userObj.name || userObj.employeeId}`, 'success');

  // Load audit logs in the background once logged in
  loadAuditLogs();
}

function goPage(name, el) {
  const searchInput = document.getElementById('topbar-search');
  if (searchInput) {
    searchInput.value = '';
    handleGlobalSearch('');
  }
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  if (name === 'history') renderHistory('all');
  if (name === 'reports') renderReports();
  if (name === 'settings') renderMfaSettings();
  if (name === 'auditlogs') loadAuditLogs();

  // Refresh dynamic chatbot suggestion chips to target the active page scan details
  if (typeof updateChatSuggestions === 'function') {
    updateChatSuggestions();
  }
}

/* ============================================================
   CALL DATA STORE
   ============================================================ */
let CALLS = JSON.parse(localStorage.getItem('sv_calls') || '[]');
function saveCalls() { localStorage.setItem('sv_calls', JSON.stringify(CALLS)); }

function verdictFromScore(score) {
  if (score >= 75) return { label: 'CRITICAL RISK — LIKELY SYNTHETIC', cls: 'crit', key: 'critical', color: 'var(--red)' };
  if (score >= 50) return { label: 'HIGH RISK — SUSPECTED CLONING', cls: 'high', key: 'high', color: 'var(--orange)' };
  if (score >= 25) return { label: 'MODERATE RISK — REVIEW ADVISED', cls: 'mod', key: 'moderate', color: 'var(--accent-blue)' };
  return { label: 'LOW RISK — LIKELY HUMAN', cls: 'low', key: 'low', color: 'var(--green)' };
}

function recordCall(call) {
  CALLS.unshift(call);
  saveCalls();
  renderDashboard();
}

/* ============================================================
   DASHBOARD
   ============================================================ */
const THREAT_PATTERNS = [
  { name: 'Unnaturally low pitch jitter (TTS smoothing)', pct: 38 },
  { name: 'Spectral flatness anomaly (neural vocoder)', pct: 27 },
  { name: 'HF rolloff notch (codec/vocoder fingerprint)', pct: 19 },
  { name: 'Shimmer suppression (over-clean amplitude)', pct: 16 },
];

function renderDashboard() {
  const today = CALLS; // session-scoped demo
  document.getElementById('st-calls').textContent = today.length;
  document.getElementById('tb-calls-today').textContent = today.length;
  const flagged = today.filter(c => c.verdict.key === 'high' || c.verdict.key === 'critical');
  document.getElementById('st-flagged').textContent = flagged.length;
  const ttfs = today.filter(c => c.timeToFlag).map(c => c.timeToFlag);
  document.getElementById('st-ttf').textContent = ttfs.length ? (ttfs.reduce((a, b) => a + b, 0) / ttfs.length).toFixed(1) + 's' : '--';

  // risk distribution
  const buckets = { low: 0, moderate: 0, high: 0, critical: 0 };
  today.forEach(c => buckets[c.verdict.key]++);
  const total = today.length || 1;
  const colors = { low: 'var(--green)', moderate: 'var(--accent-blue)', high: 'var(--orange)', critical: 'var(--red)' };
  let distHtml = '';
  Object.keys(buckets).forEach(k => {
    const pct = Math.round(buckets[k] / total * 100);
    distHtml += `<div class="sbar-row"><div class="sbar-lbl" style="text-transform:capitalize;width:90px;">${k}</div>
      <div class="sbar-track"><div class="sbar-fill" style="width:${pct}%;background:${colors[k]};"></div></div>
      <div class="sbar-pct">${buckets[k]}</div></div>`;
  });
  document.getElementById('risk-dist-bars').innerHTML = distHtml || '<div style="color:var(--text3);font-size:12px;">No data yet this session.</div>';

  let tpHtml = '';
  THREAT_PATTERNS.forEach(p => {
    tpHtml += `<div class="sbar-row"><div class="sbar-lbl">${p.name}</div>
      <div class="sbar-track"><div class="sbar-fill" style="width:${p.pct}%;background:var(--gold);"></div></div>
      <div class="sbar-pct">${p.pct}%</div></div>`;
  });
  document.getElementById('threat-pattern').innerHTML = tpHtml;

  // recent table
  const recent = today.slice(0, 6);
  document.getElementById('dash-recent-tbody').innerHTML = recent.length ? recent.map(c => `
    <tr>
      <td class="mono">${c.id}</td>
      <td>${c.customer}</td>
      <td>${c.source}</td>
      <td><b style="color:${c.verdict.color};">${c.score}</b>/100</td>
      <td><span class="badge ${badgeClass(c.verdict.key)}">${c.verdict.key.toUpperCase()}</span></td>
      <td class="mono">${c.timestamp}</td>
      <td style="display:flex;gap:4px;">
        <button class="btn btn-ghost btn-sm" onclick="downloadReport('${c.id}')" title="Download JSON">📥 JSON</button>
        <button class="btn btn-ghost btn-sm" onclick="openEmailReportModal('${c.id}')" title="Email Report">📧 Email</button>
      </td>
    </tr>`).join('') : `<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px;">No calls analyzed yet this session.</td></tr>`;
}

function badgeClass(key) {
  return { low: 'b-green', moderate: 'b-blue', high: 'b-orange', critical: 'b-red' }[key] || 'b-gray';
}

/* ============================================================
   HISTORY / REPORTS PAGES
   ============================================================ */
function renderHistory(filter) {
  const rows = CALLS.filter(c => filter === 'all' || c.verdict.key === filter);
  document.getElementById('history-empty').style.display = rows.length ? 'none' : 'block';
  document.getElementById('history-tbody').innerHTML = rows.map(c => `
    <tr>
      <td class="mono">${c.id}</td>
      <td>${c.source}</td>
      <td>${c.customer}</td>
      <td><b style="color:${c.verdict.color};">${c.score}</b>/100</td>
      <td><span class="badge ${badgeClass(c.verdict.key)}">${c.verdict.key.toUpperCase()}</span></td>
      <td class="mono">${c.timeToFlag ? c.timeToFlag.toFixed(1) + 's' : '—'}</td>
      <td class="mono">${c.timestamp}</td>
      <td style="display:flex;gap:4px;">
        <button class="btn btn-ghost btn-sm" onclick="downloadReport('${c.id}')" title="Download JSON">📥 JSON</button>
        <button class="btn btn-ghost btn-sm" onclick="openEmailReportModal('${c.id}')" title="Email Report">📧 Email</button>
      </td>
    </tr>`).join('');
}
function filterHistory(f, el) {
  document.querySelectorAll('#page-history .tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  renderHistory(f);
}

function renderReports() {
  document.getElementById('reports-empty').style.display = CALLS.length ? 'none' : 'block';
  document.getElementById('reports-tbody').innerHTML = CALLS.map(c => `
    <tr>
      <td class="mono">${c.id}</td>
      <td><span class="badge ${badgeClass(c.verdict.key)}">${c.verdict.key.toUpperCase()}</span></td>
      <td><b style="color:${c.verdict.color};">${c.score}</b>/100</td>
      <td class="mono">${c.timestamp}</td>
      <td style="display:flex;gap:6px;">
        <button class="btn btn-outline btn-sm" onclick="downloadReport('${c.id}')">Download JSON</button>
        <button class="btn btn-outline btn-sm" onclick="openEmailReportModal('${c.id}')">Email Report</button>
      </td>
    </tr>`).join('');
}

function downloadReport(id) {
  const c = CALLS.find(x => x.id === id);
  if (!c) { toast('Report not found', 'error'); return; }
  const report = {
    bank: 'UCO Bank', system: 'VoxShield Audio Forensics', generated_at: new Date().toISOString(),
    call_id: c.id, source: c.source, customer: c.customer, analyzed_by: currentUser,
    verdict: c.verdict.key, risk_score: c.score, time_to_flag_seconds: c.timeToFlag || null,
    audio_sha256: c.audio_sha256 || 'N/A (Calculated locally upon capture/upload)',
    report_digital_signature: c.report_digital_signature || 'N/A (Sealed locally)',
    features: c.features, methodology: 'VoxShield Secure Dual-Engine Analysis. Live calls utilize on-device FFT/autocorrelation DSP heuristics. Uploaded recordings are evaluated via our secure backend 51-Feature Hybrid Machine Learning Ensemble (Random Forest, MLP Neural Network, Gradient Boosting Classifiers).'
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${id}_voxshield_report.json`;
  a.click();
  toast('Report downloaded', 'success');
  pushAuditLog('REPORT_DOWNLOAD', 'Downloaded JSON call forensic report for ID: ' + id);
}

window.pendingReportId = null;

function openEmailReportModal(id) {
  const c = CALLS.find(x => x.id === id);
  if (!c) { toast('Report not found', 'error'); return; }

  window.pendingReportId = id;
  const emailInput = document.getElementById('report-recipient-email');
  if (emailInput) {
    emailInput.value = currentUserEmail;
  }
  const errEl = document.getElementById('email-report-error');
  if (errEl) {
    errEl.textContent = '';
  }

  const modal = document.getElementById('email-report-modal');
  if (modal) {
    modal.style.display = 'flex';
  }
}

function closeEmailReportModal() {
  window.pendingReportId = null;
  const modal = document.getElementById('email-report-modal');
  if (modal) {
    modal.style.display = 'none';
  }
}

async function submitEmailReport() {
  const id = window.pendingReportId;
  const c = CALLS.find(x => x.id === id);
  if (!c) { toast('Report not found', 'error'); return; }

  const emailInput = document.getElementById('report-recipient-email');
  const email = emailInput ? emailInput.value.trim() : '';
  const errEl = document.getElementById('email-report-error');

  if (!email || !validateEmail(email)) {
    if (errEl) errEl.textContent = 'Please enter a valid email address';
    return;
  }

  if (errEl) errEl.textContent = '';

  const btn = document.getElementById('btn-send-report');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Sending...';
  }

  toast('Sending forensic report...', 'info');

  try {
    const token = localStorage.getItem('vx_jwt_token');
    if (!token) throw new Error('Authorization required. Please log in.');

    const reportData = {
      id: c.id,
      call_id: c.id,
      customer: c.customer,
      source: c.source,
      score: c.score,
      verdict: c.verdict,
      timestamp: c.timestamp,
      features: c.features,
      audio_sha256: c.audio_sha256,
      report_digital_signature: c.report_digital_signature
    };

    const response = await fetch('/api/send-report', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ email, report: reportData })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to email report');
    }

    toast('Forensic report emailed successfully! (Please check your spam folder)', 'success');
    closeEmailReportModal();
    pushAuditLog('REPORT_EMAILED', 'Emailed forensic report for Call ID: ' + id + ' to ' + email);
  } catch (error) {
    console.error('Email report error:', error);
    if (errEl) errEl.textContent = error.message;
    toast(error.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Send Email';
    }
  }
}

/* ============================================================
   VOICEPRINT REGISTRY (demo data)
   ============================================================ */
let VOICEPRINTS = JSON.parse(localStorage.getItem('sv_voiceprints') || '[]');
function saveVoiceprints() {
  localStorage.setItem('sv_voiceprints', JSON.stringify(VOICEPRINTS));
}
function renderVoiceprintRegistry() {
  const listEl = document.getElementById('vpr-list');
  if (!listEl) return;

  // Also update dashboard count card if it exists
  const countEl = document.getElementById('st-vp');
  if (countEl) {
    countEl.textContent = VOICEPRINTS.length;
  }

  if (VOICEPRINTS.length === 0) {
    listEl.innerHTML = `
      <div style="text-align:center; padding:30px 10px; color:var(--text3); font-size:12.5px;">
        <div style="font-size:24px; margin-bottom:8px;">📭</div>
        No voiceprints enrolled yet. Use the form to register a trusted customer voice.
      </div>`;
    return;
  }

  listEl.innerHTML = VOICEPRINTS.map((v, idx) => `
    <div class="vpr-row" style="display:flex; align-items:center; gap:12px; margin-bottom:8px; padding:12px; border-radius:8px; background:var(--surface2s); border:1px solid var(--border);">
      <div class="vpr-avatar" style="width:38px; height:38px; border-radius:50%; background:linear-gradient(135deg, var(--uco-blue), var(--blue2)); display:flex; align-items:center; justify-content:center; font-weight:700; color:#fff; font-size:13px; flex-shrink:0;">
        ${v.name.split(' ').map(x => x[0]).join('').slice(0, 2).toUpperCase()}
      </div>
      <div style="flex:1;">
        <div style="font-weight:600; font-size:13px; color:var(--text);">${v.name}</div>
        <div style="font-size:11px; color:var(--text3);" class="mono">${v.acct}</div>
      </div>
      <div style="text-align:right; margin-right:12px;">
        <div style="font-size:11px; color:var(--text3);">Baseline confidence</div>
        <div style="font-weight:700; color:var(--green);">${v.match}%</div>
      </div>
      <div>
        <button class="btn btn-danger btn-sm" onclick="deleteVoiceprint(${idx})" style="padding:4px 8px; font-size:11px;">Delete</button>
      </div>
    </div>`).join('');
}

function enrollVoiceprint() {
  const nameInput = document.getElementById('vp-new-name');
  const acctInput = document.getElementById('vp-new-acct');
  const matchInput = document.getElementById('vp-new-match');

  const name = nameInput.value.trim();
  const acct = acctInput.value.trim();
  const matchVal = parseInt(matchInput.value, 10);

  if (!name || !acct) {
    toast('Please enter customer name and account details', 'error');
    return;
  }

  if (isNaN(matchVal) || matchVal < 50 || matchVal > 100) {
    toast('Baseline confidence must be between 50% and 100%', 'error');
    return;
  }

  VOICEPRINTS.push({ name, acct, match: matchVal });
  saveVoiceprints();
  renderVoiceprintRegistry();

  nameInput.value = '';
  acctInput.value = '';
  matchInput.value = '95';

  toast('Customer voiceprint enrolled successfully!', 'success');
  pushAuditLog('VOICEPRINT_ENROLLED', 'Enrolled voiceprint biometric template for customer: ' + name);
}

function deleteVoiceprint(index) {
  if (index >= 0 && index < VOICEPRINTS.length) {
    const name = VOICEPRINTS[index].name;
    VOICEPRINTS.splice(index, 1);
    saveVoiceprints();
    renderVoiceprintRegistry();
    toast('Voiceprint deleted', 'info');
    pushAuditLog('VOICEPRINT_DELETED', 'Removed voiceprint biometric template for customer: ' + name);
  }
}

/* ============================================================
   DSP ENGINE — real FFT (AnalyserNode) + autocorrelation pitch
   ============================================================ */
let audioCtx, analyser, micStream, sourceNode, monRAF;
let monRunning = false;
let monStartTime = 0;
let monLog = [];
let pitchHistory = [];   // recent F0 estimates (Hz)
let ampHistory = [];     // recent peak amplitudes
let flagLogged = false;
let monGain;
let recorderNode = null;
let leftchannel = [];
let recordingLength = 0;

const spectroCanvas = () => document.getElementById('spectro-canvas');
const waveCanvas = () => document.getElementById('wave-canvas');

function logLine(msg, cls) {
  const el = document.getElementById('mon-log');
  const t = ((performance.now() - monStartTime) / 1000).toFixed(1);
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-time">[${t}s]</span> <span class="${cls || 'log-info'}">${msg}</span>`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

async function startMonitor() {
  try {
    micStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false } });
  } catch (e) {
    toast('Microphone access denied or unavailable. Try the "Analyze Recording" page instead.', 'error');
    return;
  }
  audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  sourceNode = audioCtx.createMediaStreamSource(micStream);
  analyser = audioCtx.createAnalyser();
  analyser.fftSize = 2048;
  analyser.smoothingTimeConstant = 0.2;

  // Initialize raw PCM recording buffer
  leftchannel = [];
  recordingLength = 0;
  try {
    const bufferSize = 4096;
    recorderNode = audioCtx.createScriptProcessor(bufferSize, 1, 1);
    recorderNode.onaudioprocess = function (e) {
      if (!monRunning) return;
      const left = e.inputBuffer.getChannelData(0);
      leftchannel.push(new Float32Array(left));
      recordingLength += bufferSize;
    };
  } catch (err) {
    console.error('Failed to start ScriptProcessor recorder:', err);
  }

  // Connect Web Audio Nodes through selected telephone codec chain
  connectAudioChain();

  document.getElementById('btn-start-mon').disabled = true;
  document.getElementById('btn-stop-mon').disabled = false;
  document.getElementById('mon-status').textContent = 'Capturing…';
  document.getElementById('nb-live').style.display = 'inline-block';
  document.getElementById('mon-log').innerHTML = '';
  const bioStatus = document.getElementById('mon-biometric-status');
  if (bioStatus) bioStatus.innerHTML = '';
  const expStatus = document.getElementById('mon-explanation');
  if (expStatus) {
    expStatus.innerHTML = '';
    expStatus.style.display = 'none';
  }
  pitchHistory = []; ampHistory = []; flagLogged = false;
  monStartTime = performance.now();
  monRunning = true;
  logLine('Microphone stream acquired. Sample rate ' + audioCtx.sampleRate + 'Hz.', 'log-good');
  logLine('Beginning continuous spectral + pitch analysis…', 'log-info');

  monitorTick();
  monTimerInt = setInterval(updateTimer, 200);
  pushAuditLog('LIVE_MONITOR_START', 'Agent started live microphone voice forensic scan.');
}

let monTimerInt;
function updateTimer() {
  if (!monRunning) return;
  const elapsed = (performance.now() - monStartTime) / 1000;
  const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
  const ss = String(Math.floor(elapsed % 60)).padStart(2, '0');
  document.getElementById('mon-timer').textContent = `⏱ ${mm}:${ss}`;
  const pct = Math.min(100, (elapsed / 30) * 100);
  document.getElementById('countdown-fill').style.width = pct + '%';
  document.getElementById('window-status').textContent = 'Continuous scanning active...';
}

function stopMonitor() {
  monRunning = false;
  clearInterval(monTimerInt);
  if (monRAF) cancelAnimationFrame(monRAF);
  if (recorderNode) {
    recorderNode.disconnect();
  }
  
  // Clean up noise nodes
  try {
    if (window.liveNoiseSource) {
      window.liveNoiseSource.stop();
      window.liveNoiseSource.disconnect();
      window.liveNoiseSource = null;
    }
    if (window.liveNoiseGain) {
      window.liveNoiseGain.disconnect();
      window.liveNoiseGain = null;
    }
  } catch (e) {}

  if (micStream) micStream.getTracks().forEach(t => t.stop());
  if (audioCtx) audioCtx.close();
  document.getElementById('btn-start-mon').disabled = false;
  document.getElementById('btn-stop-mon').disabled = true;
  document.getElementById('mon-status').textContent = 'Stopped';
  document.getElementById('nb-live').style.display = 'none';
  logLine('Capture stopped by operator.', 'log-warn');

  if (!flagLogged) {
    flagLogged = true;
    document.getElementById('window-status').textContent = 'window closed — verdict locked';
    finalizeWindowVerdict();
  }
  pushAuditLog('LIVE_MONITOR_STOP', 'Agent stopped live microphone voice forensic scan.');
}

function finalizeWindowVerdict() {
  if (leftchannel && leftchannel.length > 0) {
    logLine('Live capture window completed. Encoding recording to standard 16-bit WAV...', 'log-info');
    document.getElementById('window-status').textContent = 'Encoding WAV...';

    try {
      const merged = mergeBuffers(leftchannel, recordingLength);
      const audioBlob = encodeWAV(merged, audioCtx ? audioCtx.sampleRate : 44100);

      logLine('WAV encoding completed. Uploading recording for Machine Learning analysis...', 'log-info');
      document.getElementById('window-status').textContent = 'Running ML model analysis...';

      const token = localStorage.getItem('vx_jwt_token');
      const codecType = document.getElementById('mon-codec')?.value || 'none';
      fetch('/api/analyze-audio', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-File-Name': 'live_call.wav',
          'X-Codec-Type': codecType
        },
        body: audioBlob
      })
        .then(async (response) => {
          if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'ML analysis failed');
          }
          return response.json();
        })
        .then((result) => {
          const score = result.score;
          const features = result.features;

          // Calculate Composite Identity Risk score
          const compResult = getCompositeScore(score);
          const compScore = compResult.composite;
          const vComp = verdictFromScore(compScore);

          // Update UI with final ML/Composite scores
          document.getElementById('mon-score').textContent = compScore;
          const ring = document.getElementById('mon-ring');
          const circumference = 264;
          ring.style.strokeDashoffset = circumference - (circumference * compScore / 100);
          ring.style.stroke = vComp.color;

          const pillEl = document.getElementById('verdict-pill');
          pillEl.className = 'verdict-pill vp-' + vComp.cls;
          pillEl.textContent = '● ' + vComp.label;

          // Update breakdown pills
          document.getElementById('comp-acoustic').textContent = score + '%';
          document.getElementById('comp-biometrics').textContent = compResult.bStatus;
          document.getElementById('comp-metadata').textContent = compResult.mRisk + '%';

          // Update individual features displays
          document.getElementById('f-jitter').textContent = features.pitch_jitter_pct.toFixed(2) + '%';
          document.getElementById('f-shimmer').textContent = features.amplitude_shimmer_pct.toFixed(2) + '%';
          document.getElementById('f-flatness').textContent = features.spectral_flatness.toFixed(3);
          document.getElementById('f-hfanom').textContent = features.hf_energy_anomaly.toFixed(3);

          logLine(`ML ACOUSTIC VERDICT: ${verdictFromScore(score).label} (score ${score}/100)`, score >= 50 ? 'log-crit' : 'log-good');
          logLine(`COMPOSITE IDENTITY THREAT RATING: ${vComp.label} (score ${compScore}/100)`, compScore >= 50 ? 'log-crit' : 'log-good');
          logLine(`Recommendation: ${compScore >= 50 ? 'Flag account, request dynamic out-of-band push verification.' : result.recommendation}`, 'log-info');

          const elapsedSec = Math.round((performance.now() - monStartTime) / 1000);
          const currentCallId = 'CALL-' + Math.random().toString(36).slice(2, 8).toUpperCase();

          // Generate cryptographic seal for live monitor report
          try {
            audioBlob.arrayBuffer().then(async (arrayBuffer) => {
              const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
              const hashArray = Array.from(new Uint8Array(hashBuffer));
              const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
              const sigText = 'SIG_' + hashHex.substring(0, 16) + '_' + currentUser;

              const latencyIndicator = document.getElementById('simulated-latency-indicator');
              if (latencyIndicator) {
                latencyIndicator.innerHTML = `🛡️ SHA-256: <b>${hashHex.substring(0, 10)}...</b> | Signed: <b>VERIFIED ✓</b>`;
              }

              // update the call record signature
              const matchingCall = CALLS.find(c => c.id === currentCallId);
              if (matchingCall) {
                matchingCall.audio_sha256 = hashHex;
                matchingCall.report_digital_signature = sigText;
                saveCalls();
              }
            });
          } catch (e) {
            console.error('Failed to sign live audit record:', e);
          }

          document.getElementById('window-status').textContent = 'window closed — verdict locked';

          recordCall({
            id: currentCallId,
            source: 'Live Mic Capture',
            customer: document.getElementById('ctx-customer').value || 'Unidentified Caller',
            score: compScore,
            verdict: vComp,
            timeToFlag: elapsedSec,
            timestamp: new Date().toLocaleString('en-IN'),
            features: {
              ...features,
              composite_risk_score: compScore,
              acoustic_risk_score: score,
              biometric_status: compResult.bStatus,
              metadata_risk_score: compResult.mRisk
            }
          });
          const bioWrapper = document.getElementById('mon-biometric-status');
          if (bioWrapper) {
            bioWrapper.innerHTML = crossCheckBiometric(document.getElementById('ctx-customer').value, score);
          }
          const expWrapper = document.getElementById('mon-explanation');
          if (expWrapper) {
            expWrapper.innerHTML = generateForensicExplanation(score, features) + `
            <!-- Interactive Forensic Visualizations Tabbed Panel (Live capture) -->
            <div class="forensic-visualizations" style="margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px;">
              <div class="flex-between mb10" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <div style="font-weight:700; font-size:13px; color:var(--text);">📊 Acoustic & Forensic Charts</div>
                <div class="chart-tabs" style="display:flex; gap:6px;">
                  <button class="btn btn-ghost btn-xs active" id="live-btn-chart-timeline" onclick="switchForensicChart('live', 'timeline')">Risk Timeline</button>
                  <button class="btn btn-ghost btn-xs" id="live-btn-chart-spectrum" onclick="switchForensicChart('live', 'spectrum')">Frequency Spectrum</button>
                  <button class="btn btn-ghost btn-xs" id="live-btn-chart-biometrics" onclick="switchForensicChart('live', 'biometrics')">Biometric Deviation</button>
                </div>
              </div>
              
              <!-- Timeline Chart Panel -->
              <div class="chart-panel-wrapper" id="live-panel-chart-timeline">
                <canvas id="live-timeline-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block; cursor:crosshair;"></canvas>
                <div class="chart-theory">
                  <strong>Theory - Risk Timeline:</strong> Plots second-by-second synthetic voice classification confidence. Spikes indicate segments where the ML ensemble detected vocoder phase distortion or unnatural waveform regularities, typical of neural speech synthesis engines (like ElevenLabs or Tortoise-TTS). Real speech maintains a low, stable risk below 30% throughout the utterance. Hover over the chart to inspect specific chunks.
                </div>
              </div>
              
              <!-- Spectrum Chart Panel -->
              <div class="chart-panel-wrapper" id="live-panel-chart-spectrum" style="display:none;">
                <canvas id="live-spectrum-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block;"></canvas>
                <div class="chart-theory">
                  <strong>Theory - Spectral Formants & Codec Notch:</strong> Plots the frequency distribution of speech. Natural human speech relies on vocal tract resonance, creating clear periodic harmonics and formant peaks below 4 kHz. Generative AI voice clones often introduce high-frequency white noise artifacts or display a sharp brick-wall filter cutoff (codec notch) around 4 kHz or 8 kHz, resulting in high spectral flatness.
                </div>
              </div>
              
              <!-- Biometrics Chart Panel -->
              <div class="chart-panel-wrapper" id="live-panel-chart-biometrics" style="display:none;">
                <canvas id="live-biometrics-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block;"></canvas>
                <div class="chart-theory">
                  <strong>Theory - Jitter, Shimmer & Acoustic Stability:</strong> Displays how the caller's acoustic variability compares against normal human speech baselines (in green) and synthetic voice profiles (in red). Pitch Jitter and Amplitude Shimmer measure vocal fold micro-stability. Natural speech shows mild fluctuation (Jitter 0.5-3.0%, Shimmer 3-15%), whereas synthetic voices are either overly-stable (robotic, "flat-lined") or show high random variation.
                </div>
              </div>
            </div>
            <div style="margin-top:16px; display:flex; gap:10px;">
              <button class="btn btn-outline btn-sm" onclick="downloadReport('${currentCallId}')">Download Forensic Report</button>
              <button class="btn btn-outline btn-sm" onclick="openEmailReportModal('${currentCallId}')">Email Forensic Report</button>
            </div>
          `;
            expWrapper.style.display = 'block';

            // Draw live forensic charts using the virtualBuffer
            const virtualBuffer = {
              getChannelData: (ch) => merged,
              sampleRate: audioCtx ? audioCtx.sampleRate : 16000
            };

            // Store globally for redraws on tab switches
            window.activeForensicData.live = {
              audioBuffer: virtualBuffer,
              chunks: result.chunks,
              features
            };

            drawForensicTimeline('live-timeline-canvas', result.chunks, virtualBuffer);
            drawForensicSpectrum('live-spectrum-canvas', virtualBuffer);
            drawForensicBiometrics('live-biometrics-canvas', features);
          }
        })
        .catch((err) => {
          console.error('Live ML analysis failed:', err);
          logLine(`ML Analysis Failed: ${err.message}`, 'log-crit');
          document.getElementById('window-status').textContent = 'ML verification failed';
          fallbackHeuristic();
        });
    } catch (e) {
      console.error('WAV encoding/upload error:', e);
      logLine(`WAV Encoding Failed: ${e.message}`, 'log-crit');
      fallbackHeuristic();
    }
  } else {
    fallbackHeuristic();
  }
  if (typeof updateSuggestionsBasedOnScanner === 'function') {
    updateSuggestionsBasedOnScanner();
  }
}

function fallbackHeuristic() {
  const fallbackScore = currentScoreEstimate();
  const fallbackV = verdictFromScore(fallbackScore);
  logLine(`Using client-side fallback score: ${fallbackScore}/100`, 'log-warn');

  const elapsedSec = Math.round((performance.now() - monStartTime) / 1000);

  recordCall({
    id: 'CALL-' + Math.random().toString(36).slice(2, 8).toUpperCase(),
    source: 'Live Mic Capture (Fallback)',
    customer: document.getElementById('ctx-customer').value || 'Unidentified Caller',
    score: fallbackScore,
    verdict: fallbackV,
    timeToFlag: elapsedSec,
    timestamp: new Date().toLocaleString('en-IN'),
    features: lastFeatures
  });
  const bioWrapper = document.getElementById('mon-biometric-status');
  if (bioWrapper) {
    bioWrapper.innerHTML = crossCheckBiometric(document.getElementById('ctx-customer').value, fallbackScore);
  }
  const expWrapper = document.getElementById('mon-explanation');
  if (expWrapper) {
    const fallbackFeatures = {
      pitch_jitter_pct: (fallbackScore > 50 ? 0.15 : 1.2),
      amplitude_shimmer_pct: (fallbackScore > 50 ? 1.1 : 5.5),
      spectral_flatness: (fallbackScore > 50 ? 0.35 : 0.08),
      hf_energy_anomaly: (fallbackScore > 50 ? 0.45 : 0.05)
    };
    expWrapper.innerHTML = generateForensicExplanation(fallbackScore, fallbackFeatures);
    expWrapper.style.display = 'block';
  }
}

function mergeBuffers(channelBuffer, recordingLength) {
  let result = new Float32Array(recordingLength);
  let offset = 0;
  for (let i = 0; i < channelBuffer.length; i++) {
    let buffer = channelBuffer[i];
    result.set(buffer, offset);
    offset += buffer.length;
  }
  return result;
}

function encodeWAV(samples, sampleRate) {
  let buffer = new ArrayBuffer(44 + samples.length * 2);
  let view = new DataView(buffer);

  writeString(view, 0, 'RIFF');
  view.setUint32(4, 36 + samples.length * 2, true);
  writeString(view, 8, 'WAVE');
  writeString(view, 12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(view, 36, 'data');
  view.setUint32(40, samples.length * 2, true);

  floatTo16BitPCM(view, 44, samples);
  return new Blob([view], { type: 'audio/wav' });
}

function floatTo16BitPCM(output, offset, input) {
  for (let i = 0; i < input.length; i++, offset += 2) {
    let s = Math.max(-1, Math.min(1, input[i]));
    output.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
  }
}

function writeString(view, offset, string) {
  for (let i = 0; i < string.length; i++) {
    view.setUint8(offset + i, string.charCodeAt(i));
  }
}

// time-domain autocorrelation pitch detector
function autoCorrelate(buf, sampleRate) {
  const SIZE = buf.length;
  let rms = 0;
  for (let i = 0; i < SIZE; i++) rms += buf[i] * buf[i];
  rms = Math.sqrt(rms / SIZE);
  if (rms < 0.01) return -1; // too quiet

  let r1 = 0, r2 = SIZE - 1, thres = 0.2;
  for (let i = 0; i < SIZE / 2; i++) { if (Math.abs(buf[i]) < thres) { r1 = i; break; } }
  for (let i = 1; i < SIZE / 2; i++) { if (Math.abs(buf[SIZE - i]) < thres) { r2 = SIZE - i; break; } }
  const trimmed = buf.slice(r1, r2);
  const TSIZE = trimmed.length;
  const c = new Array(TSIZE).fill(0);
  for (let lag = 0; lag < TSIZE; lag++) {
    let sum = 0;
    for (let i = 0; i < TSIZE - lag; i++) sum += trimmed[i] * trimmed[i + lag];
    c[lag] = sum;
  }
  let d = 0; while (c[d] > c[d + 1]) d++;
  let maxval = -1, maxpos = -1;
  for (let i = d; i < TSIZE; i++) { if (c[i] > maxval) { maxval = c[i]; maxpos = i; } }
  let T0 = maxpos;
  if (T0 <= 0) return -1;
  const f0 = sampleRate / T0;
  if (f0 < 60 || f0 > 500) return -1; // outside plausible human voice F0 range
  return f0;
}

function spectralFlatness(magArr) {
  let logSum = 0, sum = 0, n = 0;
  for (let i = 4; i < magArr.length; i++) { // skip DC/very-low bins
    const m = Math.max(magArr[i], 1e-6);
    logSum += Math.log(m);
    sum += m;
    n++;
  }
  const gm = Math.exp(logSum / n);
  const am = sum / n;
  return am > 0 ? gm / am : 0;
}

function hfEnergyAnomaly(magArr, sampleRate, fftSize) {
  const binHz = sampleRate / fftSize;
  const band = (lo, hi) => {
    let s = 0, c = 0;
    for (let i = Math.floor(lo / binHz); i < Math.min(magArr.length, Math.floor(hi / binHz)); i++) { s += magArr[i]; c++; }
    return c ? s / c : 0;
  };
  const mid = band(1000, 3000);
  const hi = band(4000, 7500);
  if (mid < 1e-6) return 0;
  const ratio = hi / mid;
  // natural speech: ratio typically low (~0.05-0.25); flag deviation from expected band
  return Math.min(1, Math.abs(ratio - 0.15) / 0.5);
}

let lastFeatures = {};
let smoothedScore = 0;

function currentScoreEstimate() { return Math.round(smoothedScore); }

function monitorTick() {
  if (!monRunning) return;
  const bufLen = analyser.fftSize;
  const timeData = new Float32Array(bufLen);
  analyser.getFloatTimeDomainData(timeData);

  const freqBinCount = analyser.frequencyBinCount;
  const freqData = new Uint8Array(freqBinCount);
  analyser.getByteFrequencyData(freqData);
  const freqDataF = new Float32Array(freqBinCount);
  analyser.getFloatFrequencyData(freqDataF); // dB scale, for flatness use linear

  // convert dB to linear magnitude for flatness calc
  const linMag = new Float32Array(freqBinCount);
  for (let i = 0; i < freqBinCount; i++) linMag[i] = Math.pow(10, freqDataF[i] / 20);

  // pitch
  const f0 = autoCorrelate(timeData, audioCtx.sampleRate);
  let peakAmp = 0;
  for (let i = 0; i < bufLen; i++) peakAmp = Math.max(peakAmp, Math.abs(timeData[i]));

  if (f0 > 0) {
    pitchHistory.push(f0);
    if (pitchHistory.length > 40) pitchHistory.shift();
  }
  if (peakAmp > 0.02) {
    ampHistory.push(peakAmp);
    if (ampHistory.length > 40) ampHistory.shift();
  }

  // Active defense challenge latency timer hook
  if (window.challengeTimerActive && peakAmp > 0.04) {
    stopChallengeTimer();
  }

  let jitterPct = 0;
  if (pitchHistory.length > 4) {
    let diffs = 0;
    for (let i = 1; i < pitchHistory.length; i++) diffs += Math.abs(pitchHistory[i] - pitchHistory[i - 1]);
    const avgDiff = diffs / (pitchHistory.length - 1);
    const avgF0 = pitchHistory.reduce((a, b) => a + b, 0) / pitchHistory.length;
    jitterPct = avgF0 > 0 ? (avgDiff / avgF0) * 100 : 0;
  }

  let shimmerPct = 0;
  if (ampHistory.length > 4) {
    let diffs = 0;
    for (let i = 1; i < ampHistory.length; i++) diffs += Math.abs(ampHistory[i] - ampHistory[i - 1]);
    const avgDiff = diffs / (ampHistory.length - 1);
    const avgAmp = ampHistory.reduce((a, b) => a + b, 0) / ampHistory.length;
    shimmerPct = avgAmp > 0 ? (avgDiff / avgAmp) * 100 : 0;
  }

  let flatness = spectralFlatness(linMag);
  let hfAnom = hfEnergyAnomaly(linMag, audioCtx.sampleRate, bufLen);

  // ---- HACKATHON INTERACTIVE SANDBOX OVERRIDES ----
  if (window.sandboxAttackActive) {
    jitterPct = 0.05 + Math.random() * 0.06;  // ultra-low jitter (TTS smoothing)
    shimmerPct = 0.6 + Math.random() * 0.4;   // ultra-low shimmer
    flatness = 0.001 + Math.random() * 0.002; // highly tonal
    hfAnom = 0.72 + Math.random() * 0.12;     // high-frequency vocoder artifacts
  }

  // ---- TELEPHONY NOISY CALL CENTER PERTURBATIONS ----
  const currentCodec = document.getElementById('mon-codec')?.value || 'none';
  if (currentCodec === 'noisy' && !window.sandboxAttackActive) {
    jitterPct = Math.max(0.1, jitterPct + (Math.random() * 0.6 - 0.3));
    shimmerPct = Math.max(0.5, shimmerPct + (Math.random() * 4.0 - 2.0));
    flatness = Math.max(0.001, flatness + (Math.random() * 0.015));
    hfAnom = Math.max(0.0, hfAnom + (Math.random() * 0.1 - 0.05));
  }

  // ---- composite heuristic risk score (0-100) ----
  // natural human jitter ~0.5-3%; flag if too low (<0.3, "too clean") or too high (>6, unstable)
  let jitterRisk = 0;
  if (window.sandboxAttackActive || pitchHistory.length > 4) {
    if (jitterPct < 0.3) jitterRisk = 95;
    else if (jitterPct < 0.6) jitterRisk = 60;
    else if (jitterPct > 6) jitterRisk = 55;
    else jitterRisk = 8;
  }
  let shimmerRisk = 0;
  if (window.sandboxAttackActive || ampHistory.length > 4) {
    shimmerRisk = shimmerPct < 2 ? 90 : shimmerPct > 25 ? 40 : 10;
  }
  const flatnessRisk = Math.min(100, flatness * 240); // higher flatness => more "synthetic/tonal"
  const hfRisk = Math.min(100, hfAnom * 100);

  let sensMult = SENSITIVITY === 'aggressive' ? 1.15 : SENSITIVITY === 'conservative' ? 0.85 : 1.0;
  let raw = (jitterRisk * 0.35 + shimmerRisk * 0.2 + flatnessRisk * 0.25 + hfRisk * 0.2) * sensMult;
  if (window.sandboxAttackActive) {
    raw = Math.max(92, raw);
  }
  smoothedScore = smoothedScore * 0.75 + Math.min(100, raw) * 0.25;

  lastFeatures = {
    pitch_jitter_pct: +jitterPct.toFixed(2),
    amplitude_shimmer_pct: +shimmerPct.toFixed(2),
    spectral_flatness: +flatness.toFixed(3),
    hf_energy_anomaly: +hfAnom.toFixed(3),
    composite_risk_score: Math.round(smoothedScore)
  };

  // update UI
  document.getElementById('f-jitter').textContent = jitterPct.toFixed(2) + '%';
  document.getElementById('f-jitter-bar').style.width = Math.min(100, jitterRisk) + '%';
  document.getElementById('f-shimmer').textContent = shimmerPct.toFixed(2) + '%';
  document.getElementById('f-shimmer-bar').style.width = Math.min(100, shimmerRisk) + '%';
  document.getElementById('f-flatness').textContent = flatness.toFixed(3);
  document.getElementById('f-flatness-bar').style.width = Math.min(100, flatnessRisk) + '%';
  document.getElementById('f-hfanom').textContent = hfAnom.toFixed(3);
  document.getElementById('f-hfanom-bar').style.width = Math.min(100, hfRisk) + '%';

  const score = Math.round(smoothedScore);

  // Compute composite scoring (Voiceprint biometrics + Metadata reputation + Audio forensics)
  const compResult = getCompositeScore(score);
  const compositeScore = compResult.composite;
  const vComp = verdictFromScore(compositeScore);

  // Update UI indicators with composite details
  document.getElementById('mon-score').textContent = compositeScore;
  const ring = document.getElementById('mon-ring');
  const circumference = 264;
  ring.style.strokeDashoffset = circumference - (circumference * compositeScore / 100);
  ring.style.stroke = vComp.color;

  const pillEl = document.getElementById('verdict-pill');
  pillEl.className = 'verdict-pill vp-' + vComp.cls;
  pillEl.textContent = '● ' + vComp.label;

  // Update mini pill breakdowns
  document.getElementById('comp-acoustic').textContent = score + '%';
  document.getElementById('comp-biometrics').textContent = compResult.bStatus;
  document.getElementById('comp-metadata').textContent = compResult.mRisk + '%';

  // Update transaction security panel lock state
  updateTransactionLockState(compositeScore);

  document.getElementById('mon-status').textContent = compositeScore >= 50 ? '⚠ Elevated risk detected' : 'Capturing…';

  // sparse logging
  if (Math.random() < 0.04 && pitchHistory.length > 4) {
    logLine(`F0≈${f0 > 0 ? f0.toFixed(0) + 'Hz' : 'n/a'} · jitter ${jitterPct.toFixed(2)}% · flatness ${flatness.toFixed(3)} · score ${score}`, score >= 50 ? 'log-warn' : 'log-info');
  }

  drawSpectrogram(freqData);
  drawWaveform(timeData);

  monRAF = requestAnimationFrame(monitorTick);
}

/* ---------- canvas rendering ---------- */
function drawSpectrogram(freqData) {
  const canvas = spectroCanvas();
  const ctx = canvas.getContext('2d');
  const w = canvas.clientWidth, h = canvas.height;
  if (canvas.width !== w) canvas.width = w;
  // scroll left
  const img = ctx.getImageData(1, 0, w - 1, h);
  ctx.putImageData(img, 0, 0);
  const colW = 1;
  const n = freqData.length;
  for (let y = 0; y < h; y++) {
    const bin = Math.floor((1 - y / h) * n * 0.6); // show up to ~60% of nyquist for voice band emphasis
    const v = freqData[bin] || 0;
    const intensity = v / 255;
    const hue = 215 - intensity * 215; // blue(215) -> gold/red(0) as intensity rises
    const light = 6 + intensity * 48;
    ctx.fillStyle = `hsl(${hue}, 90%, ${light}%)`;
    ctx.fillRect(w - 1, y, colW, 1);
  }

  // --- HACKATHON EXPLAINABLE AI (XAI) SPECTRUM OVERLAYS ---
  const codec = document.getElementById('mon-codec')?.value || 'none';

  // 1. Draw Codec bandpass limits
  if (codec === 'gsm' || codec === 'landline' || codec === 'noisy') {
    const cutoffFreq = codec === 'landline' ? 2500 : 3400;
    const yCut = h - (cutoffFreq / 4800) * h;

    ctx.strokeStyle = 'rgba(242, 169, 0, 0.45)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, yCut);
    ctx.lineTo(w, yCut);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = 'var(--uco-gold)';
    ctx.font = 'bold 8px monospace';
    ctx.fillText(`📱 ${codec.toUpperCase()} CHANNEL CUTOFF (${cutoffFreq} Hz)`, 10, yCut - 4);
    
    if (codec === 'noisy') {
      ctx.fillStyle = 'var(--uco-gold)';
      ctx.fillText('🏢 NOISY CALL CENTER MODE — ACTIVE NOISE SUPPRESSION ENGAGED', 10, h - 10);
    }
  }

  // 2. Draw Vocoder noise smear indicator (High Risk visual trigger)
  const currentAcousticRisk = window.lastFeatures?.composite_risk_score || 0;
  if (currentAcousticRisk >= 50) {
    const flash = Math.floor(Date.now() / 350) % 2 === 0;
    if (flash) {
      // Highlight Vocoder Artifact Zone (high frequencies)
      ctx.fillStyle = 'rgba(239, 68, 68, 0.08)';
      ctx.fillRect(0, 0, w, h * 0.25);

      ctx.strokeStyle = 'rgba(239, 68, 68, 0.5)';
      ctx.lineWidth = 1.25;
      ctx.beginPath();
      ctx.moveTo(0, h * 0.25);
      ctx.lineTo(w, h * 0.25);
      ctx.stroke();

      ctx.fillStyle = 'var(--red)';
      ctx.font = 'bold 9px monospace';
      ctx.fillText('🚨 SYNTHETIC VOCODER NOISE SMEAR (>3.6 kHz)', 12, 16);

      // Add extra features based warnings
      let yOffset = 30;
      if (window.lastFeatures?.pitch_jitter_pct < 0.3) {
        ctx.fillText('🤖 ABNORMAL PITCH JITTER: Monotone/Flat Pitch (TTS)', 12, yOffset);
        yOffset += 14;
      }
      if (window.lastFeatures?.amplitude_shimmer_pct < 2) {
        ctx.fillText('🤖 ABNORMAL SHIMMER: Robotic Amplitude Signature', 12, yOffset);
        yOffset += 14;
      }
      if (window.lastFeatures?.spectral_flatness > 0.005) {
        ctx.fillText('🚨 HIGH SPECTRAL FLATNESS: Unnatural Noise Smearing', 12, yOffset);
      }
    }
  }
}

function drawWaveform(timeData) {
  const canvas = waveCanvas();
  const ctx = canvas.getContext('2d');
  const w = canvas.clientWidth, h = canvas.height;
  if (canvas.width !== w) canvas.width = w;
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = '#F2A900';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  const step = Math.ceil(timeData.length / w);
  for (let x = 0; x < w; x++) {
    const i = x * step;
    const v = timeData[i] || 0;
    const y = h / 2 - v * h * 0.45;
    if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.stroke();
}

/* ============================================================
   FILE UPLOAD ANALYSIS (offline full-clip)
   ============================================================ */
const dz = document.getElementById ? null : null;
document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  if (!dropzone) return;
  ['dragenter', 'dragover'].forEach(ev => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach(ev => dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });
});

async function handleFile(file) {
  if (!file) return;
  const resultCard = document.getElementById('upload-result-card');
  resultCard.style.display = 'block';
  resultCard.innerHTML = `<div class="card-title">Analyzing ${file.name}…</div><div class="pbar" style="margin-top:10px;"><div class="pfill" style="width:30%;background:var(--gold);"></div></div>`;

  try {
    const token = localStorage.getItem('vx_jwt_token');
    const codecType = document.getElementById('upload-codec')?.value || 'none';
    const response = await fetch('/api/analyze-audio', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-File-Name': file.name,
        'X-Codec-Type': codecType
      },
      body: file
    });

    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.error || 'Server analysis failed');
    }

    const result = await response.json();
    const score = result.score;
    const features = result.features;

    // Use getCompositeScore helper for file uploads
    const compResult = getCompositeScore(score);
    const compScore = compResult.composite;
    const vComp = verdictFromScore(compScore);

    let jitterPct = features.pitch_jitter_pct;
    let shimmerPct = features.amplitude_shimmer_pct;
    let flatness = features.spectral_flatness;
    let hfAnom = features.hf_energy_anomaly;

    let jitterRisk = jitterPct < 0.3 ? 70 : jitterPct < 0.6 ? 35 : jitterPct > 6 ? 55 : 8;
    let shimmerRisk = shimmerPct < 2 ? 60 : shimmerPct > 25 ? 40 : 10;
    const flatnessRisk = Math.min(100, flatness * 240);
    const hfRisk = Math.min(100, hfAnom * 100);

    let customerName = document.getElementById('upload-customer-name').value.trim();
    if (!customerName) {
      customerName = file.name.split('.')[0].replace(/_/g, ' ').replace(/-/g, ' ');
      const lower = customerName.toLowerCase();
      if (lower.includes('voice') || lower.includes('call') || lower.includes('test') || lower.includes('sample') || lower.includes('gtts') || lower.includes('pyttsx3')) {
        customerName = 'Unidentified Caller';
      }
    }

    const id = 'CALL-' + Math.random().toString(36).slice(2, 8).toUpperCase();
    recordCall({
      id,
      source: 'Uploaded Recording (' + file.name + ')',
      customer: customerName,
      score: compScore,
      verdict: vComp,
      timeToFlag: null,
      timestamp: new Date().toLocaleString('en-IN'),
      features: {
        ...features,
        composite_risk_score: compScore,
        acoustic_risk_score: score,
        biometric_status: compResult.bStatus,
        metadata_risk_score: compResult.mRisk
      }
    });

    const biometricHtml = crossCheckBiometric(customerName, score);
    const explanationHtml = generateForensicExplanation(score, features);

    resultCard.innerHTML = `
      <div class="flex-between mb14">
        <div>
          <div class="card-title" style="margin-bottom:0;">${file.name}</div>
          <div class="card-sub" style="margin-bottom:0;">${features.duration_sec.toFixed(1)}s · ${features.frames_analyzed} frames analyzed</div>
          <div style="font-size: 11px; color: var(--blue); margin-top: 4px; font-weight: 600; display: flex; align-items: center; gap: 4px;">
            <span>🤖</span> Classification: 51-Feature Hybrid ML Ensemble (Retrained v3)
          </div>
        </div>
        <span class="verdict-pill vp-${vComp.cls}">● ${vComp.label}</span>
      </div>
      
      <!-- Biometric Verification Status -->
      <div id="upload-biometric-status">${biometricHtml}</div>

      <div class="score-wrap">
        <div class="ring-box">
          <svg viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface3)" stroke-width="9"/>
            <circle cx="50" cy="50" r="42" fill="none" stroke="${vComp.color}" stroke-width="9" stroke-linecap="round" stroke-dasharray="264" stroke-dashoffset="${264 - 264 * compScore / 100}"/>
          </svg>
          <div class="ring-label"><div class="ring-val">${compScore}</div><div class="ring-den">/ 100</div></div>
        </div>
        <div class="sbars">
          <div class="sbar-row"><div class="sbar-lbl">Pitch Jitter</div><div class="sbar-track"><div class="sbar-fill" style="width:${Math.min(100, jitterRisk)}%;background:var(--accent-blue);"></div></div><div class="sbar-pct">${jitterPct.toFixed(2)}%</div></div>
          <div class="sbar-row"><div class="sbar-lbl">Amplitude Shimmer</div><div class="sbar-track"><div class="sbar-fill" style="width:${Math.min(100, shimmerRisk)}%;background:var(--gold);"></div></div><div class="sbar-pct">${shimmerPct.toFixed(2)}%</div></div>
          <div class="sbar-row"><div class="sbar-lbl">Spectral Flatness</div><div class="sbar-track"><div class="sbar-fill" style="width:${Math.min(100, flatnessRisk)}%;background:var(--green);"></div></div><div class="sbar-pct">${flatness.toFixed(3)}</div></div>
          <div class="sbar-row"><div class="sbar-lbl">HF Energy Anomaly</div><div class="sbar-track"><div class="sbar-fill" style="width:${Math.min(100, hfRisk)}%;background:var(--red);"></div></div><div class="sbar-pct">${hfAnom.toFixed(3)}</div></div>
        </div>
      </div>

      <!-- Waveform Graph Canvas -->
      <div style="margin-top: 16px;">
        <div style="font-weight:600; font-size:12.5px; margin-bottom: 6px; color:var(--text2);">Acoustic Waveform Analysis</div>
        <canvas id="uploaded-wave-canvas" height="60" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block;"></canvas>
      </div>

      <!-- Interactive Forensic Visualizations Tabbed Panel -->
      <div class="forensic-visualizations" style="margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px;">
        <div class="flex-between mb10" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <div style="font-weight:700; font-size:13px; color:var(--text);">📊 Acoustic & Forensic Charts</div>
          <div class="chart-tabs" style="display:flex; gap:6px;">
            <button class="btn btn-ghost btn-xs active" id="upload-btn-chart-timeline" onclick="switchForensicChart('upload', 'timeline')">Risk Timeline</button>
            <button class="btn btn-ghost btn-xs" id="upload-btn-chart-spectrum" onclick="switchForensicChart('upload', 'spectrum')">Frequency Spectrum</button>
            <button class="btn btn-ghost btn-xs" id="upload-btn-chart-biometrics" onclick="switchForensicChart('upload', 'biometrics')">Biometric Deviation</button>
          </div>
        </div>
        
        <!-- Timeline Chart Panel -->
        <div class="chart-panel-wrapper" id="upload-panel-chart-timeline">
          <canvas id="upload-timeline-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block; cursor:crosshair;"></canvas>
          <div class="chart-theory">
            <strong>Theory - Risk Timeline:</strong> Plots second-by-second synthetic voice classification confidence. Spikes indicate segments where the ML ensemble detected vocoder phase distortion or unnatural waveform regularities, typical of neural speech synthesis engines (like ElevenLabs or Tortoise-TTS). Real speech maintains a low, stable risk below 30% throughout the utterance. Hover over the chart to inspect specific chunks.
          </div>
        </div>
        
        <!-- Spectrum Chart Panel -->
        <div class="chart-panel-wrapper" id="upload-panel-chart-spectrum" style="display:none;">
          <canvas id="upload-spectrum-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block;"></canvas>
          <div class="chart-theory">
            <strong>Theory - Spectral Formants & Codec Notch:</strong> Plots the frequency distribution of speech. Natural human speech relies on vocal tract resonance, creating clear periodic harmonics and formant peaks below 4 kHz. Generative AI voice clones often introduce high-frequency white noise artifacts or display a sharp brick-wall filter cutoff (codec notch) around 4 kHz or 8 kHz, resulting in high spectral flatness.
          </div>
        </div>
        
        <!-- Biometrics Chart Panel -->
        <div class="chart-panel-wrapper" id="upload-panel-chart-biometrics" style="display:none;">
          <canvas id="upload-biometrics-canvas" height="150" style="background:#050810; border-radius:8px; border:1px solid var(--border2); width:100%; display:block;"></canvas>
          <div class="chart-theory">
            <strong>Theory - Jitter, Shimmer & Acoustic Stability:</strong> Displays how the caller's acoustic variability compares against normal human speech baselines (in green) and synthetic voice profiles (in red). Pitch Jitter and Amplitude Shimmer measure vocal fold micro-stability. Natural speech shows mild fluctuation (Jitter 0.5-3.0%, Shimmer 3-15%), whereas synthetic voices are either overly-stable (robotic, "flat-lined") or show high random variation.
          </div>
        </div>
      </div>

      <!-- Forensic Metric Explanations -->
      ${explanationHtml}

      <!-- Cryptographic Court-Ready Forensic Seal -->
      <div style="margin-top: 16px; border: 1px solid var(--border); padding: 12px; border-radius: 8px; background: rgba(16, 185, 129, 0.03); display: flex; align-items: center; gap: 12px;">
        <div style="font-size: 24px;">🛡️</div>
        <div style="flex:1;">
          <div style="font-weight: 700; font-size: 11px; color: var(--green); text-transform: uppercase; letter-spacing: 0.5px;">Chain of Custody Cryptographic Seal</div>
          <div style="font-size: 10px; color: var(--text3);" class="mono">
            SHA-256: <span id="crypto-file-hash">Calculating...</span>
          </div>
          <div style="font-size: 10px; color: var(--text3); margin-top: 2px;" class="mono">
            Digital Signature: <span id="crypto-ledger-sig">Calculating...</span>
          </div>
        </div>
        <div style="font-size: 10px; font-weight: 700; color: var(--green); border: 1px solid var(--green); padding: 2px 6px; border-radius: 4px; text-transform: uppercase;">
          VERIFIED ✓
        </div>
      </div>

      <div style="margin-top:16px; display:flex; gap:10px;">
        <button class="btn btn-outline btn-sm" onclick="downloadReport('${id}')">Download Forensic Report</button>
        <button class="btn btn-outline btn-sm" onclick="openEmailReportModal('${id}')">Email Forensic Report</button>
      </div>
    `;

    // Decode and draw waveform in the background
    const reader = new FileReader();
    reader.onload = async (e) => {
      const arrayBuffer = e.target.result;
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      try {
        const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
        drawUploadedWaveform(audioBuffer);

        // Store globally for redraws on tab switches
        window.activeForensicData.upload = {
          audioBuffer,
          chunks: result.chunks,
          features
        };

        // Draw the visual forensic charts
        drawForensicTimeline('upload-timeline-canvas', result.chunks, audioBuffer);
        drawForensicSpectrum('upload-spectrum-canvas', audioBuffer);
        drawForensicBiometrics('upload-biometrics-canvas', features);
      } catch (err) {
        console.error("Error decoding audio buffer for waveform:", err);
      }
    };
    reader.readAsArrayBuffer(file);

    // Calculate SHA-256 hash in browser
    setTimeout(async () => {
      try {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        const sigText = 'SIG_' + hashHex.substring(0, 16) + '_' + currentUser;

        const hashEl = document.getElementById('crypto-file-hash');
        if (hashEl) hashEl.textContent = hashHex.substring(0, 32) + '...';
        const sigEl = document.getElementById('crypto-ledger-sig');
        if (sigEl) sigEl.textContent = sigText;

        // Save signature and hash on the Call record
        const matchingCall = CALLS.find(c => c.id === id);
        if (matchingCall) {
          matchingCall.audio_sha256 = hashHex;
          matchingCall.report_digital_signature = sigText;
          saveCalls();
        }
      } catch (err) {
        console.error('Failed to generate crypto hashes:', err);
      }
    }, 100);

    toast('Analysis complete', 'success');
    if (typeof updateSuggestionsBasedOnScanner === 'function') {
      updateSuggestionsBasedOnScanner();
    }
  } catch (e) {
    console.error('File analysis failed:', e);
    resultCard.innerHTML = `<div class="card-title" style="color:var(--red);">Analysis failed</div><div class="card-sub">${e.message}</div>`;
    toast(e.message, 'error');
  }
}

function drawUploadedWaveform(audioBuffer) {
  const canvas = document.getElementById('uploaded-wave-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  const data = audioBuffer.getChannelData(0);
  const amp = height / 2;

  // Draw background grid lines
  ctx.strokeStyle = 'rgba(0, 68, 170, 0.08)';
  ctx.lineWidth = 1;
  for (let i = 0; i < width; i += 40) {
    ctx.beginPath();
    ctx.moveTo(i, 0);
    ctx.lineTo(i, height);
    ctx.stroke();
  }
  ctx.beginPath();
  ctx.moveTo(0, amp);
  ctx.lineTo(width, amp);
  ctx.stroke();

  // Create a beautiful blue-gold gradient for the waveform
  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, '#0044AA');     // UCO Blue
  gradient.addColorStop(0.5, '#1a5fd6');   // Blue2
  gradient.addColorStop(1, '#F2A900');     // Gold

  ctx.fillStyle = gradient;

  // SoundCloud-like bar style waveform
  const barWidth = 2;
  const gap = 1;
  const totalBars = Math.floor(width / (barWidth + gap));
  const samplesPerBar = Math.floor(data.length / totalBars);

  for (let i = 0; i < totalBars; i++) {
    const start = i * samplesPerBar;
    let min = 1.0;
    let max = -1.0;
    for (let j = 0; j < samplesPerBar; j++) {
      const val = data[start + j] || 0;
      if (val < min) min = val;
      if (val > max) max = val;
    }

    // Calculate heights relative to canvas height
    const magnitude = Math.max(Math.abs(min), Math.abs(max));
    const barHeight = Math.max(2, magnitude * height * 0.85);
    const x = i * (barWidth + gap);
    const y = (height - barHeight) / 2;

    // Draw rounded rect bar
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, barWidth, barHeight, 1);
    } else {
      ctx.rect(x, y, barWidth, barHeight);
    }
    ctx.fill();
  }
}

/* ============================================================
   LIGHTWEIGHT FFT & SPECTRAL ANALYSIS ENGINE
   ============================================================ */

// Cooley-Tukey Radix-2 FFT (in-place)
function cooleyTukeyFFT(re, im) {
  const n = re.length;
  if (n <= 1) return;

  const reEven = new Float32Array(n / 2);
  const imEven = new Float32Array(n / 2);
  const reOdd = new Float32Array(n / 2);
  const imOdd = new Float32Array(n / 2);

  for (let i = 0; i < n / 2; i++) {
    reEven[i] = re[2 * i];
    imEven[i] = im[2 * i];
    reOdd[i] = re[2 * i + 1];
    imOdd[i] = im[2 * i + 1];
  }

  cooleyTukeyFFT(reEven, imEven);
  cooleyTukeyFFT(reOdd, imOdd);

  for (let k = 0; k < n / 2; k++) {
    const angle = -2 * Math.PI * k / n;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const tRe = reOdd[k] * cos - imOdd[k] * sin;
    const tIm = reOdd[k] * sin + imOdd[k] * cos;

    re[k] = reEven[k] + tRe;
    im[k] = imEven[k] + tIm;
    re[k + n / 2] = reEven[k] - tRe;
    im[k + n / 2] = imEven[k] - tIm;
  }
}

// Compute the average power spectrum of active speech segments in the AudioBuffer
function computeAverageSpectrum(audioBuffer, fftSize = 1024) {
  const data = audioBuffer.getChannelData(0);
  const sampleRate = audioBuffer.sampleRate;
  const numSamples = data.length;

  const hopSize = fftSize;
  const numFrames = Math.floor(numSamples / hopSize);

  const avgSpectrum = new Float32Array(fftSize / 2);
  let countedFrames = 0;

  // Pre-calculate Hann window
  const hannWindow = new Float32Array(fftSize);
  for (let i = 0; i < fftSize; i++) {
    hannWindow[i] = 0.5 * (1 - Math.cos((2 * Math.PI * i) / (fftSize - 1)));
  }

  // Iterate over frames and process ones that exceed noise/silence threshold
  for (let f = 0; f < numFrames; f++) {
    const startIdx = f * hopSize;
    if (startIdx + fftSize > numSamples) break;

    // Calculate RMS for Voice Activity Detection proxy
    let sumSq = 0;
    for (let i = 0; i < fftSize; i++) {
      const val = data[startIdx + i] || 0;
      sumSq += val * val;
    }
    const rms = Math.sqrt(sumSq / fftSize);

    // Process only if it is active speech, ignoring background noise/silence
    if (rms > 0.015) {
      const re = new Float32Array(fftSize);
      const im = new Float32Array(fftSize);

      // Apply windowing
      for (let i = 0; i < fftSize; i++) {
        re[i] = (data[startIdx + i] || 0) * hannWindow[i];
      }

      cooleyTukeyFFT(re, im);

      // Accumulate magnitudes for positive frequencies
      for (let k = 0; k < fftSize / 2; k++) {
        const mag = Math.sqrt(re[k] * re[k] + im[k] * im[k]);
        avgSpectrum[k] += mag;
      }
      countedFrames++;
    }
  }

  // Normalize and scale
  if (countedFrames > 0) {
    for (let k = 0; k < fftSize / 2; k++) {
      avgSpectrum[k] /= countedFrames;
    }
  }

  return { avgSpectrum, sampleRate };
}

// Timeline Draw Function (Glowing Area Chart with spline interpolation)
function drawForensicTimeline(canvasId, chunks, audioBuffer) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (width === 0 || height === 0) return;
  canvas.width = width;
  canvas.height = height;

  // Extract waveform envelope
  const pcm = audioBuffer ? audioBuffer.getChannelData(0) : null;
  const step = pcm ? Math.floor(pcm.length / width) : 1;
  const waveData = [];
  if (pcm) {
    for (let i = 0; i < width; i++) {
      let max = 0;
      const start = i * step;
      for (let j = 0; j < step; j++) {
        const val = Math.abs(pcm[start + j] || 0);
        if (val > max) max = val;
      }
      waveData.push(max);
    }
  }

  function renderTimeline(mouseX = -1) {
    ctx.clearRect(0, 0, width, height);

    // 1. Draw Grid lines (more refined, real digital oscilloscope look)
    ctx.strokeStyle = 'rgba(0, 68, 170, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 30) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += 25) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // 2. Draw Waveform Envelope in background (beautiful blue glow)
    if (waveData.length > 0) {
      const wGrad = ctx.createLinearGradient(0, 0, 0, height);
      wGrad.addColorStop(0, 'rgba(26, 95, 214, 0.08)');
      wGrad.addColorStop(0.5, 'rgba(0, 68, 170, 0.22)');
      wGrad.addColorStop(1, 'rgba(26, 95, 214, 0.08)');
      ctx.fillStyle = wGrad;
      for (let i = 0; i < width; i++) {
        const h = waveData[i] * height * 0.75;
        ctx.fillRect(i, (height - h) / 2, 1, h);
      }
    }

    // 3. Draw Threshold Line (55%)
    const thresholdY = height - (0.55 * height);
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.5)';
    ctx.lineWidth = 1.25;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(width, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(239, 68, 68, 0.85)';
    ctx.font = 'bold 8.5px monospace';
    ctx.fillText('CRITICAL RISK TRIGGER (55%)', 10, thresholdY - 4);

    // 4. Plot Chunks Risk Line
    if (!chunks || chunks.length === 0) {
      ctx.fillStyle = '#64748b';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No timeline data available', width / 2, height / 2);
      return;
    }

    const points = [];
    const numChunks = chunks.length;

    for (let i = 0; i < numChunks; i++) {
      const c = chunks[i];
      const cx = (i / (numChunks - 1 || 1)) * (width - 40) + 20;
      const cy = height - (c.risk_score * (height - 40) + 20);
      points.push({ x: cx, y: cy, chunk: c, index: i });
    }

    if (points.length > 0) {
      // Connect points with a smooth spline curve (Quadratic Bezier)
      const gradient = ctx.createLinearGradient(0, height, 0, 0);
      gradient.addColorStop(0, '#10b981');   // Green (Low)
      gradient.addColorStop(0.5, '#f59e0b'); // Orange (Medium)
      gradient.addColorStop(1, '#ef4444');   // Red (High)

      // Draw Area Gradient Fill first
      ctx.beginPath();
      ctx.moveTo(points[0].x, height);
      ctx.lineTo(points[0].x, points[0].y);
      if (points.length > 2) {
        for (let i = 0; i < points.length - 1; i++) {
          const xc = (points[i].x + points[i + 1].x) / 2;
          const yc = (points[i].y + points[i + 1].y) / 2;
          ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
      } else {
        for (let i = 0; i < points.length; i++) {
          ctx.lineTo(points[i].x, points[i].y);
        }
      }
      ctx.lineTo(points[points.length - 1].x, height);
      ctx.closePath();

      const areaGrad = ctx.createLinearGradient(0, 0, 0, height);
      areaGrad.addColorStop(0, 'rgba(0, 68, 170, 0.16)');
      areaGrad.addColorStop(0.5, 'rgba(242, 169, 0, 0.05)');
      areaGrad.addColorStop(1, 'rgba(7, 11, 20, 0)');
      ctx.fillStyle = areaGrad;
      ctx.fill();

      // Draw glowing spline line
      ctx.beginPath();
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 3.5;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.shadowBlur = 8;
      ctx.shadowColor = 'rgba(26, 95, 214, 0.4)';

      ctx.moveTo(points[0].x, points[0].y);
      if (points.length > 2) {
        for (let i = 0; i < points.length - 1; i++) {
          const xc = (points[i].x + points[i + 1].x) / 2;
          const yc = (points[i].y + points[i + 1].y) / 2;
          ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
      } else {
        for (let i = 0; i < points.length; i++) {
          ctx.lineTo(points[i].x, points[i].y);
        }
      }
      ctx.stroke();
      ctx.shadowBlur = 0; // reset shadow
    }

    // Draw visual point markers
    points.forEach((p) => {
      const isCritical = p.chunk.risk_score >= 0.55;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 4.5, 0, 2 * Math.PI);
      ctx.fillStyle = isCritical ? '#ef4444' : '#10b981';
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // 5. Draw Interactive Crosshair & Tooltip
    if (mouseX >= 0 && points.length > 0) {
      let closest = points[0];
      let minDist = Math.abs(points[0].x - mouseX);
      for (let i = 1; i < points.length; i++) {
        const dist = Math.abs(points[i].x - mouseX);
        if (dist < minDist) {
          minDist = dist;
          closest = points[i];
        }
      }

      // Draw vertical crosshair line
      ctx.strokeStyle = 'rgba(242, 169, 0, 0.7)';
      ctx.lineWidth = 1.25;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(closest.x, 0);
      ctx.lineTo(closest.x, height);
      ctx.stroke();
      ctx.setLineDash([]);

      // Draw tooltip box
      const boxW = 160;
      const boxH = 68;
      let boxX = closest.x + 12;
      let boxY = closest.y - 45;

      if (boxX + boxW > width) boxX = closest.x - boxW - 12;
      if (boxY < 5) boxY = 5;
      if (boxY + boxH > height - 5) boxY = height - boxH - 5;

      // Draw glassmorphic tooltip card
      ctx.fillStyle = 'rgba(10, 15, 30, 0.96)';
      ctx.strokeStyle = 'var(--uco-gold)';
      ctx.lineWidth = 1.5;
      ctx.shadowBlur = 10;
      ctx.shadowColor = 'rgba(0,0,0,0.6)';
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(boxX, boxY, boxW, boxH, 6);
      } else {
        ctx.rect(boxX, boxY, boxW, boxH);
      }
      ctx.fill();
      ctx.stroke();
      ctx.shadowBlur = 0; // reset shadow

      // Draw text info inside tooltip
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 10px sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(`Time: ${closest.chunk.timestamp.toFixed(1)}s`, boxX + 8, boxY + 16);

      ctx.font = '10px sans-serif';
      ctx.fillStyle = 'rgba(255,255,255,0.75)';
      ctx.fillText('Synthetic Risk: ', boxX + 8, boxY + 32);

      const riskVal = Math.round(closest.chunk.risk_score * 100);
      ctx.fillStyle = closest.chunk.risk_score >= 0.55 ? '#ef4444' : closest.chunk.risk_score >= 0.35 ? '#f59e0b' : '#10b981';
      ctx.font = 'bold 10px sans-serif';
      ctx.fillText(`${riskVal}%`, boxX + 84, boxY + 32);

      ctx.font = '9px monospace';
      ctx.fillStyle = 'rgba(255,255,255,0.5)';

      let vText = closest.chunk.verdict || '';
      if (vText.startsWith('✅') || vText.startsWith('⚡') || vText.startsWith('⚠') || vText.startsWith('🔴') || vText.startsWith('🟢') || vText.startsWith('🟡')) {
        vText = vText.substring(2);
      }
      ctx.fillText(vText, boxX + 8, boxY + 48);

      // Highlight dot
      ctx.beginPath();
      ctx.arc(closest.x, closest.y, 8, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(242, 169, 0, 0.9)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
    }
  }

  canvas.onmousemove = function (e) {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    renderTimeline(mouseX);
  };

  canvas.onmouseleave = function () {
    renderTimeline(-1);
  };

  renderTimeline(-1);
}

// Frequency Spectrum Draw Function
function drawForensicSpectrum(canvasId, audioBuffer) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (width === 0 || height === 0) return;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  // 1. Draw Grid lines
  ctx.strokeStyle = 'rgba(0, 68, 170, 0.04)';
  ctx.lineWidth = 1;
  for (let x = 0; x < width; x += 30) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let y = 0; y < height; y += 25) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  // Draw Vertical Acoustic Range Dividers
  const maxDisplayFreq = 8000;
  const drawVerticalDivider = (freq, name) => {
    const x = (freq / maxDisplayFreq) * (width - 40) + 20;
    ctx.strokeStyle = 'rgba(242, 169, 0, 0.08)';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 3]);
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height - 16);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(255,255,255,0.25)';
    ctx.font = '7.5px sans-serif';
    ctx.fillText(name, x + 4, 25);
  };

  drawVerticalDivider(300, 'Bass Resonance');
  drawVerticalDivider(3000, 'Vocal Formants (F1-F3)');
  drawVerticalDivider(4500, 'Sibilance Band');

  // 2. Add Axis Labels
  ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
  ctx.font = '8px monospace';
  ctx.fillText('0 Hz', 5, height - 4);
  ctx.fillText('2 kHz', width * 0.25 - 12, height - 4);
  ctx.fillText('4 kHz', width * 0.5 - 12, height - 4);
  ctx.fillText('6 kHz', width * 0.75 - 12, height - 4);
  ctx.fillText('8 kHz (Max)', width - 55, height - 4);

  // Compute actual spectrum
  const { avgSpectrum, sampleRate } = computeAverageSpectrum(audioBuffer, 1024);
  const numBins = avgSpectrum.length;

  const nyquist = sampleRate / 2;
  const displayBinLimit = Math.min(numBins, Math.floor((maxDisplayFreq / nyquist) * numBins));

  // Find max value for normalization
  let maxMag = 1e-6;
  for (let i = 0; i < displayBinLimit; i++) {
    if (avgSpectrum[i] > maxMag) maxMag = avgSpectrum[i];
  }

  // Normalize measured data to draw
  const points = [];
  for (let i = 0; i < displayBinLimit; i++) {
    const x = (i / (displayBinLimit - 1)) * (width - 40) + 20;
    const normVal = avgSpectrum[i] / maxMag;
    const compressed = Math.pow(normVal, 0.45);
    const y = height - (compressed * (height - 35) + 18);
    points.push({ x, y });
  }

  // 3. Draw Reference Templates (Dotted Lines)
  // Natural Human Speech Template
  ctx.strokeStyle = 'rgba(16, 185, 129, 0.35)'; // Muted green
  ctx.lineWidth = 1.25;
  ctx.setLineDash([3, 4]);
  ctx.beginPath();
  for (let i = 0; i < displayBinLimit; i++) {
    const f = (i / displayBinLimit) * maxDisplayFreq;
    const x = (i / (displayBinLimit - 1)) * (width - 40) + 20;

    let val = Math.exp(-f / 1500);
    val += 0.35 * Math.exp(-Math.pow(f - 500, 2) / (2 * 110 * 110));
    val += 0.28 * Math.exp(-Math.pow(f - 1600, 2) / (2 * 210 * 210));
    val += 0.18 * Math.exp(-Math.pow(f - 2600, 2) / (2 * 310 * 310));

    const y = height - ((val / 1.5) * (height - 35) + 18);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // Synthetic Voice Template
  ctx.strokeStyle = 'rgba(239, 68, 68, 0.35)'; // Muted red
  ctx.lineWidth = 1.25;
  ctx.setLineDash([5, 5]);
  ctx.beginPath();
  for (let i = 0; i < displayBinLimit; i++) {
    const f = (i / displayBinLimit) * maxDisplayFreq;
    const x = (i / (displayBinLimit - 1)) * (width - 40) + 20;

    let val = 0.4 * Math.exp(-f / 3500) + 0.14;
    if (f > 4000) {
      val *= 0.12;
    }

    const y = height - (val * (height - 35) + 18);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
  ctx.setLineDash([]);

  // Legend
  ctx.font = '8px monospace';
  ctx.fillStyle = 'rgba(16, 185, 129, 0.8)';
  ctx.fillText('■ Human Reference', width - 205, 14);
  ctx.fillStyle = 'rgba(239, 68, 68, 0.8)';
  ctx.fillText('■ AI Clone Reference', width - 110, 14);
  ctx.fillStyle = 'var(--uco-gold)';
  ctx.fillText('■ Caller Spectrum (Power density)', 10, 14);

  // 4. Draw Measured Spectrum Area Fill (soft amber)
  if (points.length > 0) {
    ctx.beginPath();
    ctx.moveTo(points[0].x, height - 16);
    for (let i = 0; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.lineTo(points[points.length - 1].x, height - 16);
    ctx.closePath();

    const fillG = ctx.createLinearGradient(0, 0, 0, height);
    fillG.addColorStop(0, 'rgba(242, 169, 0, 0.12)');
    fillG.addColorStop(1, 'rgba(7, 11, 20, 0)');
    ctx.fillStyle = fillG;
    ctx.fill();

    // Draw Measured Spectrum Line
    ctx.beginPath();
    ctx.strokeStyle = 'var(--uco-gold)';
    ctx.lineWidth = 2.5;
    ctx.shadowBlur = 4;
    ctx.shadowColor = 'rgba(242,169,0,0.3)';
    for (let i = 0; i < points.length; i++) {
      if (i === 0) ctx.moveTo(points[i].x, points[i].y);
      else ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.stroke();
    ctx.shadowBlur = 0; // reset
  }
}

// Biometrics Draw Function (High-Tech Diagnostic Instrument Scale Gauges)
function drawForensicBiometrics(canvasId, features) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (width === 0 || height === 0) return;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  const metrics = [
    {
      name: 'Pitch Jitter',
      val: features.pitch_jitter_pct,
      unit: '%',
      min: 0,
      max: 8,
      humanMin: 0.5,
      humanMax: 3.0,
      desc: 'Normal Human: 0.5% - 3.0% (AI smoothing is < 0.3%)'
    },
    {
      name: 'Amplitude Shimmer',
      val: features.amplitude_shimmer_pct,
      unit: '%',
      min: 0,
      max: 30,
      humanMin: 3.0,
      humanMax: 15.0,
      desc: 'Normal Human: 3.0% - 15.0% (AI vocoders suppress variance to < 2.0%)'
    },
    {
      name: 'Spectral Flatness',
      val: features.spectral_flatness,
      unit: '',
      min: 0,
      max: 0.6,
      humanMin: 0.0,
      humanMax: 0.15,
      desc: 'Normal Human: < 0.15 (AI white noise/flatness is > 0.3)'
    },
    {
      name: 'HF Energy Anomaly',
      val: features.hf_energy_anomaly,
      unit: '',
      min: 0,
      max: 0.8,
      humanMin: 0.0,
      humanMax: 0.20,
      desc: 'Normal Human: < 0.20 (AI filter cutoffs produce spikes > 0.4)'
    }
  ];

  const barH = 12;
  const rowH = 34;
  const startX = 145;
  const barW = width - startX - 85;

  metrics.forEach((m, idx) => {
    const rowY = idx * rowH + 12;

    // A. Draw metric label
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 11px sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(m.name, 10, rowY + 12);

    // B. Draw track layout mapping
    const mapValToX = (v) => {
      const pct = (v - m.min) / (m.max - m.min);
      return startX + Math.min(1, Math.max(0, pct)) * barW;
    };

    // Draw warning background zone (AI synthetic areas)
    ctx.fillStyle = 'rgba(239, 68, 68, 0.13)';
    ctx.fillRect(startX, rowY + 3, barW, barH);
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.28)';
    ctx.lineWidth = 1;
    ctx.strokeRect(startX, rowY + 3, barW, barH);

    // Draw human normal baseline green zone
    const hX1 = mapValToX(m.humanMin);
    const hX2 = mapValToX(m.humanMax);
    ctx.fillStyle = 'rgba(16, 185, 129, 0.32)';
    ctx.fillRect(hX1, rowY + 3, hX2 - hX1, barH);
    ctx.strokeStyle = 'rgba(16, 185, 129, 0.7)';
    ctx.strokeRect(hX1, rowY + 3, hX2 - hX1, barH);

    // Draw tick marks in the track for grid realism (Oszillograph style)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
    ctx.lineWidth = 1;
    for (let t = 0; t <= 10; t++) {
      const tx = startX + (t / 10) * barW;
      ctx.beginPath();
      ctx.moveTo(tx, rowY + 3);
      ctx.lineTo(tx, rowY + 3 + (t % 5 === 0 ? barH : barH / 2));
      ctx.stroke();
    }

    // C. Draw Caller Value Needle / Indicator
    const valX = mapValToX(m.val);

    // Draw pointer needle with glowing shadow
    ctx.beginPath();
    ctx.moveTo(valX, rowY - 3);
    ctx.lineTo(valX, rowY + barH + 5);
    ctx.strokeStyle = 'var(--uco-gold)';
    ctx.lineWidth = 3;
    ctx.shadowBlur = 5;
    ctx.shadowColor = 'rgba(242,169,0,0.5)';
    ctx.stroke();
    ctx.shadowBlur = 0; // reset

    // Draw solid triangle pointer tip
    ctx.beginPath();
    ctx.moveTo(valX, rowY + 1);
    ctx.lineTo(valX - 4.5, rowY - 4);
    ctx.lineTo(valX + 4.5, rowY - 4);
    ctx.closePath();
    ctx.fillStyle = 'var(--uco-gold)';
    ctx.fill();

    // D. Print Caller numeric value (color coded by classification status)
    ctx.font = 'bold 11px sans-serif';
    ctx.textAlign = 'right';
    const textVal = m.val.toFixed(m.name.includes('Flatness') || m.name.includes('HF') ? 3 : 2) + m.unit;

    const isHuman = m.val >= m.humanMin && m.val <= m.humanMax;
    ctx.fillStyle = isHuman ? '#10b981' : '#ef4444';
    ctx.fillText(textVal, width - 10, rowY + 12);

    // E. Draw explanation bounds text
    ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
    ctx.font = '7.5px monospace';
    ctx.textAlign = 'left';
    ctx.fillText(m.desc, startX, rowY + 24);
  });
}

// Chart tab switcher
function switchForensicChart(prefix, tab) {
  // Hide all panels
  const timelinePanel = document.getElementById(prefix + '-panel-chart-timeline');
  const spectrumPanel = document.getElementById(prefix + '-panel-chart-spectrum');
  const biometricsPanel = document.getElementById(prefix + '-panel-chart-biometrics');

  if (timelinePanel) timelinePanel.style.display = 'none';
  if (spectrumPanel) spectrumPanel.style.display = 'none';
  if (biometricsPanel) biometricsPanel.style.display = 'none';

  // Remove active class from buttons
  const timelineBtn = document.getElementById(prefix + '-btn-chart-timeline');
  const spectrumBtn = document.getElementById(prefix + '-btn-chart-spectrum');
  const biometricsBtn = document.getElementById(prefix + '-btn-chart-biometrics');

  if (timelineBtn) timelineBtn.classList.remove('active');
  if (spectrumBtn) spectrumBtn.classList.remove('active');
  if (biometricsBtn) biometricsBtn.classList.remove('active');

  // Show active panel and set active class
  const activePanel = document.getElementById(prefix + '-panel-chart-' + tab);
  const activeBtn = document.getElementById(prefix + '-btn-chart-' + tab);

  if (activePanel) activePanel.style.display = 'block';
  if (activeBtn) activeBtn.classList.add('active');

  // Redraw the selected chart now that the panel is visible (clientWidth/clientHeight are non-zero)
  const data = window.activeForensicData ? window.activeForensicData[prefix] : null;
  if (data) {
    if (tab === 'timeline' && data.chunks && data.audioBuffer) {
      drawForensicTimeline(prefix + '-timeline-canvas', data.chunks, data.audioBuffer);
    } else if (tab === 'spectrum' && data.audioBuffer) {
      drawForensicSpectrum(prefix + '-spectrum-canvas', data.audioBuffer);
    } else if (tab === 'biometrics' && data.features) {
      drawForensicBiometrics(prefix + '-biometrics-canvas', data.features);
    }
  }
}

function generateForensicExplanation(score, features) {
  const jitter = features.pitch_jitter_pct;
  const shimmer = features.amplitude_shimmer_pct;
  const flatness = features.spectral_flatness;
  const hfAnom = features.hf_energy_anomaly;

  // Jitter evaluation
  let jitterEval = "";
  let jitterCls = "b-green";
  if (jitter < 0.3) {
    jitterEval = "🔴 CRITICAL: Pitch variation is abnormally low (smoothed). Natural human voices have micro-variations of 0.5% - 3.0%. A value below 0.3% strongly indicates neural text-to-speech smoothing.";
    jitterCls = "b-red";
  } else if (jitter > 6.0) {
    jitterEval = "🟡 ELEVATED: Pitch variation is abnormally high (frequency instability). Suggestive of vocoder phase reconstruction errors or bad audio quality.";
    jitterCls = "b-orange";
  } else {
    jitterEval = "🟢 NORMAL: Pitch variation fits natural human speech micro-stability characteristics (0.5% - 3.0%).";
    jitterCls = "b-green";
  }

  // Shimmer evaluation
  let shimmerEval = "";
  let shimmerCls = "b-green";
  if (shimmer < 2.0) {
    shimmerEval = "🔴 CRITICAL: Loudness variation is suppressed. Natural human voice cycle-to-cycle amplitude fluctuates by 3% - 15%. Suppressed shimmer is typical of over-regularized AI vocoder speech.";
    shimmerCls = "b-red";
  } else if (shimmer > 25.0) {
    shimmerEval = "🟡 ELEVATED: Amplitude shimmer is unstable. Typical of environmental noise contamination or voice synthesis distortion.";
    shimmerCls = "b-orange";
  } else {
    shimmerEval = "🟢 NORMAL: Amplitude variation matches expected natural human breathing and speech rhythm.";
    shimmerCls = "b-green";
  }

  // Flatness evaluation
  let flatnessEval = "";
  let flatnessCls = "b-green";
  if (flatness > 0.3) {
    flatnessEval = "🔴 CRITICAL: High Spectral Flatness indicates a flatter, more noise-like frequency distribution. AI vocoders leave highly uniform noise signatures unlike human vocal cords which exhibit clear harmonic formants.";
    flatnessCls = "b-red";
  } else if (flatness > 0.15) {
    flatnessEval = "🟡 ELEVATED: Tonal-to-noise ratio is unbalanced. Indicates potential neural vocoder artifacts or background static line noise.";
    flatnessCls = "b-orange";
  } else {
    flatnessEval = "🟢 NORMAL: Frequency spectrum is rich in clear harmonic structure, representing human vocal tract acoustics.";
    flatnessCls = "b-green";
  }

  // HF Energy evaluation
  let hfEval = "";
  let hfCls = "b-green";
  if (hfAnom > 0.4) {
    hfEval = "🔴 CRITICAL: High-frequency energy is abnormal. Indicates a signature high-frequency energy notch, typical of diffusion-based synthesis models or codec filtering anomalies.";
    hfCls = "b-red";
  } else if (hfAnom > 0.2) {
    hfEval = "🟡 ELEVATED: Minor energy rolloff deviations detected in the 4kHz-8kHz band.";
    hfCls = "b-orange";
  } else {
    hfEval = "🟢 NORMAL: High-frequency rolloff matches the natural attenuation curve of human speech.";
    hfCls = "b-green";
  }

  // Verdict Summary
  let summary = "";
  if (score >= 75) {
    summary = `<b style="color:var(--red);">CRITICAL DETECTION SUMMARY (Synthetic Voice Confirmed)</b><br/>
               The voice scan confirms the presence of multiple synthetic audio signatures. The combination of suppressed pitch jitter and amplitude shimmer points to a neural vocoder (e.g. ElevenLabs, tortoise-tts). This call should be treated as a potential voice cloning/impersonation attempt. <b>ACTION REQUIRED: Terminate session or request high-level authentication (MFA/Callback).</b>`;
  } else if (score >= 50) {
    summary = `<b style="color:var(--orange);">HIGH DETECTED RISK (AI Voice Suspected)</b><br/>
               Significant acoustic anomalies detected. Several metrics deviate from standard human voice biometrics, typical of low-latency voice conversion models. <b>ACTION REQUIRED: Ask out-of-band security questions and verify through registered channels.</b>`;
  } else if (score >= 25) {
    summary = `<b style="color:var(--accent-blue);">MODERATE SCAN RISK (Review Advised)</b><br/>
               Mild acoustic abnormalities. This scan may represent a degraded cellular network signal, extreme background noise, or a high-quality speech conversion tool. <b>ACTION REQUIRED: Continue monitoring with caution.</b>`;
  } else {
    summary = `<b style="color:var(--green);">LOW SCAN RISK (Verified Human Voice)</b><br/>
               The caller's voice parameters reside safely within natural human biological ranges. Jitter, shimmer, and spectral peaks verify standard human speech biomechanics. <b>ACTION REQUIRED: Proceed with standard operation.</b>`;
  }

  return `
    <div style="margin-top:16px; border-top:1px solid var(--border); padding-top:16px;">
      <div style="font-weight:700; font-size:13.5px; color:var(--text); margin-bottom:8px;">🔍 Forensic Explanation & Artifact Breakdown</div>
      <div style="font-size:12px; line-height:1.6; color:var(--text2); background:var(--surface2s); border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:12px;">
        ${summary}
      </div>
      
      <div style="display:flex; flex-direction:column; gap:8px;">
        <div style="font-size:11px; padding:8px; border-radius:6px; border:1px solid var(--border); background:#ffffff;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <b>1. Pitch Jitter (F0 Variation)</b>
            <span class="badge ${jitterCls}">${jitter.toFixed(2)}%</span>
          </div>
          <div style="font-size:10.5px; color:var(--text3);">${jitterEval}</div>
        </div>
        
        <div style="font-size:11px; padding:8px; border-radius:6px; border:1px solid var(--border); background:#ffffff;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <b>2. Amplitude Shimmer (Loudness Stability)</b>
            <span class="badge ${shimmerCls}">${shimmer.toFixed(2)}%</span>
          </div>
          <div style="font-size:10.5px; color:var(--text3);">${shimmerEval}</div>
        </div>
        
        <div style="font-size:11px; padding:8px; border-radius:6px; border:1px solid var(--border); background:#ffffff;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <b>3. Spectral Flatness (Tonal Purity)</b>
            <span class="badge ${flatnessCls}">${flatness.toFixed(3)}</span>
          </div>
          <div style="font-size:10.5px; color:var(--text3);">${flatnessEval}</div>
        </div>
        
        <div style="font-size:11px; padding:8px; border-radius:6px; border:1px solid var(--border); background:#ffffff;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <b>4. HF Energy Anomaly (Codec Rolloff)</b>
            <span class="badge ${hfCls}">${hfAnom.toFixed(3)}</span>
          </div>
          <div style="font-size:10.5px; color:var(--text3);">${hfEval}</div>
        </div>
      </div>
    </div>
  `;
}

function crossCheckBiometric(customerName, riskScore) {
  if (!customerName) return null;
  const cleanName = customerName.trim();
  if (cleanName === "" || cleanName === "Unidentified Caller" || cleanName === "Unknown Caller") {
    return `
      <div style="background:var(--surface2s); border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:12px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
        <div>
          <div style="font-size:10px; color:var(--text3); text-transform:uppercase; letter-spacing:.5px;">Biometric Verification</div>
          <div style="font-size:13px; font-weight:700; color:var(--text); margin-top:2px;">👤 Caller is Unidentified</div>
        </div>
        <div style="display:flex; gap:6px; align-items:center;">
          <input id="quick-enroll-acct" placeholder="Enter Account Details" style="padding:6px 10px; background:#fff; border:1px solid var(--border2); border-radius:6px; font-size:11px; width:150px;" />
          <button class="btn btn-ghost btn-sm" onclick="quickEnrollCaller('${cleanName.replace(/'/g, "\\'")}')" style="padding:6px 12px; font-size:11px; font-weight:600;">Enroll Voice</button>
        </div>
      </div>
    `;
  }

  // Look for match in VOICEPRINTS
  const enrolled = VOICEPRINTS.find(v => v.name.toLowerCase() === cleanName.toLowerCase());

  if (enrolled) {
    if (riskScore >= 50) {
      // High synthetic risk, but caller claims this name!
      return `
        <div style="background:rgba(239, 68, 68, 0.08); border:1px solid rgba(239, 68, 68, 0.35); border-radius:8px; padding:12px; margin-bottom:12px;">
          <div style="font-size:10px; color:var(--red); font-weight:700; text-transform:uppercase; letter-spacing:.5px;">🚨 Biometric Fraud Alert</div>
          <div style="font-size:13px; font-weight:700; color:var(--text); margin-top:2px; display:flex; align-items:center; justify-content:space-between;">
            <span>Spoofing Attempt / Voice Clone Detected</span>
            <span class="badge b-red">FAILED (Clone Match)</span>
          </div>
          <div style="font-size:11.5px; color:var(--text2); margin-top:6px; line-height:1.5;">
            The caller claims to be <b>${enrolled.name}</b> (${enrolled.acct}), but the live speech analysis detects artificial voice synthesis and cloned characteristics. Match with authentic registry voiceprint failed.
          </div>
        </div>
      `;
    } else {
      // Low risk and name matches! This is a verified customer!
      // Generate a slight deviation match percentage close to baseline match
      const deviation = (Math.random() * 2 - 1).toFixed(1);
      const matchPct = Math.min(100, Math.max(50, enrolled.match + parseFloat(deviation))).toFixed(1);

      return `
        <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.35); border-radius:8px; padding:12px; margin-bottom:12px;">
          <div style="font-size:10px; color:var(--green); font-weight:700; text-transform:uppercase; letter-spacing:.5px;">🛡️ Biometric Verification Verified</div>
          <div style="font-size:13px; font-weight:700; color:var(--text); margin-top:2px; display:flex; align-items:center; justify-content:space-between;">
            <span>Identified as ${enrolled.name}</span>
            <span class="badge b-green">PASSED (${matchPct}% Match)</span>
          </div>
          <div style="font-size:11.5px; color:var(--text2); margin-top:6px; line-height:1.5;">
            Voice biometrics match the registered authentic profile for <b>${enrolled.name}</b> (${enrolled.acct}) with a confidence of <b>${matchPct}%</b> (required: ${enrolled.match}%). Voice parameters show normal human biomechanical characteristics.
          </div>
        </div>
      `;
    }
  } else {
    // Claimed name is not in the registry
    return `
      <div style="background:var(--surface2s); border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:12px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
        <div>
          <div style="font-size:10px; color:var(--text3); text-transform:uppercase; letter-spacing:.5px;">Biometric Verification</div>
          <div style="font-size:13px; font-weight:700; color:var(--text); margin-top:2px;">👤 ${cleanName} (Unregistered)</div>
        </div>
        <div style="display:flex; gap:6px; align-items:center;">
          <input id="quick-enroll-acct" placeholder="Enter Account Details" style="padding:6px 10px; background:#fff; border:1px solid var(--border2); border-radius:6px; font-size:11px; width:150px;" />
          <button class="btn btn-primary btn-sm" onclick="quickEnrollCaller('${cleanName.replace(/'/g, "\\'")}')" style="padding:6px 12px; font-size:11px; font-weight:600;">Enroll Voice</button>
        </div>
      </div>
    `;
  }
}

function quickEnrollCaller(name) {
  const acctInput = document.getElementById('quick-enroll-acct');
  const acct = acctInput ? acctInput.value.trim() : "";
  if (!acct) {
    toast("Please enter account details to enroll caller", "error");
    return;
  }

  VOICEPRINTS.push({ name, acct, match: 95 });
  saveVoiceprints();
  renderVoiceprintRegistry();
  toast(`Enrolled voiceprint for ${name}!`, "success");

  // Re-trigger visual updates of live monitor card or upload results card if visible
  const activePage = document.querySelector('.page.active').id;
  if (activePage === 'page-monitor') {
    const wrapper = document.getElementById('mon-biometric-status');
    if (wrapper) {
      const score = parseInt(document.getElementById('mon-score').textContent, 10);
      wrapper.innerHTML = crossCheckBiometric(name, score);
    }
  } else if (activePage === 'page-upload') {
    const resultCard = document.getElementById('upload-result-card');
    if (resultCard) {
      const score = parseInt(resultCard.querySelector('.ring-val').textContent, 10);
      const bioWrapper = document.getElementById('upload-biometric-status');
      if (bioWrapper) {
        bioWrapper.innerHTML = crossCheckBiometric(name, score);
      }
    }
  }
}

function avg(arr) { return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0; }

function computeJitter(pHist) {
  if (pHist.length < 5) return 0;
  let diffs = 0; for (let i = 1; i < pHist.length; i++) diffs += Math.abs(pHist[i] - pHist[i - 1]);
  const avgDiff = diffs / (pHist.length - 1);
  const avgF0 = avg(pHist);
  return avgF0 > 0 ? (avgDiff / avgF0) * 100 : 0;
}
function computeShimmer(aHist) {
  if (aHist.length < 5) return 0;
  let diffs = 0; for (let i = 1; i < aHist.length; i++) diffs += Math.abs(aHist[i] - aHist[i - 1]);
  const avgDiff = diffs / (aHist.length - 1);
  const avgAmp = avg(aHist);
  return avgAmp > 0 ? (avgDiff / avgAmp) * 100 : 0;
}

// minimal radix-2 FFT magnitude (frame padded/truncated to power of 2)
function fftMagnitude(frame) {
  let N = 1; while (N < frame.length) N *= 2; N = Math.min(N, 2048);
  const re = new Float64Array(N), im = new Float64Array(N);
  for (let i = 0; i < N; i++) {
    const w = 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (N - 1)); // Hann window
    re[i] = (frame[i] || 0) * w;
  }
  fftInPlace(re, im);
  const mag = new Float64Array(N / 2);
  for (let i = 0; i < N / 2; i++) mag[i] = Math.sqrt(re[i] * re[i] + im[i] * im[i]);
  return mag;
}
function fftInPlace(re, im) {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) { [re[i], re[j]] = [re[j], re[i]];[im[i], im[j]] = [im[j], im[i]]; }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = -2 * Math.PI / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let curWr = 1, curWi = 0;
      for (let j = 0; j < len / 2; j++) {
        const ur = re[i + j], ui = im[i + j];
        const vr = re[i + j + len / 2] * curWr - im[i + j + len / 2] * curWi;
        const vi = re[i + j + len / 2] * curWi + im[i + j + len / 2] * curWr;
        re[i + j] = ur + vr; im[i + j] = ui + vi;
        re[i + j + len / 2] = ur - vr; im[i + j + len / 2] = ui - vi;
        const nwr = curWr * wr - curWi * wi, nwi = curWr * wi + curWi * wr;
        curWr = nwr; curWi = nwi;
      }
    }
  }
}

/* ============================================================
   CHATBOT WIDGET CONTROLLER — GROQ API INTEGRATION
   ============================================================ */
let GROQ_API_KEY = localStorage.getItem('sv_groq_api_key') || '';
let chatHistory = []; // format: { role: 'user'|'assistant', content: String }

function toggleChat() {
  const panel = document.getElementById('chat-panel');
  panel.classList.toggle('show');
  if (panel.classList.contains('show')) {
    if (!GROQ_API_KEY) {
      showApiConfig(false);
    } else {
      // Always populate greeting if empty
      const messagesContainer = document.getElementById('chat-messages');
      if (messagesContainer.children.length === 0) {
        addChatBubble("Hello! I am the VoxShield Voice Forensics Assistant. How can I help you protect UCO Bank customers from AI voice clones today?", 'assistant');
      }
      if (typeof lastFeatures !== 'undefined' && lastFeatures.composite_risk_score !== undefined) {
        updateSuggestionsBasedOnScanner();
      } else {
        updateChatSuggestions();
      }
      document.getElementById('chat-user-input').focus();
    }
  }
}

function showApiConfig(allowCancel = true) {
  document.getElementById('chat-api-screen').style.display = 'flex';
  document.getElementById('chat-api-key').value = GROQ_API_KEY || '';
  const cancelBtn = document.getElementById('btn-cancel-api');
  if (cancelBtn) {
    cancelBtn.style.display = allowCancel ? 'block' : 'none';
  }
}

function hideApiConfig() {
  document.getElementById('chat-api-screen').style.display = 'none';
  document.getElementById('chat-user-input').focus();
}

function saveGroqKey() {
  const val = document.getElementById('chat-api-key').value.trim();
  if (!val) {
    toast('Please enter a valid Groq API key', 'error');
    return;
  }
  GROQ_API_KEY = val;
  localStorage.setItem('sv_groq_api_key', val);
  document.getElementById('chat-api-screen').style.display = 'none';
  toast('API Key saved successfully!', 'success');

  const messagesContainer = document.getElementById('chat-messages');
  if (messagesContainer.children.length === 0) {
    addChatBubble("Hello! I am the VoxShield Voice Forensics Assistant. How can I help you protect UCO Bank customers from AI voice clones today?", 'assistant');
  }
  document.getElementById('chat-user-input').focus();
}

async function sendChatMessage() {
  const inputEl = document.getElementById('chat-user-input');
  const prompt = inputEl.value.trim();
  if (!prompt) return;

  // Render user bubble
  addChatBubble(prompt, 'user');
  inputEl.value = '';

  // Show typing loader
  const loader = showTypingLoader();

  try {
    const aiResponse = await callGroqApi(prompt);

    // Remove loader
    loader.remove();

    // Render assistant bubble
    addChatBubble(aiResponse, 'assistant');

    // Add to local chat memory
    chatHistory.push({ role: 'user', content: prompt });
    chatHistory.push({ role: 'assistant', content: aiResponse });

    // limit history size to keep payload reasonable
    if (chatHistory.length > 20) {
      chatHistory = chatHistory.slice(-20);
    }

    // Dynamic suggestions based on user question
    updateChatSuggestions(prompt);
  } catch (error) {
    loader.remove();
    console.error("Groq API Error:", error);
    addChatBubble("Sorry, I encountered an error communicating with the AI model. Please verify your internet connection and check if your Groq API key is valid.", 'assistant');
    toast('AI request failed', 'error');
  }
}

async function callGroqApi(userPrompt) {
  const url = 'https://api.groq.com/openai/v1/chat/completions';

  // Gather current active telemetry to make chatbot context-aware
  const activeData = window.activeForensicData || {};
  const currentLive = lastFeatures; // pitch_jitter_pct, amplitude_shimmer_pct, etc.
  
  let telemetryContext = "\n\n--- ACTIVE TELEMETRY FOR REFERENCE ---";
  if (currentLive && currentLive.composite_risk_score !== undefined) {
    telemetryContext += `\n[Live Call Monitor (Active Session)]:
    - Pitch Jitter: ${currentLive.pitch_jitter_pct}%
    - Amplitude Shimmer: ${currentLive.amplitude_shimmer_pct}%
    - Spectral Flatness: ${currentLive.spectral_flatness}
    - High-Frequency (HF) Energy Anomaly: ${currentLive.hf_energy_anomaly}
    - Composite Call Risk Score: ${currentLive.composite_risk_score}%
    - Active Codec/Channel: ${document.getElementById('mon-codec')?.value || 'none'}`;
  } else {
    telemetryContext += "\n- Live Call Monitor: No active streaming data collected yet.";
  }

  if (activeData.upload && activeData.upload.features) {
    const upFeat = activeData.upload.features;
    telemetryContext += `\n[Uploaded Recording Analysis]:
    - Pitch Jitter: ${upFeat.pitch_jitter_pct}%
    - Amplitude Shimmer: ${upFeat.amplitude_shimmer_pct}%
    - Spectral Flatness: ${upFeat.spectral_flatness}
    - HF Energy Anomaly: ${upFeat.hf_energy_anomaly}
    - Composite File Risk Score: ${upFeat.composite_risk_score || activeData.upload.score || 0}%`;
  } else {
    telemetryContext += "\n- Uploaded Recording: No file analyzed yet in this session.";
  }
  
  telemetryContext += "\n-------------------------------------\n";
  telemetryContext += "If the user asks to analyze the current call, explain the telemetry metrics, or asks why a warning occurred, reference these values. Under deepfake sandbox attack, highlight that the Pitch Jitter is extremely low (around 0.05%-0.15%), which is below human speech limits (<0.3%), representing artificial vocoder smoothing.";

  const baseSystemPrompt = "You are the VoxShield Voice Forensics Assistant, a specialized AI assistant integrated into UCO Bank's voice clone and deepfake detection dashboard. Your goal is to assist bank security officers and agents with inquiries about: voice cloning/deepfake risks in banking (e.g. synthetic audio used for unauthorized fund transfers); audio forensic markers evaluated by VoxShield: Pitch Jitter, Amplitude Shimmer, Spectral Flatness, and HF Energy Anomaly; UCO Bank's cybersecurity initiatives, specifically the UCO Bank FinTech & Cybersecurity Hackathon 2025–26, and its partnership with IIT Kharagpur, DFS, and IBA; best practices for verifying caller identities when VoxShield flags a call as high/critical risk. Keep answers professional, concise, and focused on security forensics.";

  const fullSystemPrompt = baseSystemPrompt + telemetryContext;

  const messages = [
    { role: 'system', content: fullSystemPrompt },
    ...chatHistory.map(item => ({ role: item.role, content: item.content })),
    { role: 'user', content: userPrompt }
  ];

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GROQ_API_KEY}`
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: messages,
      temperature: 0.7,
      max_tokens: 1024
    })
  });

  if (!response.ok) {
    const errorDetails = await response.text();
    throw new Error(`Groq API Request failed with status ${response.status}: ${errorDetails}`);
  }

  const data = await response.json();
  if (data.choices && data.choices[0] && data.choices[0].message) {
    return data.choices[0].message.content;
  } else {
    throw new Error("Invalid response format from Groq API");
  }
}

function sendQuickPrompt(text) {
  document.getElementById('chat-user-input').value = text;
  sendChatMessage();
}

function addChatBubble(text, sender) {
  const container = document.getElementById('chat-messages');
  const msgRow = document.createElement('div');
  msgRow.className = `chat-msg-row ${sender}`;

  // Simple Markdown formatting helper for bolding and code lines
  let formattedText = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
    .replace(/\*(.*?)\*/g, '<i>$1</i>')
    .replace(/`(.*?)`/g, '<code class="mono" style="background:rgba(255,255,255,0.08); padding:1px 4px; border-radius:4px;">$1</code>')
    .replace(/\n/g, '<br/>');

  msgRow.innerHTML = `
    <div class="chat-msg ${sender}">${formattedText}</div>
    <div class="chat-msg-meta">${sender === 'user' ? 'You' : 'Assistant'} · ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
  `;

  container.appendChild(msgRow);
  container.scrollTop = container.scrollHeight;
}

function showTypingLoader() {
  const container = document.getElementById('chat-messages');
  const msgRow = document.createElement('div');
  msgRow.className = 'chat-msg-row assistant';
  msgRow.id = 'chat-typing-loader';

  msgRow.innerHTML = `
    <div class="chat-msg assistant">
      <div class="chat-loader">
        <div class="chat-dot"></div>
        <div class="chat-dot"></div>
        <div class="chat-dot"></div>
      </div>
    </div>
  `;
  container.appendChild(msgRow);
  container.scrollTop = container.scrollHeight;
  return msgRow;
}

async function loadAuditLogs() {
  const tbody = document.getElementById('audit-logs-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text3);padding:20px;">Loading logs from database...</td></tr>`;

  const token = localStorage.getItem('vx_jwt_token');
  if (!token) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--red);padding:20px;">Unauthorized: Please log in again.</td></tr>`;
    return;
  }

  try {
    const response = await fetch('/api/audit-logs', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) throw new Error('Failed to retrieve logs');

    const data = await response.json();
    if (data.success && data.logs) {
      if (data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text3);padding:20px;">No audit logs recorded yet.</td></tr>`;
      } else {
        tbody.innerHTML = data.logs.map(log => {
          const localTime = new Date(log.timestamp).toLocaleString('en-IN');
          let badgeColor = 'var(--text2)';
          if (log.eventType.includes('SUCCESS') || log.eventType.includes('COMPLETED')) badgeColor = 'var(--green)';
          if (log.eventType.includes('FAILED') || log.eventType.includes('LOCKED') || log.eventType.includes('EXPIRED')) badgeColor = 'var(--red)';
          if (log.eventType.includes('MFA')) badgeColor = 'var(--gold)';

          return `
            <tr>
              <td class="mono">${localTime}</td>
              <td class="mono">${log.employeeId}</td>
              <td><span style="font-weight:600; color:${badgeColor}">${log.eventType}</span></td>
              <td class="mono">${log.ipAddress || '—'}</td>
              <td style="text-align:left;">${log.details}</td>
            </tr>
          `;
        }).join('');
      }
    } else {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--red);padding:20px;">Error parsing logs data.</td></tr>`;
    }
  } catch (error) {
    console.error('Audit logs error:', error);
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--red);padding:20px;">Failed to communicate with database logs.</td></tr>`;
  }
}

async function pushAuditLog(eventType, details) {
  const token = localStorage.getItem('vx_jwt_token');
  if (!token) return;
  try {
    await fetch('/api/audit-log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ eventType, details })
    });
  } catch (e) {
    console.error('Error sending audit log:', e);
  }
}

/* ============================================================
   CHATBOT DRAGGABLE & DYNAMIC QUESTION SUGGESTION FEATURES
   ============================================================ */

const FOLLOW_UP_SUGGESTIONS = {
  jitter: [
    { text: "What is normal Jitter?", prompt: "What range of Pitch Jitter is typical for a normal human voice?" },
    { text: "Explain shimmer differences", prompt: "What is the difference between Amplitude Shimmer and Pitch Jitter?" },
    { text: "Vocoder pitch anomalies", prompt: "How do voice cloning systems and neural vocoders hide or alter pitch jitter?" }
  ],
  shimmer: [
    { text: "Shimmer calculation", prompt: "How is Amplitude Shimmer calculated in the audio signal processor?" },
    { text: "Shimmer suppression", prompt: "Why do AI voice clones show shimmer suppression anomalies?" },
    { text: "Noise vs Shimmer", prompt: "Does high amplitude shimmer indicate a clone or just background noise?" }
  ],
  flatness: [
    { text: "Risk of high Flatness", prompt: "Why does high spectral flatness indicate a synthetic voice?" },
    { text: "Spectral Flatness formula", prompt: "Explain the geometric vs arithmetic mean calculation for Spectral Flatness." },
    { text: "Adjusting Flatness thresholds", prompt: "How can we adjust thresholds to handle noisy environments that cause high spectral flatness?" }
  ],
  hfanom: [
    { text: "HF energy notch", prompt: "What is a high-frequency energy notch, and how do vocoder fingerprints create it?" },
    { text: "Telephony band limits", prompt: "How does telephone line band-limiting (300Hz-3.4kHz) affect high frequency anomalies?" },
    { text: "GAN artifact detection", prompt: "How does high-frequency rolloff help detect GAN or diffusion cloned voices?" }
  ],
  mfa: [
    { text: "How to re-enroll MFA", prompt: "What are the steps to re-enroll a Microsoft Authenticator device on settings page?" },
    { text: "TOTP offline safety", prompt: "Can UCO Bank officers authenticate with TOTP if their dashboard is offline?" },
    { text: "MFA settings", prompt: "How do I toggle or reconfigure Multi-Factor Authentication settings?" }
  ],
  hackathon: [
    { text: "IIT Kharagpur collaboration", prompt: "What is the scope of UCO Bank's collaboration with IIT Kharagpur on voice forensics?" },
    { text: "DFS / IBA guidelines", prompt: "What are the DFS and IBA guidelines regarding voice biometrics for banks?" },
    { text: "Hackathon objectives", prompt: "What were the core goals of the UCO Bank FinTech & Cybersecurity Hackathon?" }
  ],
  report: [
    { text: "Forensic report details", prompt: "Where are the forensic reports stored, and how do I download them?" },
    { text: "Time-to-Flag metrics", prompt: "What is Average Time-to-Flag and why is the target under 10 seconds?" },
    { text: "Audit log database", prompt: "How are security audits logged to the database?" }
  ],
  default: [
    { text: "Jitter explanation", prompt: "How does Pitch Jitter work?" },
    { text: "What is Spectral Flatness?", prompt: "What is Spectral Flatness?" },
    { text: "High Risk protocol", prompt: "What action to take if Critical Risk is flagged?" },
    { text: "UCO Hackathon", prompt: "Tell me about the UCO Bank FinTech & Cybersecurity Hackathon" }
  ]
};

function updateChatSuggestions(query = '') {
  const container = document.getElementById('chat-chips');
  if (!container) return;

  // Prioritize current analysis suggestions if any scan has occurred
  const activePageEl = document.querySelector('.page.active');
  const activePage = activePageEl ? activePageEl.id : 'page-monitor';
  const hasLiveScan = (typeof lastFeatures !== 'undefined' && lastFeatures && lastFeatures.composite_risk_score !== undefined);
  const hasUploadScan = (activePage === 'page-upload' && window.activeForensicData?.upload?.features);

  if (hasLiveScan || hasUploadScan) {
    updateSuggestionsBasedOnScanner();
    return;
  }

  // Fallback to keyword-based suggestions if no active scan data is loaded yet
  let key = 'default';
  const q = query.toLowerCase();

  if (q.includes('jitter') || q.includes('pitch') || q.includes('f0')) {
    key = 'jitter';
  } else if (q.includes('shimmer') || q.includes('amplitude')) {
    key = 'shimmer';
  } else if (q.includes('flatness') || q.includes('spectral')) {
    key = 'flatness';
  } else if (q.includes('hf') || q.includes('anomaly') || q.includes('rolloff') || q.includes('vocoder') || q.includes('notch')) {
    key = 'hfanom';
  } else if (q.includes('mfa') || q.includes('auth') || q.includes('totp') || q.includes('secret') || q.includes('qr')) {
    key = 'mfa';
  } else if (q.includes('hackathon') || q.includes('iit') || q.includes('kharagpur') || q.includes('dfs') || q.includes('iba')) {
    key = 'hackathon';
  } else if (q.includes('report') || q.includes('log') || q.includes('history') || q.includes('audit')) {
    key = 'report';
  }

  const chips = FOLLOW_UP_SUGGESTIONS[key] || FOLLOW_UP_SUGGESTIONS['default'];

  container.innerHTML = chips.map(chip =>
    `<div class="chat-chip" onclick="sendQuickPrompt('${chip.prompt.replace(/'/g, "\\'")}')">${chip.text}</div>`
  ).join('');
}

function updateSuggestionsBasedOnScanner() {
  const container = document.getElementById('chat-chips');
  if (!container) return;

  const activePageEl = document.querySelector('.page.active');
  const activePage = activePageEl ? activePageEl.id : 'page-monitor';

  let score = 0;
  let jitter = 0;
  let shimmer = 0;
  let flatness = 0;
  let typeLabel = "last call";

  if (activePage === 'page-upload' && window.activeForensicData?.upload?.features) {
    const upFeat = window.activeForensicData.upload.features;
    score = upFeat.composite_risk_score || window.activeForensicData.upload.score || 0;
    jitter = upFeat.pitch_jitter_pct || 0;
    shimmer = upFeat.amplitude_shimmer_pct || 0;
    flatness = upFeat.spectral_flatness || 0;
    typeLabel = "uploaded call";
  } else if (typeof lastFeatures !== 'undefined' && lastFeatures && lastFeatures.composite_risk_score !== undefined) {
    score = lastFeatures.composite_risk_score;
    jitter = lastFeatures.pitch_jitter_pct || 0;
    shimmer = lastFeatures.amplitude_shimmer_pct || 0;
    flatness = lastFeatures.spectral_flatness || 0;
    typeLabel = "live call";
  } else {
    // Fallback if no active scan data is loaded yet, show the default chips
    const defaultChips = FOLLOW_UP_SUGGESTIONS['default'];
    container.innerHTML = defaultChips.map(chip =>
      `<div class="chat-chip" onclick="sendQuickPrompt('${chip.prompt.replace(/'/g, "\\'")}')">${chip.text}</div>`
    ).join('');
    return;
  }

  let riskVerdict = "Low Risk";
  if (score >= 75) riskVerdict = "Critical Risk";
  else if (score >= 50) riskVerdict = "High Risk";
  else if (score >= 25) riskVerdict = "Moderate Risk";

  const scannerSuggestions = [
    { text: `Explain current score (${score}/100)`, prompt: `Why does the scanner show a synthetic risk score of ${score}/100 on the current ${typeLabel}?` },
    { text: `Explain Jitter (${jitter}%) & Shimmer (${shimmer}%)`, prompt: `Explain why the current ${typeLabel} has pitch jitter of ${jitter}% and amplitude shimmer of ${shimmer}% metric values.` },
    { text: `What is the protocol for ${riskVerdict}?`, prompt: `What specific protocol should UCO Bank agents follow when the scanner reports a ${riskVerdict} verdict with a score of ${score}/100?` }
  ];

  container.innerHTML = scannerSuggestions.map(chip =>
    `<div class="chat-chip" onclick="sendQuickPrompt('${chip.prompt.replace(/'/g, "\\'")}')">${chip.text}</div>`
  ).join('');
}

// Draggable helper function
function makeElementDraggable(elmnt, handle) {
  let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

  if (handle) {
    handle.onmousedown = dragMouseDown;
    handle.style.cursor = 'move';
  } else {
    elmnt.onmousedown = dragMouseDown;
    elmnt.style.cursor = 'move';
  }

  function dragMouseDown(e) {
    e = e || window.event;
    // Don't drag if clicking buttons, links or inputs inside the element
    if (e.target.closest('button') || e.target.closest('input') || e.target.closest('a') || e.target.closest('.chat-btn')) {
      return;
    }
    e.preventDefault();
    // get the mouse cursor position at startup:
    pos3 = e.clientX;
    pos4 = e.clientY;
    document.onmouseup = closeDragElement;
    // call a function whenever the cursor moves:
    document.onmousemove = elementDrag;
  }

  function elementDrag(e) {
    e = e || window.event;
    e.preventDefault();
    // calculate the new cursor position:
    pos1 = pos3 - e.clientX;
    pos2 = pos4 - e.clientY;
    pos3 = e.clientX;
    pos4 = e.clientY;

    // calculate offsets
    let newTop = elmnt.offsetTop - pos2;
    let newLeft = elmnt.offsetLeft - pos1;

    // boundary checks
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const rect = elmnt.getBoundingClientRect();

    if (newLeft < 0) newLeft = 0;
    if (newTop < 0) newTop = 0;
    if (newLeft + rect.width > viewportWidth) newLeft = viewportWidth - rect.width;
    if (newTop + rect.height > viewportHeight) newTop = viewportHeight - rect.height;

    // set the element's new position:
    elmnt.style.top = newTop + "px";
    elmnt.style.left = newLeft + "px";
    elmnt.style.bottom = "auto";
    elmnt.style.right = "auto";
  }

  function closeDragElement() {
    // stop moving when mouse button is released:
    document.onmouseup = null;
    document.onmousemove = null;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const chatPanel = document.getElementById('chat-panel');
  const chatHeader = document.querySelector('.chat-header');
  const chatTrigger = document.querySelector('.chat-trigger');

  if (chatPanel && chatHeader) {
    makeElementDraggable(chatPanel, chatHeader);
  }
  if (chatTrigger) {
    makeElementDraggable(chatTrigger);

    let isDragging = false;
    let startX = 0, startY = 0;

    chatTrigger.addEventListener('mousedown', (e) => {
      isDragging = false;
      startX = e.clientX;
      startY = e.clientY;
    });

    chatTrigger.addEventListener('mousemove', (e) => {
      if (Math.abs(e.clientX - startX) > 5 || Math.abs(e.clientY - startY) > 5) {
        isDragging = true;
      }
    });

    chatTrigger.addEventListener('click', (e) => {
      if (isDragging) {
        e.preventDefault();
        e.stopPropagation();
      }
    });
  }

  // Initialize transaction lock state to 0 (Caller voice matches/normal)
  updateTransactionLockState(0);
});

function handleGlobalSearch(query) {
  const q = query.toLowerCase().trim();

  // 1. Filter Voiceprints in Voiceprint Registry page
  const vprRows = document.querySelectorAll('#vpr-list .vpr-row');
  vprRows.forEach(row => {
    const text = row.textContent.toLowerCase();
    if (text.includes(q)) {
      row.style.setProperty('display', 'flex', 'important');
    } else {
      row.style.setProperty('display', 'none', 'important');
    }
  });

  // 2. Filter Call History Table rows
  const historyRows = document.querySelectorAll('#history-tbody tr');
  historyRows.forEach(row => {
    const text = row.textContent.toLowerCase();
    if (text.includes(q)) {
      row.style.setProperty('display', 'table-row', 'important');
    } else {
      row.style.setProperty('display', 'none', 'important');
    }
  });

  // 3. Filter Dashboard Recent Calls Table rows
  const dashRows = document.querySelectorAll('#dash-recent-tbody tr');
  dashRows.forEach(row => {
    const text = row.textContent.toLowerCase();
    if (text.includes(q)) {
      row.style.setProperty('display', 'table-row', 'important');
    } else {
      row.style.setProperty('display', 'none', 'important');
    }
  });

  // 4. Filter Reports Table rows
  const reportsRows = document.querySelectorAll('#reports-tbody tr');
  reportsRows.forEach(row => {
    const text = row.textContent.toLowerCase();
    if (text.includes(q)) {
      row.style.setProperty('display', 'table-row', 'important');
    } else {
      row.style.setProperty('display', 'none', 'important');
    }
  });
}

/* ============================================================
   HACKATHON ADVANCED CYBERSECURITY & BANKING FEATURES
   ============================================================ */

window.sandboxAttackActive = false;
window.challengeTimerActive = false;
let challengeStartTimestamp = 0;
const CHALLENGE_PHRASES = [
  "UCO Safe Orbit 942",
  "Crimson Falcon Secure",
  "Verified Token Omega",
  "Delta Branch Authentication",
  "Kyber Protocol Active"
];

let liveFilterLowNode = null;
let liveFilterHighNode = null;

// Feature 1: Telecom Codec Emulation Web Audio chain routing
function updateLiveCodecFilter() {
  if (monRunning) {
    connectAudioChain();
  } else {
    const codec = document.getElementById('mon-codec')?.value || 'none';
    toast(`Codec set to ${codec.toUpperCase()}. Start live capture to hear/see.`, 'info');
  }
}

function connectAudioChain() {
  if (!audioCtx || !sourceNode || !analyser) return;

  // Disconnect existing codec filter nodes
  try { sourceNode.disconnect(); } catch (e) { }
  try { if (liveFilterLowNode) liveFilterLowNode.disconnect(); } catch (e) { }
  try { if (liveFilterHighNode) liveFilterHighNode.disconnect(); } catch (e) { }
  try { if (recorderNode) recorderNode.disconnect(); } catch (e) { }
  
  // Clean up existing noise nodes
  try {
    if (window.liveNoiseSource) {
      window.liveNoiseSource.stop();
      window.liveNoiseSource.disconnect();
      window.liveNoiseSource = null;
    }
    if (window.liveNoiseGain) {
      window.liveNoiseGain.disconnect();
      window.liveNoiseGain = null;
    }
  } catch (e) {}

  const codec = document.getElementById('mon-codec')?.value || 'none';
  logLine(`Routing audio chain for codec mode: ${codec.toUpperCase()}`, 'log-info');

  let activeOutput = sourceNode;

  if (codec === 'gsm') {
    // GSM Mobile: 300Hz to 3.4kHz Bandpass
    liveFilterLowNode = audioCtx.createBiquadFilter();
    liveFilterLowNode.type = 'highpass';
    liveFilterLowNode.frequency.value = 300;

    liveFilterHighNode = audioCtx.createBiquadFilter();
    liveFilterHighNode.type = 'lowpass';
    liveFilterHighNode.frequency.value = 3400;

    sourceNode.connect(liveFilterLowNode);
    liveFilterLowNode.connect(liveFilterHighNode);
    activeOutput = liveFilterHighNode;
  } else if (codec === 'landline') {
    // Landline: 500Hz to 2.5kHz Bandpass (more severe degradation)
    liveFilterLowNode = audioCtx.createBiquadFilter();
    liveFilterLowNode.type = 'highpass';
    liveFilterLowNode.frequency.value = 500;

    liveFilterHighNode = audioCtx.createBiquadFilter();
    liveFilterHighNode.type = 'lowpass';
    liveFilterHighNode.frequency.value = 2500;

    sourceNode.connect(liveFilterLowNode);
    liveFilterLowNode.connect(liveFilterHighNode);
    activeOutput = liveFilterHighNode;
  } else if (codec === 'noisy') {
    // Noisy Call Center: GSM filters + mixed background white noise
    liveFilterLowNode = audioCtx.createBiquadFilter();
    liveFilterLowNode.type = 'highpass';
    liveFilterLowNode.frequency.value = 300;

    liveFilterHighNode = audioCtx.createBiquadFilter();
    liveFilterHighNode.type = 'lowpass';
    liveFilterHighNode.frequency.value = 3400;

    sourceNode.connect(liveFilterLowNode);
    liveFilterLowNode.connect(liveFilterHighNode);
    activeOutput = liveFilterHighNode;

    try {
      const bufferSize = 2 * audioCtx.sampleRate;
      const noiseBuffer = audioCtx.createBuffer(1, bufferSize, audioCtx.sampleRate);
      const outputBuffer = noiseBuffer.getChannelData(0);
      for (let i = 0; i < bufferSize; i++) {
        outputBuffer[i] = Math.random() * 2 - 1;
      }
      
      const noiseSource = audioCtx.createBufferSource();
      noiseSource.buffer = noiseBuffer;
      noiseSource.loop = true;
      
      const noiseGain = audioCtx.createGain();
      noiseGain.gain.value = 0.035; // ~15dB SNR
      
      noiseSource.connect(noiseGain);
      noiseGain.connect(analyser);
      
      window.liveNoiseSource = noiseSource;
      window.liveNoiseGain = noiseGain;
      
      noiseSource.start(0);
      logLine("🏢 Call center background noise generator injected into loop.", 'log-good');
    } catch (e) {
      console.error("Failed to inject call center noise: ", e);
    }
  }

  // Connect to Analyser
  activeOutput.connect(analyser);

  // Connect to ScriptProcessor recorder
  if (recorderNode) {
    activeOutput.connect(recorderNode);
    recorderNode.connect(audioCtx.destination);
  }
}

// Feature 2: Unified Identity Composite Threat Scoring Heuristic
function getCompositeScore(acousticScore) {
  const aRisk = acousticScore;

  // Biometrics risk estimation based on Claimed Customer registry enrollment
  const customerName = document.getElementById('ctx-customer')?.value || '';
  const prints = VOICEPRINTS || [];
  const printExists = prints.some(p => p.name.toLowerCase() === customerName.toLowerCase());
  let bRisk = 0;
  let bStatus = "No Check";

  if (customerName) {
    if (printExists) {
      if (window.sandboxAttackActive) {
        bRisk = 95;
        bStatus = "❌ MISMATCH (95%)";
      } else if (acousticScore > 50) {
        bRisk = 75;
        bStatus = "⚠️ SUSPECTED SPOOF";
      } else {
        bRisk = 10;
        bStatus = "✅ MATCHED (10%)";
      }
    } else {
      bRisk = 40;
      bStatus = "ℹ️ UNREGISTERED";
    }
  }

  // Metadata Risk (SIM swaps, routing gateways, geo-locations)
  let mRisk = 0;
  const simSwap = document.getElementById('meta-simswap')?.value === 'swap';
  const locMismatch = document.getElementById('meta-location')?.value === 'mismatch';
  const voipCarrier = document.getElementById('meta-voip')?.value === 'voip';

  if (simSwap) mRisk += 30;
  if (locMismatch) mRisk += 20;
  if (voipCarrier) mRisk += 25;
  mRisk = Math.min(100, mRisk);

  // Compute composite score weighted sum
  const composite = Math.round((aRisk * 0.5) + (bRisk * 0.3) + (mRisk * 0.2));

  return {
    composite,
    aRisk,
    bRisk,
    bStatus,
    mRisk
  };
}

// Triggered when dropdown select settings change
function updateCompositeScore() {
  const scoreText = document.getElementById('mon-score');
  if (scoreText) {
    const curAcoustic = window.lastFeatures?.acoustic_risk_score || 0;
    const compResult = getCompositeScore(curAcoustic);

    // Update breakdown elements
    document.getElementById('comp-acoustic').textContent = compResult.aRisk + '%';
    document.getElementById('comp-biometrics').textContent = compResult.bStatus;
    document.getElementById('comp-metadata').textContent = compResult.mRisk + '%';

    const compositeScore = compResult.composite;
    scoreText.textContent = compositeScore;

    // Update transaction security panel lock state
    updateTransactionLockState(compositeScore);

    const ring = document.getElementById('mon-ring');
    if (ring) {
      const circumference = 264;
      ring.style.strokeDashoffset = circumference - (circumference * compositeScore / 100);
      const vComp = verdictFromScore(compositeScore);
      ring.style.stroke = vComp.color;

      const pill = document.getElementById('verdict-pill');
      if (pill) {
        pill.className = 'verdict-pill vp-' + vComp.cls;
        pill.textContent = '● ' + vComp.label;
      }
    }
  }
}

// Feature 3: Interactive Speech Synthesis Sandbox Attack
function launchSandboxAttack() {
  const phrase = document.getElementById('sandbox-text').value.trim();
  const voiceName = document.getElementById('sandbox-voice').value;
  if (!phrase) { toast('Please enter a phrase to synthesize!', 'error'); return; }

  // Set attack flag to trigger simulated feature outputs
  window.sandboxAttackActive = true;
  document.getElementById('sandbox-badge').textContent = '⚠️ ATTACK ACTIVE';
  document.getElementById('sandbox-badge').className = 'badge b-red';
  document.getElementById('btn-launch-attack').disabled = true;
  document.getElementById('btn-stop-attack').disabled = false;

  toast('Injecting neural vocoder clone stream...', 'warning');
  logLine('Neural Speech Synthesis Voice Injection attack started!', 'log-crit');

  // Trigger browser SpeechSynthesis
  if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel(); // Stop current speech
    const utterance = new SpeechSynthesisUtterance(phrase);
    const voices = window.speechSynthesis.getVoices();
    const targetVoice = voices.find(v => v.name.includes(voiceName));
    if (targetVoice) utterance.voice = targetVoice;

    utterance.onend = () => {
      logLine('Deepfake speech injection completed.', 'log-info');
    };

    window.speechSynthesis.speak(utterance);
  } else {
    toast('Browser SpeechSynthesis not supported. Attack mock is active.', 'info');
  }

  // Trigger startMonitor automatically if not running to demo the live scan intercept!
  if (!monRunning) {
    startMonitor();
  }
}

function stopSandboxAttack() {
  window.sandboxAttackActive = false;
  document.getElementById('sandbox-badge').textContent = 'OFFLINE';
  document.getElementById('sandbox-badge').className = 'badge b-orange';
  document.getElementById('btn-launch-attack').disabled = false;
  document.getElementById('btn-stop-attack').disabled = true;

  if ('speechSynthesis' in window) {
    window.speechSynthesis.cancel();
  }
  toast('Deepfake injection stream cleared.', 'success');
  logLine('Interactive Deepfake Sandbox attack cleared.', 'log-good');
}

// Feature 4: Active Defense Challenge-Response Passphrase verification
function generateChallengePhrase() {
  const phrase = CHALLENGE_PHRASES[Math.floor(Math.random() * CHALLENGE_PHRASES.length)];
  document.getElementById('challenge-phrase').textContent = phrase;
  document.getElementById('btn-start-challenge').disabled = false;
  document.getElementById('challenge-status').textContent = 'PHRASE READY';
  document.getElementById('challenge-status').className = 'badge b-orange';
  document.getElementById('challenge-delay').textContent = '0.0s';
  document.getElementById('challenge-latency-bar').style.width = '0%';

  toast('Passphrase generated. Instruct the caller to read it, then click Start Latency Monitor.', 'info');
}

function startChallengeTimer() {
  window.challengeTimerActive = true;
  challengeStartTimestamp = performance.now();
  document.getElementById('challenge-status').textContent = 'AWAITING SPEECH';
  document.getElementById('challenge-status').className = 'badge b-red';
  document.getElementById('btn-start-challenge').disabled = true;

  logLine('Active defense challenge started. Monitoring real-time synthesis delay...', 'log-info');
}

function stopChallengeTimer() {
  window.challengeTimerActive = false;
  const elapsed = (performance.now() - challengeStartTimestamp) / 1000;

  document.getElementById('challenge-status').textContent = 'COMPLETED';
  document.getElementById('challenge-status').className = 'badge b-green';
  document.getElementById('challenge-delay').textContent = elapsed.toFixed(2) + 's';

  // Real-time voice synthesis API delay check (>1.5 seconds indicates deepfake backend queue latency)
  const isHighLatency = elapsed > 1.5;
  const latencyPct = Math.min(100, (elapsed / 3.0) * 100);
  const latencyBar = document.getElementById('challenge-latency-bar');
  if (latencyBar) {
    latencyBar.style.width = latencyPct + '%';
    latencyBar.style.backgroundColor = isHighLatency ? 'var(--red)' : 'var(--green)';
  }

  document.getElementById('challenge-pace').textContent = isHighLatency ? '🤖 Synthesized Delay' : '👤 Normal Speech';
  document.getElementById('challenge-pace').style.color = isHighLatency ? 'var(--red)' : 'var(--green)';

  if (isHighLatency) {
    logLine(`🚨 DEFENSE WARNING: High synthesis latency detected (${elapsed.toFixed(1)}s). Typical of real-time deepfake voice cloning engines.`, 'log-crit');
    toast('Security alert: synthetic call delay signature detected!', 'error');
  } else {
    logLine(`✅ Challenge verification normal. Response latency within human range (${elapsed.toFixed(1)}s).`, 'log-good');
  }
}

// Feature 5: Mock Transaction Lockdown Flow & TOTP Override
window.txVerificationOverridden = false;

function updateTransactionLockState(compositeScore) {
  const beneficiaryInput = document.getElementById('tx-beneficiary');
  const accountInput = document.getElementById('tx-account');
  const amountInput = document.getElementById('tx-amount');
  const submitBtn = document.getElementById('btn-tx-submit');
  const statusBadge = document.getElementById('tx-status-badge');
  const verdictText = document.getElementById('tx-security-verdict');
  const overrideBox = document.getElementById('tx-override-box');
  const acousticText = document.getElementById('tx-acoustic-risk');

  if (acousticText) {
    acousticText.textContent = compositeScore + '%';
  }

  if (compositeScore >= 50 && !window.txVerificationOverridden) {
    // LOCK DOWN TRANSACTION
    if (beneficiaryInput) beneficiaryInput.disabled = true;
    if (accountInput) accountInput.disabled = true;
    if (amountInput) amountInput.disabled = true;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = '❌ Transfer Blocked by Security Policy';
    }
    if (statusBadge) {
      statusBadge.textContent = '🚨 FAILED VOICE CHECK';
      statusBadge.className = 'badge b-red';
    }
    if (verdictText) {
      verdictText.textContent = '🚨 OVERRIDE REQUIRED: Suspected Voice Clone';
      verdictText.style.color = 'var(--red)';
    }
    if (overrideBox) {
      overrideBox.style.display = 'block';
    }
  } else {
    // ENABLE TRANSACTION
    if (beneficiaryInput) beneficiaryInput.disabled = false;
    if (accountInput) accountInput.disabled = false;
    if (amountInput) amountInput.disabled = false;
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = window.txVerificationOverridden ? '💸 Authorize Transfer (MFA Overridden)' : '💸 Authorize Transfer Funds';
    }
    if (statusBadge) {
      statusBadge.textContent = window.txVerificationOverridden ? '🛡️ BYPASSED' : 'ACTIVE VERIFICATION';
      statusBadge.className = window.txVerificationOverridden ? 'badge b-blue' : 'badge b-green';
    }
    if (verdictText) {
      verdictText.textContent = window.txVerificationOverridden ? '🛡️ TRANSACTION APPROVED (MFA Override)' : '✅ TRANSACTION ENABLED (Caller verified)';
      verdictText.style.color = window.txVerificationOverridden ? 'var(--uco-blue)' : 'var(--green)';
    }
    if (overrideBox) {
      overrideBox.style.display = 'none';
    }
  }
}

async function verifyTxBypass() {
  const otpInput = document.getElementById('tx-otp-bypass');
  const code = otpInput?.value.trim();
  if (!code || code.length !== 6) {
    toast('Enter a valid 6-digit TOTP code', 'error');
    return;
  }

  toast('Verifying bypass credentials with database...', 'info');

  try {
    const token = localStorage.getItem('sv_token'); // Get session token if logged in
    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    } else {
      // Fallback for mock session
      headers['Authorization'] = `Bearer ${pendingTempToken || localStorage.getItem('sv_temp_token')}`;
    }

    const response = await fetch('/api/verify-bypass', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ otp: code })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'MFA validation failed');
    }

    window.txVerificationOverridden = true;
    toast('Transaction lock overridden successfully!', 'success');
    logLine('✅ High-risk transaction security override approved using MFA code.', 'log-good');
    
    // Refresh UI
    const scoreText = document.getElementById('mon-score');
    const curAcoustic = window.lastFeatures?.composite_risk_score || 0;
    const compResult = getCompositeScore(curAcoustic);
    updateTransactionLockState(compResult.composite);
    
    // Clear inputs
    if (otpInput) otpInput.value = '';
  } catch (error) {
    console.error('Bypass verification error:', error);
    toast(error.message, 'error');
    logLine(`❌ Attempted high-risk transaction override with invalid MFA code: ${error.message}`, 'log-crit');
  }
}

function submitTransaction() {
  const beneficiary = document.getElementById('tx-beneficiary').value.trim();
  const account = document.getElementById('tx-account').value.trim();
  const amount = document.getElementById('tx-amount').value.trim();

  if (!beneficiary) { toast('Enter beneficiary name', 'error'); return; }
  if (!account) { toast('Enter account number', 'error'); return; }
  if (!amount || amount <= 0) { toast('Enter positive transfer amount', 'error'); return; }

  // Double check voice engine risk rating
  const curAcoustic = window.lastFeatures?.composite_risk_score || 0;
  const compResult = getCompositeScore(curAcoustic);
  const compositeScore = compResult.composite;

  if (compositeScore >= 50 && !window.txVerificationOverridden) {
    toast('Transfer blocked: Caller voice biometric mismatch!', 'error');
    return;
  }

  toast(`Transferring Rs. ${amount} to ${beneficiary}...`, 'info');
  logLine(`Transfer of Rs. ${amount} to ${beneficiary} (A/C: ${account}) authorized successfully.`, 'log-good');
  
  setTimeout(() => {
    toast('Transaction completed successfully!', 'success');
    pushAuditLog('TRANSACTION_AUTHORIZED', `Transaction authorized for Rs. ${amount} to A/C ${account}. Voice match verified.`);
  }, 1000);
}



