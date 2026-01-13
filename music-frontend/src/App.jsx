import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'

const AUTH_STORAGE_KEY = 'music_auth'

function loadAuth() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (!parsed?.token) return null
    return parsed
  } catch {
    return null
  }
}

function saveAuth(auth) {
  if (!auth?.token) return
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth))
}

function clearAuth() {
  localStorage.removeItem(AUTH_STORAGE_KEY)
}

const usernameRe = /^[a-zA-Z0-9._-]{3,50}$/
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const passwordRules = [
  { label: 'min 8 karaktera', test: (pw) => pw.length >= 8 },
  { label: 'malo slovo', test: (pw) => /[a-z]/.test(pw) },
  { label: 'veliko slovo', test: (pw) => /[A-Z]/.test(pw) },
  { label: 'cifra', test: (pw) => /[0-9]/.test(pw) },
  { label: 'specijalni znak', test: (pw) => /[!@#$%^&*()_+\-[\]{}|;:'",.<>\/?]/.test(pw) },
]

function RegistrationView({ goToLogin }) {
  const [form, setForm] = useState({
    firstName: '',
    lastName: '',
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  })
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(false)
  const [serverMsg, setServerMsg] = useState('')
  const [token, setToken] = useState('')
  const [confirmStatus, setConfirmStatus] = useState('')

  const passwordChecks = useMemo(
    () => passwordRules.map((r) => ({ label: r.label, ok: r.test(form.password) })),
    [form.password],
  )
  const passwordStrong = passwordChecks.every((c) => c.ok)

  const onChange = (e) => {
    const { name, value } = e.target
    setForm((prev) => ({ ...prev, [name]: value }))
  }

  const validate = () => {
    const next = {}
    if (!form.firstName.trim()) next.firstName = 'Ime je obavezno'
    if (!form.lastName.trim()) next.lastName = 'Prezime je obavezno'
    if (!usernameRe.test(form.username.trim())) next.username = '3-50, slova/brojevi . _ -'
    if (!emailRe.test(form.email.trim())) next.email = 'Neispravan email'
    if (!passwordStrong) next.password = 'Lozinka ne ispunjava politiku'
    if (form.password !== form.confirmPassword) next.confirmPassword = 'Lozinke se ne poklapaju'
    setErrors(next)
    return Object.keys(next).length === 0
  }

  const register = async (e) => {
    e.preventDefault()
    setServerMsg('')
    setConfirmStatus('')
    if (!validate()) return
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...form,
          firstName: form.firstName.trim(),
          lastName: form.lastName.trim(),
          username: form.username.trim(),
          email: form.email.trim(),
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspela registracija')
      setToken(data.verificationToken)
      setServerMsg(data.message)
    } catch (err) {
      setServerMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  const confirm = async () => {
    if (!token) {
      setConfirmStatus('Unesi token iz registracije')
      return
    }
    try {
      const res = await fetch(`${API_BASE}/register/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspela potvrda')
      setConfirmStatus('Registracija potvrđena ✅')
    } catch (err) {
      setConfirmStatus(err.message)
    }
  }

  return (
    <div className="page">
      <header>
        <p className="eyebrow">Registracija</p>
        <h1>Napravi nalog</h1>
        <p className="lede">Unesi podatke, potvrdi token, pa se prijavi.</p>
      </header>

      <main className="grid">
        <section className="card">
          <h2>Registracija</h2>
          <form className="form" onSubmit={register}>
            <div className="field two">
              <label>
                Ime
                <input name="firstName" value={form.firstName} onChange={onChange} />
              </label>
              <label>
                Prezime
                <input name="lastName" value={form.lastName} onChange={onChange} />
              </label>
            </div>
            <div className="field">
              <label>
                Korisničko ime
                <input name="username" value={form.username} onChange={onChange} />
              </label>
              {errors.username && <p className="error">{errors.username}</p>}
            </div>
            <div className="field">
              <label>
                Email
                <input name="email" type="email" value={form.email} onChange={onChange} />
              </label>
              {errors.email && <p className="error">{errors.email}</p>}
            </div>
            <div className="field two">
              <label>
                Lozinka
                <input name="password" type="password" value={form.password} onChange={onChange} />
              </label>
              <label>
                Ponovi lozinku
                <input name="confirmPassword" type="password" value={form.confirmPassword} onChange={onChange} />
              </label>
            </div>
            {errors.password && <p className="error">{errors.password}</p>}
            {errors.confirmPassword && <p className="error">{errors.confirmPassword}</p>}

            <div className="password-checks">
              {passwordChecks.map((c) => (
                <span key={c.label} className={c.ok ? 'ok' : 'fail'}>
                  {c.ok ? '✓' : '•'} {c.label}
                </span>
              ))}
            </div>

            <div className="action-row">
              <button type="submit" disabled={loading}>
                {loading ? 'Slanje...' : 'Kreiraj nalog'}
              </button>
              <button type="button" className="link-btn" onClick={goToLogin}>
                Već imaš nalog? Prijava
              </button>
            </div>
            {serverMsg && <p className="info">{serverMsg}</p>}
          </form>
        </section>

        <section className="card secondary">
          <h2>Potvrda naloga</h2>
          <div className="token-box">{token || 'Nema tokena još'}</div>
          <div className="field">
            <label>
              Unesi token
              <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="verification token" />
            </label>
          </div>
          <button type="button" onClick={confirm}>
            Potvrdi nalog
          </button>
          {confirmStatus && <p className="info">{confirmStatus}</p>}

          <div className="policy">
            <p className="eyebrow">Politika lozinki</p>
            <ul>
              <li>najmanje 8 karaktera</li>
              <li>mala + velika slova, broj, specijalni znak</li>
              <li>važi 1h</li>
            </ul>
          </div>
        </section>
      </main>
    </div>
  )
}

function LoginView({ goToRegister, goToRecover }) {
  const [loginForm, setLoginForm] = useState({ username: '', password: '' })
  const [otp, setOtp] = useState('')
  const [token, setToken] = useState('')
  const [user, setUser] = useState(null)
  const [loginStatus, setLoginStatus] = useState('')

  const login = async (e) => {
    e.preventDefault()
    setLoginStatus('')
    setOtp('')
    setToken('')
    setUser(null)
    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginForm.username.trim(),
          password: loginForm.password,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešna prijava')
      setOtp(data.otp || '')
      setLoginStatus(data.message || 'OTP generisan (demo)')
    } catch (err) {
      setLoginStatus(err.message)
    }
  }

  const verifyOtp = async () => {
    setLoginStatus('')
    try {
      const res = await fetch(`${API_BASE}/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'OTP nevažeći')

      const nextAuth = {
        token: data.token,
        user_id: data.user_id,
        email: data.email,
        role: data.role,
        username: data.username,
        expiresAt: data.expiresAt,
      }

      setToken(nextAuth.token)
      setUser(nextAuth)
      saveAuth(nextAuth)

      setLoginStatus(data.message || 'Prijava uspešna')
      window.location.hash = nextAuth.role === 'A' ? '#admin' : '#user'
    } catch (err) {
      setLoginStatus(err.message)
    }
  }

  const logout = async () => {
    try {
      const res = await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešna odjava')
      setToken('')
      setUser(null)
      clearAuth()
      setLoginStatus(data.message || 'Odjava uspešna')
    } catch (err) {
      setLoginStatus(err.message)
    }
  }

  return (
    <div className="page">
      <header>
        <p className="eyebrow">Prijava</p>
        <h1>Muzika · Pristup nalogu</h1>
        <p className="lede">Prijava sa OTP. Treba ti nalog ili reset? Otvori odgovarajuću stranicu.</p>
      </header>

      <main className="grid">
        <section className="card">
          <h2>Prijava (OTP)</h2>
          <form className="form" onSubmit={login}>
            <div className="field">
              <label>
                Korisničko ime
                <input
                  name="username"
                  value={loginForm.username}
                  onChange={(e) => setLoginForm((p) => ({ ...p, username: e.target.value }))}
                />
              </label>
            </div>
            <div className="field">
              <label>
                Lozinka
                <input
                  name="password"
                  type="password"
                  value={loginForm.password}
                  onChange={(e) => setLoginForm((p) => ({ ...p, password: e.target.value }))}
                />
              </label>
            </div>
            <div className="action-row">
              <button type="submit">Dobij OTP</button>
              <button type="button" className="link-btn" onClick={goToRegister}>
                Registracija
              </button>
              <button type="button" className="link-btn" onClick={goToRecover}>
                Zaboravljena lozinka / Magic link
              </button>
            </div>
          </form>
          <div className="field" style={{ marginTop: 12 }}>
            <label>
              OTP kod
              <input value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="unesi 6-cifreni kod" />
            </label>
            <div className="token-box">{token ? `Token: ${token}` : 'Nema tokena još'}</div>
            {user?.role && (
              <p className="info" style={{ marginTop: 8 }}>
                Uloga: <b>{user.role}</b>
              </p>
            )}
          </div>
          <div className="action-row">
            <button type="button" onClick={verifyOtp}>
              Potvrdi OTP
            </button>
            <button type="button" onClick={logout}>
              Odjava
            </button>
          </div>
          {loginStatus && <p className="info">{loginStatus}</p>}
        </section>
      </main>
    </div>
  )
}

function RecoveryView({ goToLogin, auth, onAuth }) {
  const [changeForm, setChangeForm] = useState({
    username: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  })
  const [changeStatus, setChangeStatus] = useState('')
  const [resetEmail, setResetEmail] = useState('')
  const [resetForm, setResetForm] = useState({ token: '', newPassword: '', confirmPassword: '' })
  const [resetTokenDisplay, setResetTokenDisplay] = useState('')
  const [resetStatus, setResetStatus] = useState('')
  const [magicEmail, setMagicEmail] = useState('')
  const [magicToken, setMagicToken] = useState('')
  const [magicStatus, setMagicStatus] = useState('')
  const [token, setToken] = useState('')

  const passwordStrongChange = useMemo(
    () => passwordRules.every((r) => r.test(changeForm.newPassword)),
    [changeForm.newPassword],
  )
  const passwordStrongReset = useMemo(
    () => passwordRules.every((r) => r.test(resetForm.newPassword)),
    [resetForm.newPassword],
  )

  const changePassword = async (e) => {
    e.preventDefault()
    setChangeStatus('')
    if (changeForm.newPassword !== changeForm.confirmPassword) {
      setChangeStatus('Lozinke se ne poklapaju')
      return
    }
    if (!passwordStrongChange) {
      setChangeStatus('Nova lozinka ne ispunjava politiku')
      return
    }
    try {
      const res = await fetch(`${API_BASE}/password/change`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
        },
        body: JSON.stringify({
          username: changeForm.username.trim(),
          currentPassword: changeForm.currentPassword,
          newPassword: changeForm.newPassword,
          confirmPassword: changeForm.confirmPassword,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspela promena lozinke')
      setChangeStatus(data.message || 'Lozinka promenjena')
    } catch (err) {
      setChangeStatus(err.message)
    }
  }

  const requestReset = async (e) => {
    e.preventDefault()
    setResetStatus('')
    setResetTokenDisplay('')
    try {
      const res = await fetch(`${API_BASE}/password/reset/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešan zahtev za reset')
      setResetTokenDisplay(data.resetToken || '')
      setResetForm((p) => ({ ...p, token: data.resetToken || '' }))
      setResetStatus(data.message || 'Reset token generisan (demo)')
    } catch (err) {
      setResetStatus(err.message)
    }
  }

  const confirmReset = async (e) => {
    e.preventDefault()
    setResetStatus('')
    if (resetForm.newPassword !== resetForm.confirmPassword) {
      setResetStatus('Lozinke se ne poklapaju')
      return
    }
    if (!passwordStrongReset) {
      setResetStatus('Nova lozinka ne ispunjava politiku')
      return
    }
    try {
      const res = await fetch(`${API_BASE}/password/reset/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: resetForm.token,
          newPassword: resetForm.newPassword,
          confirmPassword: resetForm.confirmPassword,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešan reset lozinke')
      setResetStatus(data.message || 'Lozinka resetovana')
    } catch (err) {
      setResetStatus(err.message)
    }
  }

  const requestMagic = async (e) => {
    e.preventDefault()
    setMagicStatus('')
    setMagicToken('')
    try {
      const res = await fetch(`${API_BASE}/magic/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: magicEmail.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešan zahtev za magic link')
      setMagicToken(data.magicToken || '')
      setMagicStatus(data.message || 'Magic link generisan (demo)')
    } catch (err) {
      setMagicStatus(err.message)
    }
  }

  const confirmMagic = async (e) => {
    e.preventDefault()
    setMagicStatus('')
    try {
      const res = await fetch(`${API_BASE}/magic/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: magicToken }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Magic link nevažeći')

      const nextAuth = {
        token: data.token,
        user_id: data.user_id,
        email: data.email,
        role: data.role,
        username: data.username,
        expiresAt: data.expiresAt,
      }

      setToken(nextAuth.token || '')
      saveAuth(nextAuth)
      onAuth?.(nextAuth)
      setMagicStatus(data.message || 'Prijava preko magic linka uspešna')
      window.location.hash = nextAuth.role === 'A' ? '#admin' : '#user'
    } catch (err) {
      setMagicStatus(err.message)
    }
  }

  return (
    <div className="page">
      <header>
        <p className="eyebrow">Bezbednost naloga</p>
        <h1>Promena / Reset / Magic link</h1>
        <p className="lede">Menjaj lozinku, resetuj ili koristi magic link. Vrati se na prijavu kad završiš.</p>
      </header>

      <main className="grid">
        <section className="card">
          <h2>Promena lozinke</h2>
          <form className="form" onSubmit={changePassword}>
            <div className="field two">
              <label>
                Korisničko ime
                <input
                  name="username"
                  value={changeForm.username}
                  onChange={(e) => setChangeForm((p) => ({ ...p, username: e.target.value }))}
                />
              </label>
              <label>
                Trenutna lozinka
                <input
                  name="currentPassword"
                  type="password"
                  value={changeForm.currentPassword}
                  onChange={(e) => setChangeForm((p) => ({ ...p, currentPassword: e.target.value }))}
                />
              </label>
            </div>
            <div className="field two">
              <label>
                Nova lozinka
                <input
                  name="newPassword"
                  type="password"
                  value={changeForm.newPassword}
                  onChange={(e) => setChangeForm((p) => ({ ...p, newPassword: e.target.value }))}
                />
              </label>
              <label>
                Ponovi novu lozinku
                <input
                  name="confirmPassword"
                  type="password"
                  value={changeForm.confirmPassword}
                  onChange={(e) => setChangeForm((p) => ({ ...p, confirmPassword: e.target.value }))}
                />
              </label>
            </div>
            <div className="password-checks">
              {passwordRules.map((r) => {
                const ok = r.test(changeForm.newPassword)
                return (
                  <span key={r.label} className={ok ? 'ok' : 'fail'}>
                    {ok ? '✓' : '•'} {r.label}
                  </span>
                )
              })}
            </div>
            <div className="action-row">
              <button type="submit">Promeni lozinku</button>
              <button type="button" className="link-btn" onClick={goToLogin}>
                Nazad na prijavu
              </button>
            </div>
            {changeStatus && <p className="info">{changeStatus}</p>}
          </form>
        </section>

        <section className="card secondary">
          <h2>Reset lozinke</h2>
          <form className="form" onSubmit={requestReset}>
            <div className="field">
              <label>
                Email
                <input value={resetEmail} onChange={(e) => setResetEmail(e.target.value)} />
              </label>
            </div>
            <button type="submit">Zatraži reset</button>
          </form>
          <div className="token-box">{resetTokenDisplay || 'Nema reset tokena još'}</div>
          <form className="form" onSubmit={confirmReset}>
            <div className="field">
              <label>
                Reset token
                <input
                  value={resetForm.token}
                  onChange={(e) => setResetForm((p) => ({ ...p, token: e.target.value }))}
                  placeholder="unesi reset token"
                />
              </label>
            </div>
            <div className="field two">
              <label>
                Nova lozinka
                <input
                  type="password"
                  value={resetForm.newPassword}
                  onChange={(e) => setResetForm((p) => ({ ...p, newPassword: e.target.value }))}
                />
              </label>
              <label>
                Ponovi novu lozinku
                <input
                  type="password"
                  value={resetForm.confirmPassword}
                  onChange={(e) => setResetForm((p) => ({ ...p, confirmPassword: e.target.value }))}
                />
              </label>
            </div>
            <div className="password-checks">
              {passwordRules.map((r) => {
                const ok = r.test(resetForm.newPassword)
                return (
                  <span key={r.label} className={ok ? 'ok' : 'fail'}>
                    {ok ? '✓' : '•'} {r.label}
                  </span>
                )
              })}
            </div>
            <button type="submit">Resetuj lozinku</button>
            {resetStatus && <p className="info">{resetStatus}</p>}
          </form>
        </section>

        <section className="card">
          <h2>Povraćaj naloga (Magic link)</h2>
          <form className="form" onSubmit={requestMagic}>
            <div className="field">
              <label>
                Email
                <input value={magicEmail} onChange={(e) => setMagicEmail(e.target.value)} />
              </label>
            </div>
            <button type="submit">Pošalji magic link</button>
          </form>
          <div className="token-box">{magicToken || 'Nema magic tokena još'}</div>
          <form className="form" onSubmit={confirmMagic}>
            <div className="field">
              <label>
                Magic token
                <input value={magicToken} onChange={(e) => setMagicToken(e.target.value)} placeholder="unesi magic token" />
              </label>
            </div>
            <div className="action-row">
              <button type="submit">Potvrdi magic link</button>
              {token && <span className="info">Token: {token}</span>}
            </div>
          </form>
          {magicStatus && <p className="info">{magicStatus}</p>}
        </section>
      </main>
    </div>
  )
}

function UserHome({ auth, onLogout }) {
  return (
    <div className="page">
      <header>
        <p className="eyebrow">RK</p>
        <h1>Početna (User)</h1>
        <p className="lede">Ulogovan si kao regularni korisnik.</p>
      </header>

      <main className="grid">
        <section className="card">
          <h2>Profil</h2>
          <div className="token-box">
            <div>username: {auth?.username || '-'}</div>
            <div>email: {auth?.email || '-'}</div>
            <div>role: {auth?.role || '-'}</div>
            <div>user_id: {auth?.user_id || '-'}</div>
          </div>
          <div className="action-row">
            <button type="button" onClick={onLogout}>
              Odjava
            </button>
            <button type="button" className="link-btn" onClick={() => (window.location.hash = '#recover')}>
              Promena/Reset/Magic link
            </button>
          </div>
        </section>
      </main>
    </div>
  )
}

function AdminHome({ auth, onLogout }) {
  const [targetUserId, setTargetUserId] = useState('')
  const [targetRole, setTargetRole] = useState('RK')
  const [status, setStatus] = useState('')

  const updateRole = async () => {
    setStatus('')
    if (!targetUserId.trim()) {
      setStatus('Unesi user_id')
      return
    }
    try {
      const res = await fetch(`${API_BASE}/admin/users/${encodeURIComponent(targetUserId.trim())}/role`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${auth?.token}`,
        },
        body: JSON.stringify({ role: targetRole }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Neuspešno menjanje uloge')
      setStatus('Uloga je ažurirana')
    } catch (err) {
      setStatus(err.message)
    }
  }

  return (
    <div className="page">
      <header>
        <p className="eyebrow">ADMIN</p>
        <h1>Početna (Admin)</h1>
        <p className="lede">Ulogovan si kao administrator.</p>
      </header>

      <main className="grid">
        <section className="card">
          <h2>Profil</h2>
          <div className="token-box">
            <div>username: {auth?.username || '-'}</div>
            <div>email: {auth?.email || '-'}</div>
            <div>role: {auth?.role || '-'}</div>
            <div>user_id: {auth?.user_id || '-'}</div>
          </div>
          <div className="action-row">
            <button type="button" onClick={onLogout}>
              Odjava
            </button>
          </div>
        </section>

        <section className="card secondary">
          <h2>Admin akcija (2.17 demo)</h2>
          <div className="field">
            <label>
              user_id korisnika
              <input value={targetUserId} onChange={(e) => setTargetUserId(e.target.value)} placeholder="npr. 507f1f77bcf86cd799439011" />
            </label>
          </div>
          <div className="field">
            <label>
              Nova uloga
              <select value={targetRole} onChange={(e) => setTargetRole(e.target.value)}>
                <option value="RK">RK</option>
                <option value="A">A</option>
              </select>
            </label>
          </div>
          <button type="button" onClick={updateRole}>
            Promeni ulogu
          </button>
          {status && <p className="info">{status}</p>}
        </section>
      </main>
    </div>
  )
}

function App() {
  const [auth, setAuth] = useState(() => loadAuth())
  const [view, setView] = useState(() => {
    const hash = window.location.hash
    if (hash === '#admin') return 'admin'
    if (hash === '#user') return 'user'
    if (hash === '#register') return 'register'
    if (hash === '#recover') return 'recover'
    return 'login'
  })

  useEffect(() => {
    const onHash = () => {
      const hash = window.location.hash
      if (hash === '#admin') setView('admin')
      else if (hash === '#user') setView('user')
      else if (hash === '#register') setView('register')
      else if (hash === '#recover') setView('recover')
      else setView('login')
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    if (!auth?.token) return
    if (auth.role === 'A') {
      window.location.hash = '#admin'
      setView('admin')
    } else {
      window.location.hash = '#user'
      setView('user')
    }
  }, [auth])

  const logout = async () => {
    try {
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
        },
      })
    } finally {
      clearAuth()
      setAuth(null)
      window.location.hash = '#login'
      setView('login')
    }
  }

  const goToRegister = () => {
    window.location.hash = '#register'
    setView('register')
  }
  const goToLogin = () => {
    window.location.hash = '#login'
    setView('login')
  }
  const goToRecover = () => {
    window.location.hash = '#recover'
    setView('recover')
  }

  if (view === 'admin') return <AdminHome auth={auth} onLogout={logout} />
  if (view === 'user') return <UserHome auth={auth} onLogout={logout} />
  if (view === 'register') return <RegistrationView goToLogin={goToLogin} />
  if (view === 'recover') return <RecoveryView goToLogin={goToLogin} auth={auth} onAuth={setAuth} />
  return <LoginView goToRegister={goToRegister} goToRecover={goToRecover} />
}

export default App
