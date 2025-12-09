import { useMemo, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080'

const usernameRe = /^[a-zA-Z0-9._-]{3,50}$/
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const passwordRules = [
  { label: 'min 8 karaktera', test: (pw) => pw.length >= 8 },
  { label: 'malo slovo', test: (pw) => /[a-z]/.test(pw) },
  { label: 'veliko slovo', test: (pw) => /[A-Z]/.test(pw) },
  { label: 'cifra', test: (pw) => /[0-9]/.test(pw) },
  { label: 'specijalni znak', test: (pw) => /[!@#$%^&*()_+\-[\]{}|;:'",.<>\/?]/.test(pw) },
]

function App() {
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
        <p className="lede">Obavezna jaka lozinka i verifikacija naloga tokenom (demo umesto emaila).</p>
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

            <button type="submit" disabled={loading}>
              {loading ? 'Slanje...' : 'Kreiraj nalog'}
            </button>
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

export default App
