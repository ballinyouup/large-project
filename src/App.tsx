import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

type Mode = 'login' | 'register' | 'forgot' | 'reset'

type ApiMessage = {
  kind: 'idle' | 'success' | 'error'
  text: string
}

const passwordRule =
  'Use at least 10 characters with uppercase, lowercase, a number, and a symbol.'
const apiUrl = import.meta.env.VITE_API_URL || '/api'

function App() {
  const [mode, setMode] = useState<Mode>('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState('')
  const [message, setMessage] = useState<ApiMessage>({ kind: 'idle', text: '' })
  const [apiStatus, setApiStatus] = useState('Checking API...')

  const actionLabel = useMemo(() => {
    if (mode === 'register') return 'Create account'
    if (mode === 'forgot') return 'Send reset link'
    if (mode === 'reset') return 'Reset password'
    return 'Log in'
  }, [mode])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const resetToken = params.get('token')

    if (resetToken) {
      setToken(resetToken)
      setMode('reset')
    }
  }, [])

  useEffect(() => {
    fetch(`${apiUrl}/health`)
      .then((response) => response.json() as Promise<{ database: number }>)
      .then((data) => {
        setApiStatus(data.database === 1 ? 'API connected to MongoDB' : 'API online, database connecting')
      })
      .catch(() => setApiStatus('API unavailable locally'))
  }, [])

  const submitForm = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setMessage({ kind: 'idle', text: 'Working...' })

    const endpoint =
      mode === 'register'
        ? `${apiUrl}/auth/register`
        : mode === 'forgot'
          ? `${apiUrl}/auth/forgot-password`
          : mode === 'reset'
            ? `${apiUrl}/auth/reset-password`
            : `${apiUrl}/auth/login`

    const body =
      mode === 'forgot'
        ? { email }
        : mode === 'reset'
          ? { token, password }
          : { name, email, password }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = (await response.json()) as { message?: string; token?: string }

      if (!response.ok) {
        throw new Error(data.message || 'Request failed.')
      }

      setMessage({
        kind: 'success',
        text:
          data.message ||
          (data.token ? 'Authenticated successfully. Session token received.' : 'Request completed.'),
      })
    } catch (error) {
      setMessage({
        kind: 'error',
        text: error instanceof Error ? error.message : 'Something went wrong.',
      })
    }
  }

  return (
    <main className="auth-page">
      <section className="brand-panel">
        <div className="brand-mark">MS</div>
        <p className="eyebrow">MoneySim</p>
        <h1>Plan smarter money moves before they happen.</h1>
        <p>
          The large-project build connects a React and TypeScript client to an Express API,
          MongoDB, account recovery, and mobile-ready workflows.
        </p>
        <div className="status-card">
          <span>{apiStatus}</span>
          <strong>moneysim.app</strong>
        </div>
      </section>

      <section className="auth-card" aria-label="Account access">
        <div className="mode-tabs" aria-label="Account form mode">
          <button className={mode === 'login' ? 'active' : ''} type="button" onClick={() => setMode('login')}>
            Login
          </button>
          <button
            className={mode === 'register' ? 'active' : ''}
            type="button"
            onClick={() => setMode('register')}
          >
            Register
          </button>
        </div>

        <div className="form-heading">
          <p className="eyebrow">{mode === 'forgot' || mode === 'reset' ? 'Account recovery' : 'Secure access'}</p>
          <h2>
            {mode === 'register'
              ? 'Create your account'
              : mode === 'forgot'
                ? 'Recover your password'
                : mode === 'reset'
                  ? 'Choose a new password'
                  : 'Welcome back'}
          </h2>
        </div>

        <form onSubmit={submitForm}>
          {mode === 'register' && (
            <label>
              Full name
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" />
            </label>
          )}

          {mode !== 'reset' && (
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                required
              />
            </label>
          )}

          {mode === 'reset' && (
            <label>
              Reset token
              <input value={token} onChange={(event) => setToken(event.target.value)} required />
            </label>
          )}

          {mode !== 'forgot' && (
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter password"
                required
              />
              {(mode === 'register' || mode === 'reset') && <span className="hint">{passwordRule}</span>}
            </label>
          )}

          <button className="primary-button" type="submit">
            {actionLabel}
          </button>
        </form>

        {message.text && <p className={`message ${message.kind}`}>{message.text}</p>}

        <div className="helper-actions">
          <button type="button" onClick={() => setMode('forgot')}>
            Forgot password?
          </button>
          <button type="button" onClick={() => setMode('reset')}>
            I have a reset token
          </button>
        </div>
      </section>
    </main>
  )
}

export default App
