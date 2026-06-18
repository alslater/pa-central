import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { api, User, TotpChallenge } from '@/lib/api'

interface AuthCtx {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<TotpChallenge | null>
  completeTotp: (sessionToken: string, code: string) => Promise<void>
  logout: () => void
}

const Ctx = createContext<AuthCtx>(null!)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) { setLoading(false); return }
    api.auth.me().then(setUser).catch(() => localStorage.removeItem('token')).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const handler = () => { localStorage.removeItem('token'); setUser(null) }
    window.addEventListener('auth:unauthorized', handler)
    return () => window.removeEventListener('auth:unauthorized', handler)
  }, [])

  const login = async (email: string, password: string): Promise<TotpChallenge | null> => {
    const resp = await api.auth.login(email, password)
    if ('totp_required' in resp) {
      return resp as TotpChallenge
    }
    localStorage.setItem('token', resp.access_token)
    setUser(await api.auth.me())
    return null
  }

  const completeTotp = async (sessionToken: string, code: string): Promise<void> => {
    const { access_token } = await api.auth.totpVerify(sessionToken, code)
    localStorage.setItem('token', access_token)
    setUser(await api.auth.me())
  }

  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
  }

  return <Ctx.Provider value={{ user, loading, login, completeTotp, logout }}>{children}</Ctx.Provider>
}
