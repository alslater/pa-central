import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/hooks/useAuth'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Hosts from '@/pages/Hosts'
import HostDetail from '@/pages/HostDetail'
import Alerts from '@/pages/Alerts'
import { Scans } from '@/pages/Scans'
import Cooldown from '@/pages/Cooldown'
import Configs from '@/pages/Configs'
import ApiKeys from '@/pages/ApiKeys'
import Users from '@/pages/Users'
import RepoScans from '@/pages/RepoScans'
import Vulnerabilities from '@/pages/Vulnerabilities'
import SystemSettings from '@/pages/SystemSettings'
import { ReactNode } from 'react'
import { ErrorBoundary } from '@/components/ErrorBoundary'

function Guard({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="auth-loading" />
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function AdminGuard({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  if (user?.role !== 'admin') return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <ErrorBoundary>
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Guard><Dashboard /></Guard>} />
          <Route path="/hosts" element={<Guard><Hosts /></Guard>} />
          <Route path="/hosts/:id" element={<Guard><HostDetail /></Guard>} />
          <Route path="/alerts" element={<Guard><Alerts /></Guard>} />
          <Route path="/scans" element={<Guard><Scans /></Guard>} />
          <Route path="/cooldown" element={<Guard><Cooldown /></Guard>} />
          <Route path="/configs" element={<Guard><Configs /></Guard>} />
          <Route path="/api-keys" element={<Guard><ApiKeys /></Guard>} />
          <Route path="/users" element={<Guard><AdminGuard><Users /></AdminGuard></Guard>} />
          <Route path="/repo-scans" element={<Guard><AdminGuard><RepoScans /></AdminGuard></Guard>} />
          <Route path="/vulnerabilities" element={<Guard><AdminGuard><Vulnerabilities /></AdminGuard></Guard>} />
          <Route path="/settings" element={<Guard><AdminGuard><SystemSettings /></AdminGuard></Guard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
    </ErrorBoundary>
  )
}
