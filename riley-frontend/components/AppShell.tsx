'use client'

import { usePathname } from 'next/navigation'
import Nav from './Nav'

const APP_PREFIXES = ['/dashboard', '/alerts', '/simulate', '/patterns', '/bugs']

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const isApp = APP_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + '/'))

  if (!isApp) {
    return <>{children}</>
  }

  return (
    <div className="flex h-screen bg-[#080810] overflow-hidden">
      <Nav />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}
