import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'

export function AppLayout() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 min-w-0 lg:pl-0 overflow-auto">
        <div className="p-6 lg:p-8 max-w-7xl mx-auto w-full animate-fade-in">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
