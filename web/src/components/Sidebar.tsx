import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Search, ShieldAlert, FileText,
  Settings, Activity, ChevronRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const NAV = [
  { to: '/',         icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scanner',  icon: Search,          label: 'Scanner'   },
  { to: '/threats',  icon: ShieldAlert,     label: 'Threats'   },
  { to: '/reports',  icon: FileText,        label: 'Reports'   },
  { to: '/activity', icon: Activity,        label: 'Activity'  },
];

export function Sidebar() {
  return (
    <aside className="w-56 flex-shrink-0 flex flex-col bg-surface-1 border-r border-border h-screen sticky top-0">
      {/* Logo */}
      <div className="h-14 flex items-center px-4 border-b border-border">
        <div className="flex items-center gap-2.5">
          {/* Falcon icon */}
          <div className="relative w-7 h-7">
            <div className="absolute inset-0 rounded-lg bg-accent-gradient rotate-6 opacity-90" />
            <svg viewBox="0 0 28 28" className="relative w-7 h-7 drop-shadow-lg">
              <path
                d="M14 3 L22 10 L18 13 L22 22 L14 17 L6 22 L10 13 L6 10 Z"
                fill="white" opacity="0.95"
              />
            </svg>
          </div>
          <div>
            <span className="text-sm font-bold text-ink tracking-tight">Falcn</span>
            <div className="flex items-center gap-1">
              <span className="text-2xs text-ink-faint">Supply Chain Security</span>
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        <p className="px-2 mb-2 text-2xs font-semibold text-ink-faint uppercase tracking-widest">
          Platform
        </p>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => cn('nav-item', isActive && 'active')}
          >
            {({ isActive }) => (
              <>
                <Icon size={15} className="flex-shrink-0" />
                <span className="flex-1">{label}</span>
                {isActive && <ChevronRight size={12} className="opacity-50" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Bottom section */}
      <div className="px-2 pb-3 border-t border-border pt-3 space-y-0.5">
        <NavLink
          to="/settings"
          className={({ isActive }) => cn('nav-item', isActive && 'active')}
        >
          <Settings size={15} />
          <span>Settings</span>
        </NavLink>

        {/* Live status indicator */}
        <div className="flex items-center gap-2 px-3 py-2 mt-1">
          <span className="live-dot" />
          <span className="text-xs text-ink-faint">Live stream active</span>
        </div>
      </div>
    </aside>
  );
}
