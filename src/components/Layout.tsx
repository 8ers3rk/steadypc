import type { ReactNode } from 'react';
import {
  BarChart3,
  Globe,
  HelpCircle,
  History,
  LayoutDashboard,
  Moon,
  Search,
  ShieldCheck,
  Sun,
  WifiOff,
  Wrench,
  ListChecks,
} from 'lucide-react';
import type { AppInfo, Tab } from '../types';
import type { Lang } from '../i18n';

interface LayoutProps {
  children: ReactNode;
  lang: Lang;
  theme: 'light' | 'dark';
  tab: Tab;
  appInfo: AppInfo | null;
  onTab: (tab: Tab) => void;
  onToggleTheme: () => void;
  onToggleLang: () => void;
  onOpenFaq: () => void;
  t: (key: string) => string;
}

const NAV: Array<{ id: Tab; icon: typeof LayoutDashboard; key: string }> = [
  { id: 'overview', icon: LayoutDashboard, key: 'nav.overview' },
  { id: 'scan', icon: Search, key: 'nav.scan' },
  { id: 'plan', icon: ListChecks, key: 'nav.plan' },
  { id: 'tools', icon: Wrench, key: 'nav.tools' },
  { id: 'report', icon: BarChart3, key: 'nav.report' },
  { id: 'journal', icon: History, key: 'nav.journal' },
];

export function Layout({
  children,
  lang,
  theme,
  tab,
  appInfo,
  onTab,
  onToggleTheme,
  onToggleLang,
  onOpenFaq,
  t,
}: LayoutProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={22} strokeWidth={1.8} />
          </div>
          <div>
            <div className="brand-name">{t('app.name')}</div>
            <div className="brand-tagline">{t('app.tagline')}</div>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                type="button"
                className={`nav-item ${tab === item.id ? 'active' : ''}`}
                onClick={() => onTab(item.id)}
              >
                <Icon size={18} strokeWidth={1.8} />
                <span>{t(item.key)}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="offline-badge">
            <WifiOff size={14} />
            <span>{t('footer.offline')}</span>
          </div>
          <div className="sidebar-meta">
            <span>{t('footer.version')} {appInfo?.version || '—'}</span>
            <span>{t('footer.author')}</span>
            <span>{appInfo?.isAdmin ? t('common.admin') : t('common.user')}</span>
          </div>
          <div className="sidebar-actions">
            <button
              type="button"
              className="icon-button"
              onClick={onOpenFaq}
              title={t('faq.open')}
              aria-label={t('faq.open')}
            >
              <HelpCircle size={16} />
            </button>
            <button type="button" className="icon-button" onClick={onToggleTheme} title="Theme">
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <button type="button" className="icon-button lang-button" onClick={onToggleLang} title="Language">
              <Globe size={16} />
              <span>{lang.toUpperCase()}</span>
            </button>
          </div>
        </div>
      </aside>

      <main className="main-area">{children}</main>
    </div>
  );
}
