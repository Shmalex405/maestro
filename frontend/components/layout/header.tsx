'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { ChevronRight, Home } from 'lucide-react';
import { UserMenu } from './user-menu';

const pathNames: Record<string, string> = {
  '': 'Dashboard',
  'assessments': 'Assessments',
  'new': 'New Assessment',
  'findings': 'Findings',
  'detail': 'Detail',
  'config': 'Configuration',
  'scope': 'Scope',
  'credentials': 'Credentials',
  'tools': 'Tools',
  'llm': 'LLM',
  'integrations': 'Integrations',
  'cloud': 'Cloud',
  'audit-logs': 'Audit Logs',
  'reports': 'Reports',
  'repositories': 'Repositories',
  'import': 'Import',
};

export function Header() {
  const pathname = usePathname();
  const segments = pathname.split('/').filter(Boolean);

  const breadcrumbs = segments.map((segment, index) => {
    const href = '/' + segments.slice(0, index + 1).join('/');
    const isLast = index === segments.length - 1;
    const name = pathNames[segment] || segment.charAt(0).toUpperCase() + segment.slice(1);

    return { href, name, isLast };
  });

  return (
    <header className="h-12 border-b border-border/50 bg-background/60 backdrop-blur-md px-5 flex items-center gap-4">
      {/* Breadcrumbs */}
      <nav className="flex flex-1 items-center gap-1 text-xs">
        <Link
          href="/"
          className="text-muted-foreground hover:text-foreground transition-colors"
        >
          <Home className="h-3.5 w-3.5" />
        </Link>

        {breadcrumbs.map((crumb) => (
          <div key={crumb.href} className="flex items-center gap-1">
            <ChevronRight className="h-3 w-3 text-muted-foreground/50" />
            {crumb.isLast ? (
              <span className="font-medium text-foreground">{crumb.name}</span>
            ) : (
              <Link
                href={crumb.href}
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                {crumb.name}
              </Link>
            )}
          </div>
        ))}

        {breadcrumbs.length === 0 && (
          <>
            <ChevronRight className="h-3 w-3 text-muted-foreground/50" />
            <span className="font-medium text-foreground">Dashboard</span>
          </>
        )}
      </nav>

      <UserMenu />
    </header>
  );
}
