'use client';

// =============================================================================
// Scheduled DAST section layout.
//
// Breaks out of the root <main> padding (-m-5) to render a nested second
// sidebar flush against the content for every /scheduled/* route, wrapped in
// the section provider (shared data, mutations, dialogs). The main Maestro
// sidebar (rendered by the root layout) stays visible alongside.
// =============================================================================

import { Zap, CalendarClock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DastSidebar } from '@/components/scheduled/dast-sidebar';
import { ScheduledDastProvider, useScheduledDast } from '@/components/scheduled/dast-context';

function SectionActions() {
  const { openSchedule, openRun } = useScheduledDast();
  return (
    <div className="flex items-center gap-2">
      <Button variant="outline" size="sm" onClick={openSchedule}>
        <CalendarClock className="mr-1.5 h-4 w-4" /> Schedule a target
      </Button>
      <Button size="sm" onClick={openRun}>
        <Zap className="mr-1.5 h-4 w-4" /> Run DAST scan
      </Button>
    </div>
  );
}

export default function ScheduledLayout({ children }: { children: React.ReactNode }) {
  return (
    <ScheduledDastProvider>
      <div className="-m-5 flex min-h-[calc(100vh-3rem)]">
        <DastSidebar />
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-end border-b border-border/40 px-5 py-2.5">
            <SectionActions />
          </div>
          <div className="p-5">{children}</div>
        </div>
      </div>
    </ScheduledDastProvider>
  );
}
