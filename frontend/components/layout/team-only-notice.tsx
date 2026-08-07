'use client';

// Shown in place of a team-only feature when running in local mode.
//
// The point is to replace an empty panel with an explanation. Without this, a
// local install opening /graph would fire a cloudRequest, get "No cloud backend
// configured", and render a blank page — indistinguishable from a bug. These
// features are absent by design (they need Postgres-native schema the local DB
// has no equivalent for), so saying that plainly is the whole job.
//
// Usage:
//   const reason = featureUnavailableReason('attack-graph');
//   if (reason) return <TeamOnlyNotice feature="attack-graph" title="Attack Graph" />;

import Link from 'next/link';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { PageHeader } from './page-header';
import { featureUnavailableReason, type TeamOnlyFeature } from '@/lib/deployment-mode';
import { Cloud, ArrowRight } from 'lucide-react';

interface Props {
  feature: TeamOnlyFeature;
  /** Page title, so the notice reads as the page rather than an error on it. */
  title: string;
  description?: string;
}

export function TeamOnlyNotice({ feature, title, description }: Props) {
  const reason = featureUnavailableReason(feature);

  return (
    <div className="space-y-5">
      <PageHeader title={title} description={description} />

      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-muted p-2 text-muted-foreground">
              <Cloud className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-base">Available in team mode</CardTitle>
              <CardDescription>
                This install is running in local mode.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            {reason ??
              'This feature needs a team backend. Deploy one to enable it.'}
          </p>
          <p className="text-sm text-muted-foreground">
            Everything else is unaffected — assessments, findings, severity
            calibration, oracle verification and reports all work locally.
          </p>
          <Button asChild size="sm" variant="outline">
            <Link href="/config/data-sync">
              Set up a team backend
              <ArrowRight className="ml-2 h-3 w-3" />
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
