import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

// Self-hosted at build time (bundled into the app) so the desktop app renders
// its real typefaces offline instead of silently falling back to system fonts.
const inter = Inter({ subsets: ['latin'], variable: '--font-inter', display: 'swap' });
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains-mono', display: 'swap' });
import { Providers } from '@/components/providers';
import { Sidebar } from '@/components/layout/sidebar';
import { Header } from '@/components/layout/header';
import { ConditionalStartupGate } from '@/components/layout/conditional-startup-gate';
import { EnvironmentStatusBar } from '@/components/layout/environment-status-bar';
import { VersionBanner } from '@/components/layout/version-banner';
import { UpdateNotification } from '@/components/layout/update-notification';
import { ReadOnlyBanner } from '@/components/layout/read-only-banner';
import { LiveAssessmentsPopup } from '@/components/live-assessments-popup';

export const metadata: Metadata = {
  title: 'Maestro - Security Assessment Platform',
  description: 'Enterprise automated ethical hacking system by Groovy Security',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`dark ${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans antialiased noise-overlay">
        <Providers>
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div className="flex flex-1 flex-col overflow-hidden">
              <Header />
              <ReadOnlyBanner />
              <UpdateNotification />
              <VersionBanner />
              <EnvironmentStatusBar />
              <main className="flex-1 overflow-auto bg-grid custom-scrollbar p-5">
                <ConditionalStartupGate>
                  <div className="animate-fade-in">
                    {children}
                  </div>
                </ConditionalStartupGate>
              </main>
            </div>
          </div>
          {/* Global live-findings popup. Renders nothing when no
              assessment is registered, so it's safe to mount at root.
              See lib/stores/live-assessments-store.ts for the data flow. */}
          <LiveAssessmentsPopup />
        </Providers>
      </body>
    </html>
  );
}
