'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SessionProvider } from 'next-auth/react';
import { useState } from 'react';
import { Toaster } from '@/components/ui/sonner';
import { isWebMode } from '@/lib/deploy-mode';
import { useAuthRefresh } from '@/hooks/use-auth-refresh';

export function Providers({ children }: { children: React.ReactNode }) {
  useAuthRefresh(); // Background token refresh for desktop mode

  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30 * 1000, // 30 seconds
            refetchOnWindowFocus: false,
          },
        },
      })
  );

  const content = (
    <QueryClientProvider client={queryClient}>
      {children}
      <Toaster position="bottom-right" />
    </QueryClientProvider>
  );

  if (isWebMode()) {
    return <SessionProvider>{content}</SessionProvider>;
  }

  return content;
}
