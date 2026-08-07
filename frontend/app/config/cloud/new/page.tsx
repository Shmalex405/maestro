'use client';

import { useRouter } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { CloudAccountInput } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { ChevronLeft } from 'lucide-react';
import {
  CloudAccountForm,
  makeBlankAccountInput,
} from '@/components/config/cloud-account-form';

export default function NewCloudAccountPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const addMutation = useMutation({
    mutationFn: (input: CloudAccountInput) => api.config.cloud.addAccount(input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-accounts'] });
      toast.success('Cloud account created');
      router.push('/config/cloud');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to create account: ${msg}`);
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/config/cloud')}
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back
        </Button>
      </div>

      <div>
        <h1 className="text-3xl font-bold">New Cloud Connection</h1>
        <p className="text-muted-foreground">
          Configure a new self-hosted backend. You can switch which one is active from the
          accounts list.
        </p>
      </div>

      <CloudAccountForm
        initial={makeBlankAccountInput()}
        submitLabel="Create Connection"
        showCancel
        onCancel={() => router.push('/config/cloud')}
        onSubmit={async (input) => {
          await addMutation.mutateAsync(input);
        }}
      />
    </div>
  );
}
