Display the frontend codebase patterns reference for the Kali MCP Pentest project. Use this skill when you need to recall exact React/Next.js/shadcn conventions before writing frontend code.

Read and summarize patterns from these files, then present as quick-reference:

## Files to Read
- `frontend/app/repositories/page.tsx` — Reference page pattern (React Query, shadcn, dialogs)
- `frontend/app/findings/page.tsx` — Another page with filtering, badges, severity colors
- `frontend/lib/tauri-api.ts` — API bridge pattern
- `frontend/lib/types.ts` — Type definitions
- `frontend/components/layout/sidebar.tsx` — Navigation structure

## Present These Patterns

### 1. Page Structure
```tsx
'use client';
import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, isTauri } from '@/lib/tauri-api';
import type { TypeName } from '@/lib/types';
// shadcn/ui imports
// lucide-react icon imports
import { toast } from 'sonner';
```

### 2. Data Fetching (React Query)
```tsx
// List query
const { data, isLoading } = useQuery({
  queryKey: ['items'],
  queryFn: () => api.section.list(),
});

// Mutation with cache invalidation
const createMutation = useMutation({
  mutationFn: api.section.create,
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['items'] });
    toast.success('Item created');
    setDialogOpen(false);
  },
  onError: (err) => toast.error(`Failed: ${err.message}`),
});
```

### 3. API Bridge Method Pattern
```typescript
methodName: (params: ParamsType): Promise<ReturnType> =>
  isTauri()
    ? invoke('command_name', { params })
    : httpRequest('/api/endpoint', {
        method: 'POST',
        body: JSON.stringify(params),
      }),
```

### 4. Loading Skeleton
```tsx
if (isLoading) {
  return (
    <div className="space-y-6 p-6">
      <Skeleton className="h-8 w-48" />
      <div className="grid gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
    </div>
  );
}
```

### 5. Empty State
```tsx
<Card>
  <CardContent className="flex flex-col items-center justify-center py-12">
    <Icon className="h-12 w-12 text-muted-foreground mb-4" />
    <h3 className="text-lg font-medium">No items yet</h3>
    <p className="text-muted-foreground text-sm mt-1">Description</p>
  </CardContent>
</Card>
```

### 6. Severity Badge Colors
```tsx
const severityColor = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};
<Badge className={severityColor[item.severity]}>{item.severity}</Badge>
```

### 7. Dialog Pattern
```tsx
<Dialog open={open} onOpenChange={setOpen}>
  <DialogTrigger asChild>
    <Button><Plus className="mr-2 h-4 w-4" />Add</Button>
  </DialogTrigger>
  <DialogContent>
    <DialogHeader>
      <DialogTitle>Title</DialogTitle>
      <DialogDescription>Description</DialogDescription>
    </DialogHeader>
    {/* form fields */}
    <DialogFooter>
      <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
      <Button onClick={handleSubmit}>Create</Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

### 8. Available shadcn/ui Components
Already installed: button, card, badge, skeleton, scroll-area, progress, input, label, textarea, select, switch, tabs, separator, alert, tooltip, dialog, dropdown-menu, checkbox

### 9. Navigation Entry
```typescript
// In sidebar.tsx navigation array:
{ name: 'Display Name', href: '/route', icon: IconComponent },
```

### 10. Toast Notifications
```tsx
import { toast } from 'sonner';
toast.success('Created successfully');
toast.error('Failed to create');
toast.info('Processing...');
```
