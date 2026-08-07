Scaffold a new Next.js page for the Kali MCP Pentest frontend. The user describes the page via $ARGUMENTS.

Parse the description to determine:
1. **Route** - URL path (e.g., `/dashboard`, `/settings/notifications`)
2. **Page title** - Display name
3. **Data source** - Which `api.*` methods to call
4. **Sub-routes** - Optional detail `[id]/page.tsx` or create page

## Step 1: Create the page file

Create `frontend/app/<route>/page.tsx` following project conventions:

```tsx
'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/tauri-api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { <Icon> } from 'lucide-react';

export default function <Name>Page() {
  const [data, setData] = useState<Type[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const result = await api.<section>.list();
      setData(result);
    } catch (err) {
      console.error('Failed to load data:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="grid gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Page Title</h1>
          <p className="text-muted-foreground">Description text</p>
        </div>
        <Button>
          <Icon className="mr-2 h-4 w-4" />
          Action
        </Button>
      </div>

      {/* Empty state */}
      {data.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Icon className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No items yet</h3>
            <p className="text-muted-foreground text-sm mt-1">
              Get started by creating your first item.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {/* List/grid of items */}
        </div>
      )}
    </div>
  );
}
```

## Step 2: Add navigation entry

Edit `frontend/components/layout/sidebar.tsx`:

1. Import the icon: `import { <Icon> } from 'lucide-react';` (add to existing import)
2. Add to the `navigation` array in logical order:
```typescript
{ name: '<Display Name>', href: '/<route>', icon: <Icon> },
```

## Step 3: Create sub-routes (if needed)

For detail pages, create `frontend/app/<route>/[id]/page.tsx` with:
- Dynamic route parameter via `useParams()`
- Single-item fetch via `api.<section>.get(id)`
- Back navigation link

## Conventions to follow

- Always `'use client'` directive
- Use shadcn/ui components: Card, Button, Badge, Skeleton, ScrollArea
- Use lucide-react icons (check existing imports in sidebar.tsx for available icons)
- Use `@/lib/tauri-api` for data fetching (never raw fetch)
- Use `@/lib/utils` for `cn()` classname helper
- Loading states use `Skeleton` components
- Empty states show icon + message + action button
- Responsive: use `grid` with responsive column counts
- Color scheme: use Tailwind CSS variables (text-muted-foreground, bg-card, etc.)

## After scaffolding

1. List all created/modified files
2. Note if new types or API bridge methods are needed (point to `/project:add-command`)

---

User request: $ARGUMENTS
