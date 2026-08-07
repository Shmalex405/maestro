Scaffold a UI component for the Kali MCP Pentest frontend. The user describes the component via $ARGUMENTS.

Parse the description to determine:
1. **Component name** (PascalCase)
2. **Type** - shadcn/ui primitive to install OR custom component
3. **Location** - `components/ui/` for primitives, `components/<feature>/` for custom

## Option A: Install a shadcn/ui Primitive

If the user wants a standard shadcn/ui component (dialog, dropdown-menu, tabs, etc.):

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend
npx shadcn@latest add <component-name>
```

This automatically creates the component in `components/ui/<name>.tsx` with proper styling.

Already installed shadcn/ui components (do NOT reinstall):
- button, card, badge, skeleton, scroll-area, progress, input, label, textarea
- select, switch, tabs, separator, alert, tooltip

## Option B: Create a Custom Component

Create `frontend/components/<feature>/<ComponentName>.tsx`:

```tsx
'use client';

import { cn } from '@/lib/utils';
// Import shadcn/ui primitives as needed
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { <Icon> } from 'lucide-react';

interface <ComponentName>Props {
  // Define props
  className?: string;
}

export function <ComponentName>({ className, ...props }: <ComponentName>Props) {
  return (
    <div className={cn('', className)}>
      {/* Component content */}
    </div>
  );
}
```

## Conventions

- Use `cn()` from `@/lib/utils` for conditional classnames
- Import icons from `lucide-react`
- Use shadcn/ui primitives as building blocks
- Props interface defined above component
- Export as named export (not default)
- Use Tailwind CSS with project theme variables:
  - `bg-card`, `text-card-foreground` for card surfaces
  - `bg-primary`, `text-primary-foreground` for primary actions
  - `text-muted-foreground` for secondary text
  - `border` for borders
  - `bg-destructive` for error/danger states
- Severity colors: use Badge with variant:
  - critical/high: `variant="destructive"`
  - medium: `className="bg-yellow-500"`
  - low/info: `variant="secondary"`

## After scaffolding

1. Show the created file
2. Provide an example of how to import and use the component
3. Note any shadcn/ui primitives that need to be installed first

---

User request: $ARGUMENTS
