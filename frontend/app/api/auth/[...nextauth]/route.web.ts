import { handlers } from '@/lib/auth';

// This route file uses the .web.ts extension so it is only included in
// standalone (web) builds and excluded from static export (desktop) builds.
export const { GET, POST } = handlers;
