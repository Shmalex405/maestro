'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/**
 * Redirect to main assessments page — the welcome screen handles new assessment flow.
 */
export default function NewAssessmentPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace('/assessments');
  }, [router]);

  return null;
}
