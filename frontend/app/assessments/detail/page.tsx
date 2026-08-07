'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense } from 'react';

function RedirectContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const id = searchParams.get('id');

  useEffect(() => {
    if (id) {
      router.replace(`/assessments?id=${id}`);
    } else {
      router.replace('/assessments');
    }
  }, [id, router]);

  return null;
}

/**
 * Redirect to main assessments page — the dual-view container handles detail.
 */
export default function AssessmentDetailPage() {
  return (
    <Suspense fallback={null}>
      <RedirectContent />
    </Suspense>
  );
}
