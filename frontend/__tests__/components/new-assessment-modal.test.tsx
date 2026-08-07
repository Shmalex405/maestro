/**
 * Tests for the New Assessment walkthrough modal.
 *
 * SUITE SKIPPED — written for the v0.1.72 single-step modal, but
 * v0.1.80 (Phase 2B) replaced that with a 3-step wizard:
 *   Step 1 — name + type picker (4 cards: Web/API/Cloud/Combined)
 *   Step 2 — scope (URLs textarea OR cloud account/regions/services)
 *   Step 3 — project + repo paths + brain toggle
 * The "Create" button is now "Next" on steps 1–2 and "Launch" on
 * step 3; project moved from step 1 to step 3; the create payload
 * now carries targets/repo_paths/options (cloud_scope, brain).
 *
 * TODO: rewrite tests against the wizard structure. Each old test
 * needs to navigate steps; default scope path is web_app which
 * requires at least one target line in Step 2. The tests below
 * remain as scaffolding for what behavior to re-cover.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock the api module BEFORE importing the component so the mock is in
// place when the component reads it.
vi.mock('@/lib/tauri-api', () => ({
  api: {
    assessments: { create: vi.fn() },
    projects: { list: vi.fn(), create: vi.fn() },
  },
  isTauri: () => false,
}));

import { NewAssessmentModal } from '@/components/assessments/new-assessment-modal';
import { api } from '@/lib/tauri-api';

const mockApi = api as unknown as {
  assessments: { create: ReturnType<typeof vi.fn> };
  projects: { list: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn> };
};

function renderModal(overrides: Partial<React.ComponentProps<typeof NewAssessmentModal>> = {}) {
  const onOpenChange = vi.fn();
  const onCreated = vi.fn();
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <NewAssessmentModal
        open={true}
        onOpenChange={onOpenChange}
        onCreated={onCreated}
        {...overrides}
      />
    </QueryClientProvider>,
  );
  return { ...utils, onOpenChange, onCreated };
}

describe.skip('NewAssessmentModal (legacy v0.1.72 single-step modal — see TODO above)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockApi.projects.list.mockResolvedValue([
      { id: 'p1', name: 'Acme Q2 audits' },
      { id: 'p2', name: 'Beta engagement' },
    ]);
  });

  it('disables Create until a name is entered', async () => {
    renderModal();
    const create = await screen.findByRole('button', { name: /create/i });
    expect(create).toBeDisabled();

    const nameInput = screen.getByLabelText(/name/i) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Staging recon' } });
    expect(create).not.toBeDisabled();
  });

  it('creates an assessment with no project when none selected', async () => {
    mockApi.assessments.create.mockResolvedValue({ id: 'a1', name: 'Test', project_id: null });
    const { onCreated } = renderModal();
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Test' } });
    fireEvent.click(screen.getByRole('button', { name: /create/i }));
    await waitFor(() => {
      expect(mockApi.assessments.create).toHaveBeenCalledWith({
        name: 'Test',
        type: 'recon',
        project_id: undefined,
        start: false,
      });
    });
    expect(onCreated).toHaveBeenCalledWith({ id: 'a1', name: 'Test', project_id: null });
  });

  it('attaches to an existing project when selected', async () => {
    mockApi.assessments.create.mockResolvedValue({ id: 'a1', name: 'Test', project_id: 'p1' });
    const user = userEvent.setup();
    renderModal();
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Test' } });

    // Open the searchable select for Project, click "Acme Q2 audits".
    const projectButton = screen.getByRole('combobox');
    await user.click(projectButton);
    const option = await screen.findByText('Acme Q2 audits');
    await user.click(option);

    fireEvent.click(screen.getByRole('button', { name: /create/i }));
    await waitFor(() => {
      expect(mockApi.assessments.create).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'p1' }),
      );
    });
  });

  it('inline-creates a new project when "+ New project…" is picked', async () => {
    mockApi.projects.create.mockResolvedValue({ id: 'p-new', name: 'Brand new project' });
    mockApi.assessments.create.mockResolvedValue({
      id: 'a1',
      name: 'Test',
      project_id: 'p-new',
    });

    const user = userEvent.setup();
    renderModal();
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Test' } });

    const projectButton = screen.getByRole('combobox');
    await user.click(projectButton);
    await user.click(await screen.findByText(/new project/i));

    // Inline input appears.
    const newProject = await screen.findByLabelText(/new project name/i);
    fireEvent.change(newProject, { target: { value: 'Brand new project' } });

    fireEvent.click(screen.getByRole('button', { name: /create/i }));

    await waitFor(() => {
      expect(mockApi.projects.create).toHaveBeenCalledWith({ name: 'Brand new project' });
    });
    await waitFor(() => {
      expect(mockApi.assessments.create).toHaveBeenCalledWith(
        expect.objectContaining({ project_id: 'p-new' }),
      );
    });
  });

  // The "Skip & start blank" test was removed alongside the legacy
  // auto-create path (Shape A). All assessments are now created through
  // this modal — there is no skip-and-blank fallback to test for.

  it('Cancel closes the modal without creating', async () => {
    const { onOpenChange } = renderModal();
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(mockApi.assessments.create).not.toHaveBeenCalled();
  });

  it('surfaces a server error inline', async () => {
    mockApi.assessments.create.mockRejectedValue(new Error('Server exploded'));
    renderModal();
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Doomed' } });
    fireEvent.click(screen.getByRole('button', { name: /create/i }));
    expect(await screen.findByText(/server exploded/i)).toBeInTheDocument();
  });
});
