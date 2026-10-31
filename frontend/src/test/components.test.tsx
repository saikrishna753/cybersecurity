import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { severityClass, statusClass, CHART_COLORS } from '@/lib/tokens';
import type { Severity } from '@/types/contract';

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Critical</Badge>);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('applies variant classes', () => {
    render(<Badge variant="destructive">High</Badge>);
    expect(screen.getByText('High')).toBeInTheDocument();
  });
});

describe('design tokens', () => {
  it('maps every severity to css classes', () => {
    const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
    for (const s of severities) {
      expect(severityClass[s]).toBeTruthy();
    }
  });

  it('maps alert workflow statuses', () => {
    for (const s of ['New', 'Acknowledged', 'Investigating', 'Resolved', 'False Positive'] as const) {
      expect(statusClass[s]).toBeTruthy();
    }
  });

  it('provides chart palette', () => {
    expect(CHART_COLORS.length).toBeGreaterThanOrEqual(5);
  });
});

describe('App routing smoke', () => {
  it('renders login page without crashing', async () => {
    const { default: LoginPage } = await import('@/pages/LoginPage');
    const { AuthProvider } = await import('@/lib/auth');
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );
    expect(screen.getByText(/sign in/i)).toBeInTheDocument();
  });
});
