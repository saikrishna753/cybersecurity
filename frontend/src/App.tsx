import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Suspense, lazy, type ReactNode } from 'react';
import { AuthProvider, useAuth } from '@/lib/auth';
import { ToastProvider, Loading, ErrorState } from '@/components/ui/toast-reexports';
import AppLayout from '@/components/AppLayout';
import LoginPage from '@/pages/LoginPage';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';

const DashboardPage = lazy(() => import('@/pages/DashboardPage'));
const LivePage = lazy(() => import('@/pages/LivePage'));
const AnalysisPage = lazy(() => import('@/pages/AnalysisPage'));
const PcapPage = lazy(() => import('@/pages/PcapPage'));
const DetectionPage = lazy(() => import('@/pages/DetectionPage'));
const AlertsPage = lazy(() => import('@/pages/AlertsPage'));
const IncidentsPage = lazy(() => import('@/pages/IncidentsPage'));
const ModelsPage = lazy(() => import('@/pages/ModelsPage'));
const ExplainabilityPage = lazy(() => import('@/pages/ExplainabilityPage'));
const ThreatIntelPage = lazy(() => import('@/pages/ThreatIntelPage'));
const ReportsPage = lazy(() => import('@/pages/ReportsPage'));
const SettingsPage = lazy(() => import('@/pages/SettingsPage'));
const ProfilePage = lazy(() => import('@/pages/ProfilePage'));
const DatasetsPage = lazy(() => import('@/pages/DatasetsPage'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false },
  },
});

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <Loading label="Restoring session…" />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/** Subscribes WS events → invalidates relevant queries for live refresh. */
function LiveRefresher({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  useEffect(() => {
    // nothing here; handler wired below
  }, [qc]);
  useWebSocket((ev) => {
    if (ev.type === 'stats_update' || ev.type === 'detection_event' || ev.type === 'alert_event') {
      qc.invalidateQueries({ queryKey: ['stats'] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['detections'] });
      qc.invalidateQueries({ queryKey: ['alert-summary'] });
      qc.invalidateQueries({ queryKey: ['flows'] });
    }
    if (ev.type === 'capture_status') {
      qc.invalidateQueries({ queryKey: ['capture'] });
    }
  });
  return <>{children}</>;
}

function PageFallback() {
  return <Loading label="Loading module…" />;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route
                element={
                  <RequireAuth>
                    <LiveRefresher>
                      <AppLayout />
                    </LiveRefresher>
                  </RequireAuth>
                }
              >
                <Route index element={<Suspense fallback={<PageFallback />}><DashboardPage /></Suspense>} />
                <Route path="live" element={<Suspense fallback={<PageFallback />}><LivePage /></Suspense>} />
                <Route path="analysis" element={<Suspense fallback={<PageFallback />}><AnalysisPage /></Suspense>} />
                <Route path="pcap" element={<Suspense fallback={<PageFallback />}><PcapPage /></Suspense>} />
                <Route path="detection" element={<Suspense fallback={<PageFallback />}><DetectionPage /></Suspense>} />
                <Route path="alerts" element={<Suspense fallback={<PageFallback />}><AlertsPage /></Suspense>} />
                <Route path="incidents" element={<Suspense fallback={<PageFallback />}><IncidentsPage /></Suspense>} />
                <Route path="datasets" element={<Suspense fallback={<PageFallback />}><DatasetsPage /></Suspense>} />
                <Route path="models" element={<Suspense fallback={<PageFallback />}><ModelsPage /></Suspense>} />
                <Route path="explainability" element={<Suspense fallback={<PageFallback />}><ExplainabilityPage /></Suspense>} />
                <Route path="threat-intel" element={<Suspense fallback={<PageFallback />}><ThreatIntelPage /></Suspense>} />
                <Route path="reports" element={<Suspense fallback={<PageFallback />}><ReportsPage /></Suspense>} />
                <Route path="settings" element={<Suspense fallback={<PageFallback />}><SettingsPage /></Suspense>} />
                <Route path="profile" element={<Suspense fallback={<PageFallback />}><ProfilePage /></Suspense>} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

// re-export barrel keeps the import above simple
export { ErrorState };
