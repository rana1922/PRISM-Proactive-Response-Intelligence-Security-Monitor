import React, { useState, useEffect } from 'react';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Radio, 
  FileText, 
  Network, 
  Server, 
  Zap, 
  Shield, 
  Activity,
  CheckCircle,
  AlertOctagon,
  ChevronRight,
  Menu,
  X
} from 'lucide-react';
import { Header, NavTab } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { AttackSimulatorView } from './components/AttackSimulatorView';
import { LiveAlertsView } from './components/LiveAlertsView';
import { IncidentsView } from './components/IncidentsView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { CVEIntelligenceView } from './components/CVEIntelligenceView';
import { ResponseActionsView } from './components/ResponseActionsView';
import { DetectionRulesView } from './components/DetectionRulesView';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { AlertRecord, DashboardSummary } from './types';
import { api } from './services/api';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [isDemoActive, setIsDemoActive] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<{ title: string; desc: string; alert?: AlertRecord } | null>(null);

  const fetchSummary = async () => {
    try {
      const data = await api.getSummary();
      setSummary(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchSummary();
    const interval = setInterval(fetchSummary, 6000);
    return () => clearInterval(interval);
  }, []);

  // Listen to SSE live stream for real-time updates and notification banners
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource('/api/stream/alerts');
      es.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed.type === 'ALERT_CREATED' && parsed.payload?.alert) {
            const newAlert: AlertRecord = parsed.payload.alert;
            if (parsed.payload.summary) {
              setSummary(parsed.payload.summary);
            }
            if (newAlert.severity === 'CRITICAL') {
              setToastMessage({
                title: `[CRITICAL] ${newAlert.attack_type.replace('_', ' ')} Detected`,
                desc: `Source: ${newAlert.source_ip} · Score: ${newAlert.threat_score}/100 · Simulated Mitigation Executed`,
                alert: newAlert
              });
              setTimeout(() => {
                setToastMessage(null);
              }, 6000);
            }
          }
        } catch {
          // ignore
        }
      };
    } catch (e) {
      console.error(e);
    }
    return () => {
      if (es) es.close();
    };
  }, []);

  const handleToggleDemo = async () => {
    try {
      const res = await api.toggleDemo();
      setIsDemoActive(res.is_demo_active);
    } catch (err) {
      console.error(err);
    }
  };

  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'simulator' as NavTab, label: 'Attack Simulator', icon: AlertTriangle, highlight: true },
    { id: 'alerts' as NavTab, label: 'Live Alerts', icon: Radio },
    { id: 'incidents' as NavTab, label: 'Incidents', icon: FileText },
    { id: 'ioc' as NavTab, label: 'Threat Intel (IOC)', icon: Network },
    { id: 'cve' as NavTab, label: 'CVE Intelligence', icon: Server },
    { id: 'responses' as NavTab, label: 'Responses & Audit', icon: Zap },
    { id: 'rules' as NavTab, label: 'Detection Rules', icon: Shield },
  ];

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans selection:bg-rose-500/30">
      {/* Top Bar */}
      <Header
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isDemoActive={isDemoActive}
        onToggleDemo={handleToggleDemo}
        systemStatus={summary?.system_status || 'healthy'}
        responseMode={summary?.response_mode || 'SIMULATION'}
        onLaunchSimulator={() => setCurrentTab('simulator')}
      />

      {/* Real-time Toast Notification for incoming critical threats */}
      {toastMessage && (
        <div className="fixed top-16 right-6 z-50 max-w-md p-4 rounded-lg bg-slate-900 border-2 border-rose-500 shadow-2xl shadow-rose-950/80 animate-in slide-in-from-top-4 duration-300">
          <div className="flex items-start justify-between gap-3">
            <div className="p-2 rounded bg-rose-950/80 text-rose-400 shrink-0">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div className="space-y-1 flex-1">
              <h4 className="text-xs font-bold text-white uppercase tracking-wide">
                {toastMessage.title}
              </h4>
              <p className="text-xs text-slate-300 font-mono">
                {toastMessage.desc}
              </p>
              {toastMessage.alert && (
                <button
                  onClick={() => {
                    setSelectedAlert(toastMessage.alert!);
                    setToastMessage(null);
                  }}
                  className="mt-2 text-xs font-semibold text-rose-400 hover:text-rose-300 flex items-center gap-1"
                >
                  <span>Inspect Incident</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            <button
              onClick={() => setToastMessage(null)}
              className="text-slate-400 hover:text-white text-xs"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Main Layout Container (Sidebar + Content) */}
      <div className="flex-1 flex max-w-[1600px] w-full mx-auto">
        {/* Desktop Sidebar Navigation */}
        <aside className="hidden md:flex flex-col w-64 p-4 border-r border-slate-800/80 space-y-6 shrink-0 bg-slate-950/40">
          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3">
              Operations Center
            </span>
            <div className="space-y-1 pt-1">
              {navItems.map(item => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setCurrentTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded transition-all ${
                      isActive
                        ? 'bg-slate-800 text-white font-semibold border-l-2 border-rose-500 shadow-sm'
                        : item.highlight
                        ? 'text-rose-400 hover:text-rose-300 hover:bg-slate-900/60'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-rose-400' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.id === 'simulator' && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-800/40 font-mono">
                        DEMO
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Quick Telemetry Widget */}
          <div className="mt-auto p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px]">Engine Status</span>
              <span className="text-emerald-400 flex items-center gap-1 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px]">Safety Policy</span>
              <span className="text-slate-200">SIMULATION</span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px]">Active Rules</span>
              <span className="text-slate-200">5 / 5 Enabled</span>
            </div>
          </div>
        </aside>

        {/* Content Viewport */}
        <main className="flex-1 p-4 md:p-6 lg:p-8 overflow-y-auto">
          {currentTab === 'dashboard' && (
            <DashboardView
              summary={summary}
              onViewAlertDetail={setSelectedAlert}
              onNavigateToTab={setCurrentTab}
            />
          )}

          {currentTab === 'simulator' && (
            <AttackSimulatorView
              onAlertGenerated={(alert) => {
                fetchSummary();
                setSelectedAlert(alert);
              }}
              onViewAlertDetail={setSelectedAlert}
            />
          )}

          {currentTab === 'alerts' && (
            <LiveAlertsView
              onViewAlertDetail={setSelectedAlert}
            />
          )}

          {currentTab === 'incidents' && (
            <IncidentsView
              onViewAlertDetail={setSelectedAlert}
            />
          )}

          {currentTab === 'ioc' && (
            <ThreatIntelView />
          )}

          {currentTab === 'cve' && (
            <CVEIntelligenceView />
          )}

          {currentTab === 'responses' && (
            <ResponseActionsView />
          )}

          {currentTab === 'rules' && (
            <DetectionRulesView />
          )}
        </main>
      </div>

      {/* Incident Detail Drawer / Modal */}
      <IncidentDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAlertUpdated={(updatedAlert) => {
          setSelectedAlert(updatedAlert);
          fetchSummary();
        }}
      />
    </div>
  );
}
