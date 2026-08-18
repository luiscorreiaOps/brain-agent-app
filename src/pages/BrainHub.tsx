import React, { useEffect, useState } from 'react';
import '../styles/brain.css';

import { getBackendSrv, config, getAppEvents } from '@grafana/runtime';
import { Icon } from '@grafana/ui';
import { AppEvents } from '@grafana/data';

// Grafana's own toast (themed, dismissible, non-blocking) instead of a
// native alert() -- a blocking browser dialog stalls the whole tab for
// what's just a success/failure notice, and looks out of place embedded in
// a Grafana page.
function notify(type: 'success' | 'error', message: string): void {
  const appEvent = type === 'success' ? AppEvents.alertSuccess : AppEvents.alertError;
  getAppEvents().publish({ type: appEvent.name, payload: [message] });
}

const SETTINGS_URL = '/api/plugins/brain-agent/settings';

// Minimal shape this page actually reads off Grafana's /api/plugins list
// response (see the agent-ai-fork detection effect below) -- that endpoint
// returns much more per plugin, but id/name are all this page uses.
interface DetectedAgentPlugin {
  id: string;
  name?: string;
}

interface MemoryRecord {
  id: number;
  fact: string;
  type?: string;
  tags?: string;
  service?: string;
  namespace?: string;
  source?: string;
  confidence?: number;
  status: string;
  piiDetected?: boolean;
}

// Persists one jsonData field for real (Settings in pkg/plugin/app.go) --
// these toggles used to only write to localStorage, which never reached the
// backend that actually reads them (SearchMemory's semantic-search gate,
// the strict-tenancy fallback, the auto-learn poller). Reads the live
// settings first so this never clobbers fields this component doesn't
// manage (e.g. BrainConfig's grafanaURL).
async function savePluginSetting(key: string, value: boolean): Promise<void> {
  const current = await getBackendSrv().get(SETTINGS_URL);
  await getBackendSrv().post(SETTINGS_URL, {
    enabled: true,
    pinned: true,
    jsonData: { ...current?.jsonData, [key]: value },
  });
}

export function BrainHub() {
  // Recomputed every render (security-audit finding L7) -- this used to be
  // a module-scope const, evaluated once at first import and frozen for the
  // lifetime of the JS module in this tab, never reflecting a role change
  // (e.g. an admin changing this user's org role) without a full page reload.
  // The real enforcement is server-side (see requireEditorOrAdmin in
  // resources.go, which 403s a Viewer's call regardless of what the UI
  // does) -- this only hides/disables the controls so a Viewer isn't shown
  // actions they can't actually perform. Approving/rejecting a Pending
  // Suggestion is the deliberate exception -- Viewers can do that too, so
  // those two buttons never check canEdit.
  const canEdit = config.bootData.user.orgRole === 'Admin' || config.bootData.user.orgRole === 'Editor';

  const [agentStatus, setAgentStatus] = useState<'checking' | 'green' | 'yellow' | 'red'>('checking');
  const [agentPlugins, setAgentPlugins] = useState<DetectedAgentPlugin[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [inTransitEnabled, setInTransitEnabled] = useState(false);
  const [semanticSearch, setSemanticSearch] = useState(true);
  const [autoLearning, setAutoLearning] = useState(false);
  const [strictTenancy, setStrictTenancy] = useState(true);
  const [autoLearnMissingGrafanaConn, setAutoLearnMissingGrafanaConn] = useState(false);
  const [atRestEncryption, setAtRestEncryption] = useState(false);
  const [settingsLoadError, setSettingsLoadError] = useState(false);
  const [expandedProjects, setExpandedProjects] = useState(false);
  const [expandedPending, setExpandedPending] = useState(false);
  const [viewingProject, setViewingProject] = useState<string | null>(null);
  const [viewingFacts, setViewingFacts] = useState<MemoryRecord[]>([]);
  const [pendingFacts, setPendingFacts] = useState<Record<string, MemoryRecord[]>>({});

  const loadToggleSettings = () => {
    // Load the real toggle state from the plugin's own settings (jsonData)
    // -- semanticSearchEnabled/strictTenancyEnabled default to true (unset
    // means "on", matching Settings' nil-is-true convention in the Go
    // backend); autoLearnAlerts defaults to false (needs a Grafana
    // URL/token configured in Configuration before it can do anything).
    getBackendSrv()
      .get(SETTINGS_URL, undefined, undefined, { showErrorAlert: false })
      .then((res) => {
        const jsonData = res?.jsonData || {};
        setSemanticSearch(jsonData.semanticSearchEnabled !== false);
        setStrictTenancy(jsonData.strictTenancyEnabled !== false);
        setAutoLearning(jsonData.autoLearnAlerts === true);
        setAutoLearnMissingGrafanaConn(!jsonData.grafanaURL);
        setAtRestEncryption(jsonData.atRestEncryptionEnabled === true);
        setInTransitEnabled(jsonData.inTransitEncryptionEnabled === true);
        setSettingsLoadError(false);
      })
      .catch((err) => {
        // Don't let a transient network blip silently paint every toggle as
        // "off" -- that's indistinguishable from actually being off, and led
        // to reports of toggles "resetting on reload" when the real saved
        // value never changed. Surface it instead (see the Brain Toggles
        // card banner) and let the toggles stay disabled until a retry.
        console.error('Failed to fetch brain-agent settings', err);
        setSettingsLoadError(true);
      });
  };

  useEffect(() => {
    loadToggleSettings();
  }, []);

  useEffect(() => {
    // In-transit encryption status now comes from loadToggleSettings above
    // (real plugin settings, see security-audit finding M3) -- this effect
    // used to also fetch /encryption_in_transit/status separately here.
    // Detect agent-ai forks
    getBackendSrv()
      .get('/api/plugins', { enabled: 1 }, undefined, { showErrorAlert: false })
      .then(async (plugins) => {
        let foundAgents: DetectedAgentPlugin[] = plugins.filter((p: DetectedAgentPlugin) => p.id && p.id.includes('agent-ai'));
        // Sort to prefer original repo
        foundAgents.sort((a: DetectedAgentPlugin, b: DetectedAgentPlugin) => {
          if (a.id === 'agent-ai-app') return -1;
          if (b.id === 'agent-ai-app') return 1;
          return 0;
        });
        
        foundAgents = foundAgents.slice(0, 2);
        
        if (foundAgents.length === 0) {
          setAgentStatus('red');
          return;
        }

        setAgentPlugins(foundAgents);

        // Check health of primary agent
        try {
          const res = await getBackendSrv().get(`/api/plugins/${foundAgents[0].id}/resources/health`, undefined, undefined, { showErrorAlert: false });
          if (res && res.status === 'error') {
            setAgentStatus('yellow');
          } else {
            setAgentStatus('green');
          }
        } catch (e) {
          setAgentStatus('yellow');
        }
      })
      .catch((err) => {
        console.error('Failed to fetch plugins', err);
        setAgentStatus('red');
      });

    // Fetch memory stats
    getBackendSrv()
      .get('/api/plugins/brain-agent/resources/stats', undefined, undefined, { showErrorAlert: false })
      .then((res) => {
        if (res) {
          setStats(res);
          // Pending suggestions can exist even for a project with 0
          // approved facts yet, so always check "default" too, not just
          // the projects stats already knows about.
          const projects = Array.from(new Set([...Object.keys(res), 'default']));
          projects.forEach(refreshPendingForProject);
        }
      })
      .catch((err) => {
        console.error('Failed to fetch stats', err);
      });

    // A brand-new project with only a pending suggestion (no approved
    // facts yet) never appears in /stats above -- this is the only way
    // the Pending Suggestions card learns about it.
    getBackendSrv()
      .get('/api/plugins/brain-agent/resources/pending_facts/projects', undefined, undefined, { showErrorAlert: false })
      .then((res) => {
        (res?.projects || []).forEach(refreshPendingForProject);
      })
      .catch((err) => {
        console.error('Failed to fetch projects with pending suggestions', err);
      });
  }, []);

  const refreshPendingForProject = (project: string) => {
    getBackendSrv()
      .get(`/api/plugins/brain-agent/resources/pending_facts?project=${encodeURIComponent(project)}`, undefined, undefined, { showErrorAlert: false })
      .then((res) => {
        setPendingFacts((prev) => ({ ...prev, [project]: res?.facts || [] }));
      })
      .catch((err) => console.error('Failed to fetch pending facts', err));
  };

  const handleApprovePending = (project: string, id: number) => {
    getBackendSrv()
      .post(`/api/plugins/brain-agent/resources/pending_facts/approve?id=${id}`)
      .then(() => {
        refreshPendingForProject(project);
        getBackendSrv().get('/api/plugins/brain-agent/resources/stats').then((res) => res && setStats(res));
      })
      .catch((err) => {
        console.error(err);
        notify('error', 'Failed to approve suggestion');
      });
  };

  const handleRejectPending = (project: string, id: number) => {
    getBackendSrv()
      .post(`/api/plugins/brain-agent/resources/pending_facts/reject?id=${id}`)
      .then(() => refreshPendingForProject(project))
      .catch((err) => {
        console.error(err);
        notify('error', 'Failed to reject suggestion');
      });
  };

  const handleManage = (project: string) => {
    if (confirm(`Do you want to clear all memory facts for project: ${project}?`)) {
      getBackendSrv()
        .delete(`/api/plugins/brain-agent/resources/memory?project_id=${encodeURIComponent(project)}`)
        .then(() => {
          notify('success', 'Memory cleared successfully!');
          if (viewingProject === project) {
            setViewingProject(null);
          }
          // Refresh stats
          getBackendSrv()
            .get('/api/plugins/brain-agent/resources/stats')
            .then((res) => {
              if (res) {
                setStats(res);
              }
            });
        })
        .catch((err) => {
          console.error(err);
          notify('error', 'Failed to clear memory');
        });
    }
  };

  const handleViewFacts = (project: string) => {
    if (viewingProject === project) {
      setViewingProject(null);
      return;
    }
    getBackendSrv()
      .get(`/api/plugins/brain-agent/resources/facts?project=${encodeURIComponent(project)}`)
      .then((res) => {
        setViewingFacts((res?.facts || []) as MemoryRecord[]);
        setViewingProject(project);
      })
      .catch((err) => {
        console.error('Failed to fetch facts', err);
        notify('error', 'Failed to load facts for this project');
      });
  };

  const handleClearAll = () => {
    if (confirm(`Do you want to completely WIPE all stored memories for all projects?`)) {
      getBackendSrv()
        .delete(`/api/plugins/brain-agent/resources/memory?project_id=all`)
        .then(() => {
          notify('success', 'All memories cleared successfully!');
          setStats({});
        })
        .catch((err) => {
          console.error(err);
          notify('error', 'Failed to clear memories');
        });
    }
  };

  // Goes through Grafana's own settings API now (savePluginSetting), same
  // as every other toggle on this page -- used to POST to a custom
  // resource route backed by a /tmp sentinel file both this plugin and
  // agent-ai-app read directly off the shared pod filesystem, which didn't
  // survive a pod restart and wasn't safe with more than one replica
  // (security-audit finding M3).
  const handleToggleInTransit = (next: boolean) => {
    setInTransitEnabled(next);
    savePluginSetting('inTransitEncryptionEnabled', next).catch(() => {
      setInTransitEnabled(!next);
      notify('error', 'Failed to toggle encryption in-transit');
    });
  };

  return (
    <div className="brain-hub-container">
      <div className={`brain-status-banner${agentStatus === 'green' ? ' is-connected' : ''}`}>
        <div className="status-text" style={{ display: 'flex', alignItems: 'center' }}>
          <img src="public/plugins/brain-agent/img/brain-logo.png" alt="Brain Logo" style={{ width: '76px', height: '76px', marginRight: '16px', filter: 'saturate(1.25) drop-shadow(0 0 3px rgba(255,255,255,0.04))', borderRadius: '50%' }} />
          <div>
            <h2>Brain Connection</h2>
            <p>
              {agentStatus === 'checking' ? 'Checking for Agent AI integration...' : 
               agentStatus === 'red' ? 'Searching for Agent AI plugin in the Grafana ecosystem...' : 
               agentStatus === 'yellow' ? 'Agent AI detected, but health check failed (bad config).' :
               `Agent AI detected (${agentPlugins.map(p => p.name || p.id).join(', ')}). MCP interface is fully synchronized.`}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <div className="status-indicator">
            <span>{agentStatus === 'checking' ? 'CHECKING' : (agentStatus === 'green' ? 'INTEGRATED' : (agentStatus === 'yellow' ? 'NEEDS CONFIG' : 'DISCONNECTED'))}</span>
            <div className={`status-dot ${agentStatus}`} style={agentStatus === 'checking' ? { backgroundColor: '#ffd60a', boxShadow: '0 0 10px #ffd60a' } : {}}></div>
          </div>
          <button 
            type="button" 
            className="brain-config-button"
            title="Plugin configuration"
            onClick={() => { window.location.href = '/plugins/brain-agent?page=configuration'; }}
          >
            <Icon name="cog" size="xl" />
          </button>
        </div>
      </div>

      <div className="brain-grid">
        <div className="brain-main-column">
          <div className="brain-card">
            <h3>Capabilities</h3>
            <div className="zero-config-feature">
              <div className="feature-icon"><Icon name="database" size="lg" style={{ color: '#fff' }} /></div>
              <div className="feature-details">
                <h4>Contextual Memory Engine</h4>
                <p>Stores user preferences, system architecture, and historical facts locally in SQLite. Agent AI automatically uses this context to answer complex questions without requiring additional prompts.</p>
              </div>
            </div>
            <div className="zero-config-feature">
              <div className="feature-icon"><Icon name="search" size="lg" style={{ color: '#fff' }} /></div>
              <div className="feature-details">
                <h4>Incident Memory & Runbooks</h4>
                <p>Automatically turns resolved Grafana alerts into searchable knowledge, including labels, runbook links, and dashboard links when available, so similar incidents can be surfaced during future outages. Similar facts can also be distilled into a single "golden record" runbook to keep incident history clean over time.</p>
              </div>
            </div>
            <div className="zero-config-feature">
              <div className="feature-icon"><Icon name="sitemap" size="lg" style={{ color: '#fff' }} /></div>
              <div className="feature-details">
                <h4>Automated Root Cause Investigation</h4>
                <p>When you ask about a firing alert, the assistant automatically retrieves the relevant logs and traces, cross-references Brain Agent's memory for similar past incidents, and presents the findings in a single step.</p>
              </div>
            </div>
            <div className="zero-config-feature">
              <div className="feature-icon"><Icon name="bolt" size="lg" style={{ color: '#fff' }} /></div>
              <div className="feature-details">
                <h4>Low-Latency Execution</h4>
                <p>Native execution within the Grafana backend (written in Go) minimizes overhead, streaming MCP JSON-RPC data at near real-time speeds.</p>
              </div>
            </div>
          </div>

          <div className="brain-card">
            <h3>Active Contexts & Projects</h3>
            <p style={{ color: '#8e95a3', fontSize: '0.9rem' }}>Memory is isolated per project to ensure relevant context and security.</p>
            <div className="project-list">
              {Object.keys(stats).length === 0 ? (
                <div style={{ color: '#8e95a3', fontStyle: 'italic', padding: '10px 0' }}>No memory facts stored yet. Use the Agent AI to store some memories!</div>
              ) : (
                <>
                  {Object.entries(stats).slice(0, expandedProjects ? 100 : 3).map(([project, count]) => (
                    <div key={project}>
                      <div
                        className="project-item"
                        onClick={() => canEdit && handleViewFacts(project)}
                        style={{ cursor: canEdit ? 'pointer' : 'default', transition: 'background 0.2s' }}
                        onMouseOver={(e) => { if (canEdit) { e.currentTarget.style.background = 'rgba(0, 0, 0, 0.3)'; } }}
                        onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(0, 0, 0, 0.2)'; }}
                      >
                        <div className="project-item-info">
                          <strong>{project === 'default' ? 'Global Default' : project}</strong>
                          <span>{count} {count === 1 ? 'fact' : 'facts'} stored</span>
                        </div>
                        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                          {viewingProject === project && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleManage(project); }}
                              disabled={!canEdit}
                              style={{ padding: '6px 12px', background: 'transparent', border: '1px solid rgba(255, 69, 58, 0.3)', borderRadius: '6px', color: 'rgba(255, 69, 58, 0.7)', fontSize: '0.85rem', cursor: canEdit ? 'pointer' : 'not-allowed', opacity: canEdit ? 1 : 0.5, fontWeight: 500, transition: 'all 0.2s' }}
                              onMouseOver={(e) => { if (canEdit) { e.currentTarget.style.background = 'rgba(255, 69, 58, 0.15)'; e.currentTarget.style.color = '#ff453a'; e.currentTarget.style.borderColor = '#ff453a'; } }}
                              onMouseOut={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'rgba(255, 69, 58, 0.7)'; e.currentTarget.style.borderColor = 'rgba(255, 69, 58, 0.3)'; }}
                            >
                              Clear Data
                            </button>
                          )}
                          {canEdit && (
                            <Icon
                              name={viewingProject === project ? 'angle-up' : 'angle-down'}
                              style={{ color: '#8e95a3' }}
                            />
                          )}
                        </div>
                      </div>
                      {viewingProject === project && (
                        <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', marginTop: '-4px', marginBottom: '10px' }}>
                          {viewingFacts.length === 0 ? (
                            <div style={{ color: '#8e95a3', fontStyle: 'italic', fontSize: '0.85rem' }}>No facts to show.</div>
                          ) : (
                            <ul style={{ margin: 0, paddingLeft: '18px' }}>
                              {viewingFacts.map((record) => (
                                <li key={record.id} style={{ color: '#d6dae2', fontSize: '0.85rem', marginBottom: '6px' }}>
                                  {record.fact}
                                  {(record.type || record.service || record.namespace || record.tags || record.piiDetected) && (
                                    <div style={{ marginTop: '4px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                      {record.type && <span className="memory-badge">{record.type}</span>}
                                      {record.service && <span className="memory-badge">service: {record.service}</span>}
                                      {record.namespace && <span className="memory-badge">ns: {record.namespace}</span>}
                                      {record.tags && <span className="memory-badge">{record.tags}</span>}
                                      {record.piiDetected && (
                                        <span className="memory-badge" title="Heuristic scan matched a pattern that looks like PII (email, CPF, IP, card-shaped digits, or a long token). Not a compliance guarantee -- review the fact text yourself." style={{ background: 'rgba(255, 69, 58, 0.15)', color: '#ff453a', border: '1px solid rgba(255, 69, 58, 0.4)' }}>⚠ possible PII</span>
                                      )}
                                    </div>
                                  )}
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  {Object.keys(stats).length > 3 && (
                    <button
                      onClick={() => setExpandedProjects(!expandedProjects)}
                      style={{ marginTop: '8px', padding: '10px', width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#e2e8f0', cursor: 'pointer', fontWeight: 500 }}
                      onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
                      onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                    >
                      {expandedProjects ? 'Show Less' : `View all ${Object.keys(stats).length} projects`}
                    </button>
                  )}
                  {expandedProjects && Object.keys(stats).length > 100 && (
                    <div style={{ textAlign: 'center', color: '#8e95a3', fontSize: '0.8rem', marginTop: '8px' }}>Showing first 100 projects</div>
                  )}
                </>
              )}
            </div>
          </div>

          {(() => {
            const allPending = Object.entries(pendingFacts).flatMap(([project, facts]) =>
              facts.map((f) => ({ project, ...f }))
            );
            return (
              <div className="brain-card">
                <h3>Pending Suggestions</h3>
                <p style={{ color: '#8e95a3', fontSize: '0.9rem' }}>
                  Facts the assistant inferred on its own, not explicitly requested by a user. Review them before they become searchable memories.
                </p>
                {allPending.length === 0 ? (
                  <div style={{ color: '#8e95a3', fontStyle: 'italic', fontSize: '0.85rem' }}>No pending suggestions.</div>
                ) : (
                <div className="project-list">
                  {allPending.slice(0, expandedPending ? 100 : 5).map((record) => (
                    <div key={`${record.project}-${record.id}`} className="project-item" style={{ alignItems: 'flex-start' }}>
                      <div className="project-item-info">
                        <strong>{record.project === 'default' ? 'Global Default' : record.project}</strong>
                        <span>{record.fact}</span>
                        {record.piiDetected && (
                          <span
                            className="memory-badge"
                            title="Heuristic scan matched a pattern that looks like PII (email, CPF, IP, card-shaped digits, or a long token). Not a compliance guarantee -- review the fact text yourself."
                            style={{ marginTop: '4px', display: 'inline-block', background: 'rgba(255, 69, 58, 0.15)', color: '#ff453a', border: '1px solid rgba(255, 69, 58, 0.4)' }}
                          >
                            ⚠ possible PII
                          </span>
                        )}
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        {/* Approve requires Editor/Admin (security-audit follow-up): a
                            Viewer approving isn't reviewing, it's the review's OUTCOME --
                            promoting an unreviewed suggestion straight to real, searchable
                            memory. Reject stays open to Viewer (canEdit-independent):
                            discarding one is strictly lower risk than approving one. */}
                        <button
                          onClick={() => canEdit && handleApprovePending(record.project, record.id)}
                          disabled={!canEdit}
                          title={canEdit ? undefined : 'Requires Editor or Admin'}
                          style={{ padding: '6px 12px', background: 'transparent', border: '1px solid rgba(50, 215, 75, 0.3)', borderRadius: '6px', color: 'rgba(50, 215, 75, 0.7)', fontSize: '0.85rem', cursor: canEdit ? 'pointer' : 'not-allowed', opacity: canEdit ? 1 : 0.5, fontWeight: 500, transition: 'all 0.2s' }}
                          onMouseOver={(e) => { if (canEdit) { e.currentTarget.style.background = 'rgba(50, 215, 75, 0.15)'; e.currentTarget.style.color = '#32d74b'; e.currentTarget.style.borderColor = '#32d74b'; } }}
                          onMouseOut={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'rgba(50, 215, 75, 0.7)'; e.currentTarget.style.borderColor = 'rgba(50, 215, 75, 0.3)'; }}
                        >
                          Approve
                        </button>
                        <button onClick={() => handleRejectPending(record.project, record.id)} style={{ padding: '6px 12px', background: 'transparent', border: '1px solid rgba(255, 69, 58, 0.3)', borderRadius: '6px', color: 'rgba(255, 69, 58, 0.7)', fontSize: '0.85rem', cursor: 'pointer', fontWeight: 500, transition: 'all 0.2s' }}
                                onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(255, 69, 58, 0.15)'; e.currentTarget.style.color = '#ff453a'; e.currentTarget.style.borderColor = '#ff453a'; }}
                                onMouseOut={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'rgba(255, 69, 58, 0.7)'; e.currentTarget.style.borderColor = 'rgba(255, 69, 58, 0.3)'; }}
                        >
                          Reject
                        </button>
                      </div>
                    </div>
                  ))}
                  {allPending.length > 5 && (
                    <button
                      onClick={() => setExpandedPending(!expandedPending)}
                      style={{ marginTop: '8px', padding: '10px', width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#e2e8f0', cursor: 'pointer', fontWeight: 500 }}
                      onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
                      onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                    >
                      {expandedPending ? 'Show Less' : `View all ${allPending.length} pending suggestions`}
                    </button>
                  )}
                </div>
                )}
              </div>
            );
          })()}
        </div>

        <div className="brain-side-column">
          <div className="brain-card">
            <h3>Brain Toggles</h3>
            <p style={{ color: '#8e95a3', fontSize: '0.9rem', marginBottom: '20px' }}>Enable or disable core capabilities on the fly.</p>

            {settingsLoadError && (
              <div style={{ color: '#ff9f0a', fontSize: '0.85rem', marginBottom: '16px' }}>
                Couldn&apos;t load the current toggle state -- these may not reflect what&apos;s actually saved.{' '}
                <button
                  type="button"
                  onClick={loadToggleSettings}
                  style={{ background: 'none', border: 'none', padding: 0, color: 'inherit', textDecoration: 'underline', cursor: 'pointer' }}
                >
                  Retry
                </button>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <span>Semantic Search</span>
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={semanticSearch}
                  disabled={!canEdit || settingsLoadError}
                  onChange={(e) => {
                    const next = e.target.checked;
                    setSemanticSearch(next);
                    savePluginSetting('semanticSearchEnabled', next).catch(() => {
                      setSemanticSearch(!next);
                    });
                  }}
                />
                <span className="slider"></span>
              </label>
            </div>

            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Auto-learning from Alerts</span>
                <label className="toggle-switch">
                  <input
                    type="checkbox"
                    checked={autoLearning}
                    disabled={!canEdit || settingsLoadError}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setAutoLearning(next);
                      savePluginSetting('autoLearnAlerts', next).catch(() => {
                        setAutoLearning(!next);
                      });
                    }}
                  />
                  <span className="slider"></span>
                </label>
              </div>
              {autoLearning && autoLearnMissingGrafanaConn && (
                <small style={{ color: '#ff9f0a', display: 'block', marginTop: '4px' }}>
                  Set a Grafana URL and service account token in Configuration for this to actually watch alerts.
                </small>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Strict Tenancy (Projects)</span>
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={strictTenancy}
                  disabled={!canEdit || settingsLoadError}
                  onChange={(e) => {
                    const next = e.target.checked;
                    setStrictTenancy(next);
                    savePluginSetting('strictTenancyEnabled', next).catch(() => {
                      setStrictTenancy(!next);
                    });
                  }}
                />
                <span className="slider"></span>
              </label>
            </div>

            <details style={{ marginTop: '32px', paddingTop: '24px', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
              <summary style={{ cursor: 'pointer', outline: 'none', color: '#ff453a', fontWeight: 500, fontSize: '1rem' }}>
                Advanced
              </summary>
              <div style={{ marginTop: '16px' }}>
                <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginBottom: '16px' }}>Wipe all memories across all projects.</p>
                <button onClick={handleClearAll} disabled={!canEdit} style={{ width: '100%', padding: '10px 16px', background: 'rgba(255, 69, 58, 0.2)', border: '1px solid #ff453a', borderRadius: '6px', color: '#ff453a', cursor: canEdit ? 'pointer' : 'not-allowed', opacity: canEdit ? 1 : 0.5, fontWeight: 500, transition: 'all 0.2s', marginBottom: '16px' }}
                        onMouseOver={(e) => { if (canEdit) { e.currentTarget.style.background = '#ff453a'; e.currentTarget.style.color = '#fff'; } }}
                        onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(255, 69, 58, 0.2)'; e.currentTarget.style.color = '#ff453a'; }}
                >
                  Clear All Data
                </button>
              </div>
            </details>
          </div>

          <div className="brain-card">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <Icon name="shield" size="lg" />
              Data Protection Settings
            </h3>
            
            {/* At-Rest Encryption */}
            <div style={{ marginBottom: '24px', paddingBottom: '24px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <h4 style={{ margin: 0, fontSize: '0.95rem' }}>At-Rest (Disk)</h4>
                <label className="toggle-switch" style={{ marginTop: '2px' }}>
                  <input
                    type="checkbox"
                    checked={atRestEncryption}
                    disabled={!canEdit || settingsLoadError}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setAtRestEncryption(next);
                      savePluginSetting('atRestEncryptionEnabled', next).catch(() => {
                        setAtRestEncryption(!next);
                      });
                    }}
                  />
                  <span className="slider"></span>
                </label>
              </div>
              <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginTop: '8px', marginBottom: '12px' }}>
                When on, every NEW memory fact is encrypted (AES-256-GCM) before being written to disk; the key is generated and stored locally.
                <br />
                Existing facts remain in their original state. Enabling or disabling this option does not re-encrypt or decrypt previously stored data.
              </p>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.03)', padding: '10px', borderRadius: '6px' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '0.75rem', color: '#8e95a3', marginBottom: '2px' }}>Algorithm</span>
                  <strong style={{ fontFamily: 'monospace', color: '#fff', fontSize: '0.9rem' }}>AES-256-GCM</strong>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: '0.75rem', background: atRestEncryption ? 'rgba(168, 85, 247, 0.2)' : 'rgba(255, 255, 255, 0.1)', color: atRestEncryption ? '#a855f7' : '#8e95a3', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold' }}>
                    {atRestEncryption ? 'ENABLED' : 'DISABLED'}
                  </span>
                </div>
              </div>
            </div>

            {/* In-Transit Encryption */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <h4 style={{ margin: 0, fontSize: '0.95rem' }}>RPC Bus</h4>
                <label className="toggle-switch" style={{ marginTop: '2px' }}>
                  <input
                    type="checkbox"
                    checked={inTransitEnabled}
                    disabled={!canEdit || settingsLoadError}
                    onChange={(e) => handleToggleInTransit(e.target.checked)}
                  />
                  <span className="slider"></span>
                </label>
              </div>
              <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginTop: '8px', marginBottom: '12px' }}>
                Encodes the MCP request and response payloads exchanged between Agent AI and Brain Agent.
              </p>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.03)', padding: '10px', borderRadius: '6px' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '0.75rem', color: '#8e95a3', marginBottom: '2px' }}>Encoding</span>
                  <strong style={{ fontFamily: 'monospace', color: '#fff', fontSize: '0.9rem' }}>Base64</strong>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: '0.75rem', background: inTransitEnabled ? 'rgba(168, 85, 247, 0.2)' : 'rgba(255, 255, 255, 0.1)', color: inTransitEnabled ? '#a855f7' : '#8e95a3', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold' }}>
                    {inTransitEnabled ? 'ACTIVE' : 'INACTIVE'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
