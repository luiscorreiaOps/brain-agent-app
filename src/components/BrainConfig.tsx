import React, { useState, useEffect } from 'react';
import { AppEvents, AppPluginMeta } from '@grafana/data';
import { getBackendSrv, config, getAppEvents } from '@grafana/runtime';

// Grafana's own toast instead of a native alert() -- see BrainHub.tsx's
// identical helper; kept separate since this file doesn't share a module
// with that page.
function notify(type: 'success' | 'error', message: string): void {
  const appEvent = type === 'success' ? AppEvents.alertSuccess : AppEvents.alertError;
  getAppEvents().publish({ type: appEvent.name, payload: [message] });
}

// Real enforcement is server-side (requireEditorOrAdmin in resources.go
// 403s a Viewer's call regardless of the UI) -- this only hides/disables
// the control so a Viewer isn't shown an action they can't perform.
// This whole page is already Admin-only at the route level (plugin.json's
// Configuration include), but crypto reset is disaster recovery -- worth
// gating explicitly too, matching the server-side requireAdmin check
// (security-audit finding M2), rather than relying only on the route ACL.
const isAdmin = config.bootData.user.orgRole === 'Admin';

interface Props {
  plugin: AppPluginMeta;
}

// Defaults mirror pkg/plugin/db.go's hardcoded fallbacks exactly (500MB,
// 50 results, no retention/overlap filtering) -- shown here so the form
// isn't blank on a fresh install, but 0/unset is what's actually sent
// unless the admin changes something, matching the backend's own
// "0 means use the original hardcoded behavior" convention.
const DEFAULT_MAX_MEMORIES = 50;
const DEFAULT_MAX_DB_SIZE_MB = 500;

export function BrainConfig({ plugin }: Props) {
  const [dbStatus, setDbStatus] = useState<'unknown' | 'checking' | 'ok' | 'error'>('unknown');
  const [maxMemories, setMaxMemories] = useState(plugin.jsonData?.maxMemories || DEFAULT_MAX_MEMORIES);
  const [ragOverlap, setRagOverlap] = useState(plugin.jsonData?.ragOverlapThreshold ?? 0);
  const [retentionDays, setRetentionDays] = useState(plugin.jsonData?.retentionDays ?? 0);
  const [floodLimit, setFloodLimit] = useState(plugin.jsonData?.floodLimitPerMinute ?? 0);
  const [maxDbSize, setMaxDbSize] = useState(plugin.jsonData?.maxDbSizeMB || DEFAULT_MAX_DB_SIZE_MB);
  const [embeddingEndpointURL, setEmbeddingEndpointURL] = useState(plugin.jsonData?.embeddingEndpointURL || '');
  const [embeddingModel, setEmbeddingModel] = useState(plugin.jsonData?.embeddingModel || '');
  const [embeddingAPIKey, setEmbeddingAPIKey] = useState('');
  const [auditEnabled, setAuditEnabled] = useState(plugin.jsonData?.auditLoggingEnabled === true);
  const [piiDetectionEnabled, setPiiDetectionEnabled] = useState(plugin.jsonData?.piiDetectionEnabled === true);

  const [grafanaURL, setGrafanaURL] = useState(plugin.jsonData?.grafanaURL || '');
  const [grafanaToken, setGrafanaToken] = useState('');
  const [trustedIntegrationLogin, setTrustedIntegrationLogin] = useState(plugin.jsonData?.trustedIntegrationLogin || '');
  const [encryptionKey, setEncryptionKey] = useState('');
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'ok' | 'error'>('idle');

  // The `plugin` prop is whatever Grafana core had cached for this page at
  // mount time, which isn't reliably fresh right after a save from this
  // same form (confirmed live: the toggles below showed unchecked on reload
  // immediately after a successful save, while a direct read of this same
  // endpoint returned the real, saved `true` the whole time). Re-fetch once
  // on mount to make sure the form reflects what's actually persisted, not
  // a stale snapshot.
  useEffect(() => {
    getBackendSrv()
      .get('/api/plugins/brain-agent-app/settings')
      .then((res) => {
        const jsonData = res?.jsonData || {};
        setMaxMemories(jsonData.maxMemories || DEFAULT_MAX_MEMORIES);
        setRagOverlap(jsonData.ragOverlapThreshold ?? 0);
        setRetentionDays(jsonData.retentionDays ?? 0);
        setFloodLimit(jsonData.floodLimitPerMinute ?? 0);
        setMaxDbSize(jsonData.maxDbSizeMB || DEFAULT_MAX_DB_SIZE_MB);
        setEmbeddingEndpointURL(jsonData.embeddingEndpointURL || '');
        setEmbeddingModel(jsonData.embeddingModel || '');
        setAuditEnabled(jsonData.auditLoggingEnabled === true);
        setPiiDetectionEnabled(jsonData.piiDetectionEnabled === true);
        setGrafanaURL(jsonData.grafanaURL || '');
        setTrustedIntegrationLogin(jsonData.trustedIntegrationLogin || '');
      })
      .catch((err) => console.error('Failed to fetch brain-agent-app settings', err));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const testDatabase = async () => {
    setDbStatus('checking');
    try {
      const res = await getBackendSrv().get(`/api/plugins/brain-agent-app/resources/health`);
      if (res && res.status === 'error') {
        setDbStatus('error');
      } else {
        setDbStatus('ok');
      }
    } catch (e) {
      setDbStatus('error');
    }
  };

  const handleSave = async () => {
    setSaveStatus('saving');
    try {
      const current = await getBackendSrv().get('/api/plugins/brain-agent-app/settings');
      const body: Record<string, unknown> = {
        enabled: true,
        pinned: true,
        jsonData: {
          ...current?.jsonData,
          grafanaURL,
          maxMemories,
          ragOverlapThreshold: ragOverlap,
          retentionDays,
          floodLimitPerMinute: floodLimit,
          maxDbSizeMB: maxDbSize,
          auditLoggingEnabled: auditEnabled,
          piiDetectionEnabled,
          embeddingEndpointURL,
          embeddingModel,
          trustedIntegrationLogin: trustedIntegrationLogin.trim(),
        },
      };
      // Grafana's settings endpoint replaces secureJsonData wholesale too,
      // but only for keys actually present in the payload -- omit
      // grafanaToken/embeddingAPIKey entirely when their field was left
      // blank so an already-saved secret isn't wiped out just by
      // reopening this page.
      const secureJsonData: Record<string, string> = {};
      if (grafanaToken.trim() !== '') {
        secureJsonData.grafanaToken = grafanaToken.trim();
      }
      if (embeddingAPIKey.trim() !== '') {
        secureJsonData.embeddingAPIKey = embeddingAPIKey.trim();
      }
      if (encryptionKey.trim() !== '') {
        secureJsonData.encryptionKey = encryptionKey.trim();
      }
      if (Object.keys(secureJsonData).length > 0) {
        body.secureJsonData = secureJsonData;
      }
      await getBackendSrv().post('/api/plugins/brain-agent-app/settings', body);
      setGrafanaToken('');
      setEmbeddingAPIKey('');
      setEncryptionKey('');
      setSaveStatus('ok');
    } catch (e) {
      setSaveStatus('error');
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '800px', color: '#fff' }}>
      <h2 style={{ marginBottom: '24px', fontSize: '1.5rem' }}>Brain Agent Settings</h2>
      
      <details style={{ marginBottom: '32px', background: 'rgba(255,255,255,0.02)', padding: '20px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
        <summary style={{ cursor: 'pointer', outline: 'none', borderBottom: '1px solid #333', paddingBottom: '8px', marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '1.17em', fontWeight: 'bold' }}>
            <span aria-hidden="true" style={{ display: 'inline-block', marginRight: '8px', fontSize: '0.75em' }}>▶</span>
            Storage & Database
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {dbStatus === 'ok' && <span style={{ color: '#32d74b', fontSize: '0.85rem' }}>✓ Healthy</span>}
            {dbStatus === 'error' && <span style={{ color: '#ff453a', fontSize: '0.85rem' }}>✗ Connection failed</span>}
            <button
              onClick={(e) => { e.preventDefault(); testDatabase(); }}
              style={{ padding: '4px 12px', background: 'transparent', border: '1px solid #3274d9', color: '#3274d9', borderRadius: '4px', cursor: 'pointer', fontSize: '0.85rem' }}
            >
              {dbStatus === 'checking' ? 'Testing...' : 'Validate Connection'}
            </button>
          </span>
        </summary>
        
        {dbStatus === 'ok' && (
          <div style={{ padding: '12px', background: 'rgba(50, 215, 75, 0.1)', border: '1px solid #32d74b', color: '#32d74b', borderRadius: '4px', marginBottom: '16px' }}>
            ✓ Database connection is healthy and ready to accept RAG context.
          </div>
        )}
        {dbStatus === 'error' && (
          <div style={{ padding: '12px', background: 'rgba(255, 69, 58, 0.1)', border: '1px solid #ff453a', color: '#ff453a', borderRadius: '4px', marginBottom: '16px' }}>
            ✗ Database connection failed. Check Grafana file permissions for the plugin directory.
          </div>
        )}

        <p style={{ color: '#8e95a3', marginBottom: '16px' }}>The Brain Agent creates an isolated local SQLite database to store user context.</p>
        
        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>SQLite Storage Architecture</label>
          <input 
            type="text" 
            readOnly
            defaultValue="Local Plugin Directory (Auto-detected per fork)"
            style={{ width: '100%', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', border: '1px solid #333', borderRadius: '4px', color: '#8e95a3', cursor: 'not-allowed', marginBottom: '16px' }}
          />

          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Max Database Size (MB)</label>
          <input 
            type="number" 
            value={maxDbSize}
            onChange={(e) => { const n = parseInt(e.target.value, 10); setMaxDbSize(isNaN(n) ? 0 : n); }}
            style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
          />
          <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>If limit is reached, older memories will be automatically overwritten (FIFO) to preserve disk space.</small>
        </div>
      </details>

      <details style={{ marginBottom: '32px', background: 'rgba(255,255,255,0.02)', padding: '20px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
        <summary style={{ cursor: 'pointer', outline: 'none', borderBottom: '1px solid #333', paddingBottom: '8px', marginBottom: '16px', fontSize: '1.17em', fontWeight: 'bold' }}>RAG (Retrieval-Augmented Generation)</summary>
        <p style={{ color: '#8e95a3', marginBottom: '16px' }}>Fine-tune how the Agent AI extracts and processes memories from the Brain Agent.</p>
        
        <div style={{ display: 'flex', gap: '20px', marginBottom: '16px' }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Max Memories Returned</label>
            <input 
              type="number" 
              value={maxMemories}
              onChange={(e) => { const n = parseInt(e.target.value, 10); setMaxMemories(isNaN(n) ? 0 : n); }}
              style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
            />
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>Limits how many past facts are injected into the LLM context at once.</small>
          </div>
          
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Semantic Overlap (Threshold)</label>
            <input 
              type="number" 
              step="0.1"
              value={ragOverlap}
              onChange={(e) => { const n = parseFloat(e.target.value); setRagOverlap(isNaN(n) ? 0 : n); }}
              style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
            />
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>Minimum fraction of the query's own words that must appear in a fact for it to be returned (0.0 to 1.0). 0 = no filtering.</small>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '20px', marginBottom: '16px' }}>
          <div style={{ flex: 1 }}>
            <label htmlFor="brain-retention-days" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Data Retention (Days)</label>
            <input
              id="brain-retention-days"
              type="number"
              value={retentionDays}
              onChange={(e) => { const n = parseInt(e.target.value, 10); setRetentionDays(isNaN(n) ? 0 : n); }}
              style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
            />
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>Facts older than this are deleted automatically, checked every 15 minutes. 0 = retention disabled (facts never expire by age).</small>
          </div>
          
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Flood Protection (Queries/Min)</label>
            <input 
              type="number" 
              value={floodLimit}
              onChange={(e) => { const n = parseInt(e.target.value, 10); setFloodLimit(isNaN(n) ? 0 : n); }}
              style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
            />
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>Max memory tool calls (store/search/delete) per user per minute -- extra calls get a 429. 0 = unlimited.</small>
          </div>
        </div>

        <div style={{ marginTop: '8px', paddingTop: '16px', borderTop: '1px solid #333' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Semantic Search: Embedding Endpoint (optional)</label>
          <small style={{ color: '#8e95a3', display: 'block', marginBottom: '12px' }}>
            When set, search_memory ranks facts by real embedding-based semantic similarity instead of the built-in word-overlap scoring -- e.g. a fact saved as
            {' '}&quot;Vault became unavailable after a pod restart&quot; is then found by a query like &quot;secrets manager outage&quot;, even with no words in common.
            Any OpenAI-compatible <code>/embeddings</code> endpoint works (Ollama, OpenAI, or a compatible gateway). Leave blank to keep the existing word-overlap search exactly as-is -- this is a fully optional upgrade, not a requirement.
          </small>
          <div style={{ display: 'flex', gap: '20px', marginBottom: '16px' }}>
            <div style={{ flex: 2 }}>
              <label htmlFor="brain-embedding-url" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Endpoint URL</label>
              <input
                id="brain-embedding-url"
                type="text"
                autoComplete="off"
                value={embeddingEndpointURL}
                onChange={(e) => setEmbeddingEndpointURL(e.target.value)}
                placeholder="http://localhost:11434/v1"
                style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label htmlFor="brain-embedding-model" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Model</label>
              <input
                id="brain-embedding-model"
                type="text"
                autoComplete="off"
                value={embeddingModel}
                onChange={(e) => setEmbeddingModel(e.target.value)}
                placeholder="nomic-embed-text"
                style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
              />
            </div>
          </div>
          <div>
            <label htmlFor="brain-embedding-key" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>API Key</label>
            <input
              id="brain-embedding-key"
              type="password"
              autoComplete="new-password"
              value={embeddingAPIKey}
              onChange={(e) => setEmbeddingAPIKey(e.target.value)}
              placeholder={plugin.jsonData?.embeddingEndpointURL ? '(unchanged -- leave blank to keep the saved key)' : 'Not required for most local endpoints'}
              style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
            />
          </div>
        </div>
      </details>

      <details style={{ marginBottom: '32px', background: 'rgba(255,255,255,0.02)', padding: '20px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }} open>
        <summary style={{ cursor: 'pointer', outline: 'none', borderBottom: '1px solid #333', paddingBottom: '8px', marginBottom: '16px', fontSize: '1.17em', fontWeight: 'bold' }}>Grafana Connection</summary>
        <p style={{ color: '#8e95a3', marginBottom: '16px' }}>
          Required for "Auto-learning from Alerts" (see the main Brain Hub page) to actually watch this Grafana instance's alerts and turn resolved ones into memories on its own.
        </p>

        <div style={{ marginBottom: '16px' }}>
          <label htmlFor="brain-grafana-url" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Grafana URL</label>
          <input
            id="brain-grafana-url"
            type="text"
            autoComplete="off"
            value={grafanaURL}
            onChange={(e) => setGrafanaURL(e.target.value)}
            placeholder="http://localhost:3000"
            style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
          />
          <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>This Grafana instance's own base URL, reachable from inside the Grafana process itself.</small>
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Grafana Service Account Token</label>
          <input
            type="password"
            autoComplete="new-password"
            value={grafanaToken}
            onChange={(e) => setGrafanaToken(e.target.value)}
            placeholder={plugin.jsonData?.grafanaURL ? 'Already set -- leave blank to keep it' : 'glsa_...'}
            style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
          />
          <small style={{ color: '#8e95a3', display: 'block', marginTop: '4px' }}>Needs at least Viewer access to read the alerting API. Left blank on save, the existing token (if any) is kept.</small>
        </div>

        <div style={{ marginBottom: '8px' }}>
          <label htmlFor="brain-trusted-integration-login" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Trusted Integration Login (optional)</label>
          <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginBottom: '8px' }}>
            agent-ai-app's own Grafana service account is deliberately kept at Viewer role (giving it Editor would let every chat user act with Editor-level access through it). Since search_memory/search_memory_by_time/brain_diagnostics require Editor or Admin, that Viewer-role account can't read any stored memory back by default -- only queue suggestions. Set this to that service account's exact Grafana login to let it call those 3 read-only tools specifically, without granting it (or any other Viewer) write/delete access. Leave blank to keep every Viewer-role caller fully gated, the default.
          </p>
          <input
            id="brain-trusted-integration-login"
            type="text"
            autoComplete="off"
            value={trustedIntegrationLogin}
            onChange={(e) => setTrustedIntegrationLogin(e.target.value)}
            placeholder="e.g. sa-llm-plugin"
            style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
          />
        </div>
      </details>

      <details style={{ marginBottom: '32px', background: 'rgba(255,255,255,0.02)', padding: '20px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
        <summary style={{ cursor: 'pointer', outline: 'none', borderBottom: '1px solid #333', paddingBottom: '8px', marginBottom: '16px', fontSize: '1.17em', fontWeight: 'bold' }}>Compliance & Auditing</summary>
        
        <div style={{ marginBottom: '16px', display: 'flex', alignItems: 'center' }}>
          <input 
            type="checkbox" 
            checked={auditEnabled}
            onChange={(e) => setAuditEnabled(e.target.checked)}
            style={{ width: '18px', height: '18px', marginRight: '10px', accentColor: '#ff453a' }}
          />
          <div>
            <label style={{ display: 'block', fontWeight: 500 }}>Enable Model Invocation Logging</label>
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '2px' }}>Logs every memory tool call (store/search/delete) this plugin receives -- arguments, result, and the calling Grafana user -- to the plugin's own log output.</small>
          </div>
        </div>

        <div style={{ marginBottom: '16px', display: 'flex', alignItems: 'center' }}>
          <input
            type="checkbox"
            checked={piiDetectionEnabled}
            onChange={(e) => setPiiDetectionEnabled(e.target.checked)}
            style={{ width: '18px', height: '18px', marginRight: '10px', accentColor: '#ff453a' }}
          />
          <div>
            <label style={{ display: 'block', fontWeight: 500 }}>Flag Facts That Look Like They Contain PII</label>
            <small style={{ color: '#8e95a3', display: 'block', marginTop: '2px' }}>Heuristic scan run on every new fact -- flagged facts show a warning badge in Brain Hub for human review. Never blocks a write.</small>
          </div>
        </div>
      </details>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button
          onClick={handleSave}
          disabled={saveStatus === 'saving'}
          style={{ padding: '10px 24px', background: '#3274d9', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}
        >
          {saveStatus === 'saving' ? 'Saving...' : 'Save Settings'}
        </button>
        {saveStatus === 'ok' && <span style={{ color: '#32d74b' }}>✓ Saved</span>}
        {saveStatus === 'error' && <span style={{ color: '#ff453a' }}>✗ Failed to save</span>}
      </div>

      <details style={{ marginTop: '48px', padding: '20px', borderRadius: '8px', border: '1px solid #ff453a', background: 'rgba(255, 69, 58, 0.05)' }}>
        <summary style={{ cursor: 'pointer', outline: 'none', borderBottom: '1px solid #ff453a', paddingBottom: '8px', marginBottom: '16px', color: '#ff453a', fontSize: '1.17em', fontWeight: 'bold' }}>Key Management</summary>

        <div style={{ marginBottom: '20px' }}>
          <label htmlFor="brain-encryption-key" style={{ display: 'block', marginBottom: '8px', fontWeight: 500 }}>Encryption Key (optional)</label>
          <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginBottom: '8px' }}>
            By default the AES-256 key lives in a local file next to the database, in the same directory a backup of the database would also copy. Set a key here (base64, exactly 32 bytes -- e.g. generate one with <code>openssl rand -base64 32</code>) to store it separately instead, in Grafana's own encrypted settings storage. Leaving this blank keeps the existing local-file behavior; this is optional, not required.
          </p>
          <input
            id="brain-encryption-key"
            type="password"
            autoComplete="new-password"
            value={encryptionKey}
            onChange={(e) => setEncryptionKey(e.target.value)}
            placeholder={plugin.secureJsonFields?.encryptionKey ? '(unchanged -- leave blank to keep the saved key)' : 'Leave blank to keep using the local key file'}
            disabled={!isAdmin}
            style={{ width: '100%', padding: '8px 12px', background: '#141619', border: '1px solid #333', borderRadius: '4px', color: '#fff' }}
          />
        </div>

        <p style={{ color: '#8e95a3', fontSize: '0.85rem', marginBottom: '16px' }}>Force generate a new AES key if the current one is irrecoverably corrupted. This will destroy access to all previous data.</p>
        <button onClick={() => {
          if(confirm('DANGER: This will delete the current corrupted AES key and generate a new one. ALL PREVIOUS MEMORY WILL BE UNREADABLE. Are you absolutely sure?')) {
            getBackendSrv().post('/api/plugins/brain-agent-app/resources/crypto/reset').then(() => notify('success', 'Key deleted and reset successfully.')).catch(() => notify('error', 'Failed to reset key'));
          }
        }} disabled={!isAdmin} style={{ padding: '10px 16px', background: 'rgba(255, 159, 10, 0.2)', border: '1px solid #ff9f0a', borderRadius: '6px', color: '#ff9f0a', cursor: isAdmin ? 'pointer' : 'not-allowed', opacity: isAdmin ? 1 : 0.5, fontWeight: 500, transition: 'all 0.2s' }}
                onMouseOver={(e) => { if (isAdmin) { e.currentTarget.style.background = '#ff9f0a'; e.currentTarget.style.color = '#fff'; } }}
                onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(255, 159, 10, 0.2)'; e.currentTarget.style.color = '#ff9f0a'; }}
        >
          Reset Key
        </button>
        {!isAdmin && <p style={{ color: '#8e95a3', fontSize: '0.8rem', marginTop: '8px' }}>Admin permissions required for key management.</p>}
      </details>
    </div>
  );
}
