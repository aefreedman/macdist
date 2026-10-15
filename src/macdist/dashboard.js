'use strict';

const token = document.querySelector('meta[name="dashboard-token"]').content;
const rowsElement = document.getElementById('runs');
const runSelect = document.getElementById('log-run');
const kindSelect = document.getElementById('log-kind');
const logElement = document.getElementById('log');
const errorElement = document.getElementById('error');
const connection = document.getElementById('connection');
const actionStatus = document.getElementById('action-status');
let actionError = '';
let connectionError = '';
let polling = false;
let selectionGeneration = 0;
let rowsSnapshot = '';
const logsPanel = document.getElementById('logs-panel');

const labels = {
  preparing: 'Preparing & signing', signed: 'Signed · awaiting submission',
  submission_attempted: 'Upload attempted · check logs', uploading: 'Uploading to Apple',
  submitted: 'Awaiting Apple', accepted: 'Accepted · packaging pending',
  packaged: 'Packaging complete'
};

const publishingLabels = {
  not_configured: 'Not configured', not_published: 'Not uploaded', running: 'Checking · read only',
  upload_attempted: 'Upload attempted · check logs', uploading: 'Upload in progress · recorded',
  uploaded: 'Uploaded', uncertain: 'Upload uncertain · check before retry',
  failed: 'Check failed', dry_run_passed: 'Preview passed · not uploaded',
  status_checked: 'Channel checked · upload not confirmed'
};

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function renderError() {
  errorElement.textContent = [connectionError, actionError].filter(Boolean).join(' · ');
  errorElement.hidden = !errorElement.textContent;
}

function showError(message) {
  actionError = message;
  actionStatus.textContent = '';
  renderError();
}

async function request(url, method = 'GET') {
  const response = await fetch(url, {
    method, headers: {'X-Dashboard-Token': token}, cache: 'no-store', mode: 'same-origin'
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Dashboard request failed (${response.status})`);
  }
  return response;
}

function readableDate(value) {
  if (!value) return 'Not refreshed in this session';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}

function renderRows(rows) {
  const snapshot = JSON.stringify(rows);
  if (snapshot === rowsSnapshot) return;
  rowsSnapshot = snapshot;
  const expanded = new Set([...rowsElement.querySelectorAll('details[open]')].map(node => node.dataset.run));
  const focused = rowsElement.contains(document.activeElement) ? document.activeElement.id : '';
  rowsElement.replaceChildren();
  const selected = runSelect.value;
  runSelect.replaceChildren(element('option', 'Select a run'));
  runSelect.firstChild.value = '';
  for (const run of rows) {
    const option = element('option', `${run.version || run.app || 'Build'} · ${run.id}`);
    option.value = run.id;
    runSelect.append(option);
    const card = element('article', undefined, 'run-card');
    const build = element('div', undefined, 'build-heading');
    build.append(element('h3', run.version || run.app || 'Unreadable build'), element('small', run.id));
    const details = element('details', undefined, 'technical');
    details.dataset.run = run.id;
    details.open = expanded.has(run.id);
    const detailSummary = element('summary', 'Technical details');
    detailSummary.id = `details-${run.id}`;
    details.append(detailSummary);
    const metadata = element('dl');
    const addDetail = (label, value) => {
      if (!value) return;
      metadata.append(element('dt', label), element('dd', value));
    };
    const workflow = element('div', undefined, 'workflow');
    workflow.append(element('span', labels[run.stage] || run.stage || 'Unknown workflow', 'badge neutral'));
    if (run.operation_locked) workflow.append(element('small', 'Operation lock present · may be stale', 'warning'));
    if (run.stage === 'uploading' && Number.isFinite(run.upload_percent)) {
      const progress = document.createElement('progress');
      progress.max = 100;
      progress.value = run.upload_percent;
      progress.setAttribute('aria-label', 'Upload progress');
      workflow.append(progress, element('small', `${run.upload_percent.toFixed(1)}% uploaded · last reported`));
    }
    if (run.error) workflow.append(element('small', run.error, 'error'));
    const apple = element('section', undefined, 'status-block');
    apple.append(element('h4', 'Apple notarization'));
    const cached = run.apple || {};
    const appleStatus = cached.status || run.apple_local_status || 'Not checked';
    apple.append(element('span', appleStatus, `badge ${appleStatus === 'Accepted' ? 'success' : appleStatus === 'Invalid' || appleStatus === 'Rejected' ? 'danger' : 'neutral'}`));
    if (cached.refreshing) apple.append(element('small', 'Refreshing Apple…'));
    else apple.append(element('small', cached.checked_at ? `Checked ${readableDate(cached.checked_at)}` : run.apple_local_status ? 'From local run evidence' : 'No status recorded'));
    addDetail('Apple submission ID', run.submission_id);
    if (cached.error) apple.append(element('small', cached.error, 'error'));
    const distribution = element('section', undefined, 'status-block');
    distribution.append(element('h4', 'Distribution ZIP'));
    if (run.ready) {
      distribution.append(element('span', 'Ready to share', 'badge success'));
      const zipActions = element('div', undefined, 'action-group');
      const reveal = element('button', 'Reveal ZIP in Finder', 'primary');
      reveal.id = `reveal-${run.id}`;
      reveal.addEventListener('click', async () => {
        reveal.disabled = true;
        try {
          await request(`/api/runs/${encodeURIComponent(run.id)}/reveal`, 'POST');
          showError('');
          actionStatus.textContent = 'ZIP revealed in Finder on this Mac.';
        } catch (error) { showError(error.message); }
        finally { reveal.disabled = false; }
      });
      const copy = element('button', 'Copy ZIP path');
      copy.id = `copy-${run.id}`;
      copy.addEventListener('click', async () => {
        try {
          if (!navigator.clipboard) throw new Error('Clipboard unavailable. Copy the path from Technical details.');
          await navigator.clipboard.writeText(run.archive_path);
          copy.textContent = 'Copied';
          showError('');
          actionStatus.textContent = 'ZIP path copied.';
        } catch (error) {
          details.open = true;
          showError(`Could not copy path: ${error.message}`);
        }
      });
      zipActions.append(reveal, copy);
      distribution.append(zipActions, element('small', 'Verified ZIP · playtest on another Mac before broader sharing.'));
      addDetail('ZIP path', run.archive_path);
      addDetail('SHA-256', run.sha256);
    } else {
      distribution.append(element('span', 'Not ready', 'badge neutral'));
      if (run.stage === 'accepted') distribution.append(element('small', 'Apple accepted the app; packaging and ZIP verification are still required.'));
      if (run.archive_error) distribution.append(element('small', run.archive_error, 'error'));
    }
    const publishing = element('section', undefined, 'status-block');
    publishing.append(element('h4', 'itch.io publishing'));
    const publication = run.publishing || {};
    const publicationProblem = publication.error || ['uncertain', 'upload_attempted', 'failed'].includes(publication.status);
    publishing.append(element('span', publishingLabels[publication.status] || 'Unknown publishing state', `badge ${publicationProblem ? 'danger' : publication.status === 'uploaded' ? 'success' : 'neutral'}`));
    addDetail('itch destination', publication.target ? `${publication.target}:${publication.channel}` : null);
    addDetail('Published version', publication.version);
    addDetail('Local publishing receipt', publication.finished_at ? readableDate(publication.finished_at) : null);
    addDetail('itch channel snapshot', publication.remote_checked_at ? `${readableDate(publication.remote_checked_at)} · see status log` : null);
    if (publication.remote_check_failed) publishing.append(element('small', 'Last itch status check failed · see status log', 'error'));
    if (publication.error) publishing.append(element('small', publication.error, 'error'));
    if (/^https:\/\/[a-z0-9_-]+\.itch\.io\/[a-z0-9_-]+$/.test(publication.page_url || '')) {
      const page = element('a', 'Open itch page', 'button');
      page.id = `itch-${run.id}`;
      page.href = publication.page_url;
      page.target = '_blank';
      page.rel = 'noopener noreferrer';
      publishing.append(page);
    }
    const actions = element('div', undefined, 'action-group');
    const refresh = element('button', cached.refreshing ? 'Refreshing…' : 'Refresh Apple');
    refresh.id = `refresh-${run.id}`;
    refresh.disabled = !run.submission_id || !!run.error || !!cached.refreshing;
    refresh.title = !run.submission_id ? 'Available after a submission ID is recorded' : 'Read-only Apple status check';
    refresh.addEventListener('click', async () => {
      refresh.disabled = true;
      try {
        await request(`/api/runs/${encodeURIComponent(run.id)}/refresh`, 'POST');
        showError('');
        await poll();
      } catch (error) { showError(error.message); }
      finally { refresh.disabled = false; }
    });
    const logs = element('button', 'View logs');
    logs.id = `logs-${run.id}`;
    logs.addEventListener('click', () => {
      runSelect.value = run.id;
      selectionGeneration += 1;
      logsPanel.open = true;
      updateLog();
      logElement.focus();
    });
    actions.append(logs);
    apple.append(element('div', undefined, 'action-group'));
    apple.lastChild.append(refresh);
    const heading = element('div', undefined, 'card-heading');
    heading.append(build, workflow);
    const statuses = element('div', undefined, 'status-grid');
    statuses.append(apple, distribution, publishing);
    details.append(metadata);
    const footer = element('div', undefined, 'card-footer');
    footer.append(details, actions);
    card.append(heading, statuses, footer);
    rowsElement.append(card);
  }
  if (rows.some(run => run.id === selected)) runSelect.value = selected;
  else if (!selected && rows.length) runSelect.value = rows[0].id;
  document.getElementById('empty').hidden = rows.length !== 0;
  document.getElementById('run-count').textContent = `${rows.length} ${rows.length === 1 ? 'build' : 'builds'}`;
  if (focused) document.getElementById(focused)?.focus({preventScroll: true});
}

async function updateLog() {
  if (!logsPanel.open) return;
  const name = runSelect.value;
  const kind = kindSelect.value;
  const generation = selectionGeneration;
  if (!name) { logElement.textContent = 'Select a run to view its log.'; return; }
  try {
    const response = await request(`/api/runs/${encodeURIComponent(name)}/logs/${kind}`);
    const content = await response.text();
    if (generation !== selectionGeneration || name !== runSelect.value || kind !== kindSelect.value) return;
    const atBottom = logElement.scrollTop + logElement.clientHeight >= logElement.scrollHeight - 30;
    logElement.textContent = content;
    if (atBottom) logElement.scrollTop = logElement.scrollHeight;
  } catch (error) {
    if (generation === selectionGeneration) logElement.textContent = error.message;
  }
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const response = await request('/api/runs');
    const data = await response.json();
    renderRows(data.runs);
    connection.textContent = `Local files checked ${readableDate(data.checked_at)}`;
    connectionError = '';
    renderError();
    await updateLog();
  } catch (error) {
    connection.textContent = 'Dashboard disconnected · displayed builds may be out of date';
    connectionError = error.message;
    renderError();
  } finally { polling = false; }
}

for (const select of [runSelect, kindSelect]) {
  select.addEventListener('change', () => { selectionGeneration += 1; updateLog(); });
}
logsPanel.addEventListener('toggle', () => { if (logsPanel.open) updateLog(); });
document.getElementById('reload').addEventListener('click', poll);
poll();
setInterval(poll, 3000);
