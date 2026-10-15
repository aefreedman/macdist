'use strict';

// Dependency-free presentation regression checks; no network or publishing operations.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Node {
  constructor(tag, text = '') {
    this.tag = tag;
    this.textContent = text;
    this.children = [];
    this.listeners = {};
    this.dataset = {};
    this.value = '';
    this.open = false;
    this.id = '';
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  get firstChild() { return this.children[0]; }
  get lastChild() { return this.children.at(-1); }
  setAttribute() {}
  addEventListener(name, callback) { this.listeners[name] = callback; }
  focus() { document.activeElement = this; }
  contains(node) { return this === node || this.children.some(child => child.contains(node)); }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [
      ...(selector === 'details[open]' && child.tag === 'details' && child.open ? [child] : []),
      ...child.querySelectorAll(selector)
    ]);
  }
}

const ids = ['runs', 'log-run', 'log-kind', 'log', 'error', 'connection', 'action-status',
  'logs-panel', 'reload', 'empty', 'run-count'];
const nodes = Object.fromEntries(ids.map(id => [id, new Node(id)]));
nodes['log-kind'].value = 'upload';
const find = (node, id) => node.id === id ? node : node.children.map(child => find(child, id)).find(Boolean);
const document = {
  activeElement: null,
  querySelector: () => ({content: 'fixture-token'}),
  createElement: tag => new Node(tag),
  getElementById: id => nodes[id] || find(nodes.runs, id)
};
let rows = [{id: 'fixture', version: 'Alpha', stage: 'packaged', ready: true,
  apple_local_status: 'Accepted', archive_path: '/fixture/build.zip', sha256: 'a'.repeat(64),
  publishing: {status: 'uploaded', page_url: 'https://example.itch.io/example'}}];
const requests = [];
const context = vm.createContext({
  document, navigator: {}, console, setInterval: () => {},
  fetch: async url => {
    requests.push(url);
    return {ok: true, json: async () => ({runs: rows, checked_at: '2026-10-13T12:00:00Z'}),
      text: async () => 'fixture log'};
  }
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../src/macdist/dashboard.js'), 'utf8'), context);
const run = source => vm.runInContext(source, context);
const text = node => [node.textContent, ...node.children.map(text)].join(' ');

(async () => {
  // Allow the initial asynchronous poll to finish.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nodes.runs.children.length, 1);
  assert.match(text(nodes.runs), /Ready to share/);
  assert.doesNotMatch(text(nodes.runs), /Download & playtest still required/);
  assert.equal(requests.some(url => url.includes('/logs/')), false);
  const original = nodes.runs.children[0];
  const details = original.children[2].children[0];
  details.open = true;
  document.getElementById('details-fixture').focus();
  await run('poll()');
  assert.equal(nodes.runs.children[0], original, 'Unchanged polling must preserve DOM nodes');

  rows = [{...rows[0], operation_locked: true}];
  await run('poll()');
  assert.equal(nodes.runs.children[0].children[2].children[0].open, true);
  assert.equal(document.activeElement.id, 'details-fixture');
  assert.match(text(nodes.runs), /may be stale/);
  document.getElementById('itch-fixture').focus();
  rows = [{...rows[0], apple: {status: 'Accepted', checked_at: '2026-10-13T12:00:00Z'}}];
  await run('poll()');
  assert.equal(document.activeElement.id, 'itch-fixture', 'Changed polling must restore link focus');

  await document.getElementById('copy-fixture').listeners.click();
  assert.match(nodes.error.textContent, /Could not copy path/);
  assert.equal(nodes.runs.children[0].children[2].children[0].open, true);
  await run('poll()');
  assert.match(nodes.error.textContent, /Could not copy path/, 'Polling must not erase action errors');

  document.getElementById('logs-fixture').listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nodes['logs-panel'].open, true);
  assert.equal(nodes['log-run'].value, 'fixture');
  assert.equal(nodes.log.textContent, 'fixture log');

  rows = [{id: 'pending', stage: 'accepted', ready: false, apple_local_status: 'Accepted',
    publishing: {status: 'uncertain', error: 'Inspect before retrying'}}];
  await run('poll()');
  assert.match(text(nodes.runs), /packaging and ZIP verification are still required/);
  assert.match(text(nodes.runs), /Upload uncertain/);
  assert.match(text(nodes.runs), /Inspect before retrying/);
  assert.equal(document.getElementById('copy-pending'), undefined);

  rows = [{id: 'broken', ready: false, error: '<script>untrusted fixture</script>'}];
  await run('poll()');
  assert.match(text(nodes.runs), /<script>untrusted fixture<\/script>/);
  rows = [];
  await run('poll()');
  assert.equal(nodes.empty.hidden, false);
  assert.equal(nodes['run-count'].textContent, '0 builds');
  console.log('Dashboard UI regression checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
