/**
 * Browser harness for the Agents++ smoke app.
 *
 * This intentionally uses Node's built-in HTTP server instead of adding an app
 * framework. The harness is only a local test surface: one page, one POST
 * endpoint, and no user data beyond the disposable smoke database result.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { runSmoke } from './smoke.js';

const PORT = Number(process.env.PORT ?? 3210);

function send(res: ServerResponse, status: number, body: string, contentType = 'text/html; charset=utf-8'): void {
  res.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
  });
  res.end(body);
}

function page(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agents++ Smoke Harness</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b0f14;
      --panel: #111823;
      --panel-2: #172131;
      --line: #2d3a4d;
      --text: #eef3f8;
      --muted: #9aa8ba;
      --accent: #4c8dff;
      --pass: #38d878;
      --fail: #ff5c66;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(1120px, calc(100vw - 32px));
      margin: 32px auto;
      display: grid;
      gap: 16px;
    }
    header, section {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
      padding: 18px 20px;
    }
    h1, h2 {
      margin: 0;
      letter-spacing: 0;
    }
    h1 { font-size: 22px; }
    h2 { font-size: 16px; margin-bottom: 12px; }
    p { color: var(--muted); margin: 6px 0 0; }
    .toolbar {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    button {
      border: 1px solid #6da1ff;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      padding: 10px 14px;
      font-weight: 700;
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.62;
      cursor: wait;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      background: var(--panel-2);
      font-size: 12px;
    }
    .badge.pass { border-color: rgba(56, 216, 120, 0.55); color: var(--pass); }
    .badge.fail { border-color: rgba(255, 92, 102, 0.55); color: var(--fail); }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 6px;
      background: #0e1520;
    }
    th, td {
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    pre {
      white-space: pre-wrap;
      margin: 0;
      color: var(--muted);
      background: #0e1520;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      max-height: 260px;
      overflow: auto;
    }
    .hidden { display: none; }
    @media (max-width: 760px) {
      main { width: calc(100vw - 20px); margin: 16px auto; }
      .grid { grid-template-columns: 1fr; }
      header, section { padding: 14px; }
      table { font-size: 12px; }
      th, td { padding: 7px; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Agents++ Smoke Harness</h1>
      <p>Runs a local consumer-style test through the package exports and a disposable Postgres database.</p>
    </header>

    <section>
      <div class="toolbar">
        <button id="run" type="button">Run Smoke Test</button>
        <span id="status" class="badge">Idle</span>
        <span id="db" class="badge">Database: localhost:5433</span>
      </div>
    </section>

    <section id="summary" class="hidden">
      <h2>Result</h2>
      <div class="toolbar">
        <span id="overscope" class="badge"></span>
        <span id="audit" class="badge"></span>
        <span id="columns" class="badge"></span>
      </div>
    </section>

    <div id="tables" class="grid hidden">
      <section>
        <h2>Full Access Agent</h2>
        <div id="full"></div>
      </section>
      <section>
        <h2>Limited Agent</h2>
        <div id="limited"></div>
      </section>
    </div>

    <section id="rawWrap" class="hidden">
      <h2>Raw Smoke Output</h2>
      <pre id="raw"></pre>
    </section>
  </main>

  <script>
    const runButton = document.getElementById('run');
    const statusEl = document.getElementById('status');
    const dbEl = document.getElementById('db');
    const summary = document.getElementById('summary');
    const tables = document.getElementById('tables');
    const rawWrap = document.getElementById('rawWrap');
    const overscope = document.getElementById('overscope');
    const audit = document.getElementById('audit');
    const columns = document.getElementById('columns');
    const full = document.getElementById('full');
    const limited = document.getElementById('limited');
    const raw = document.getElementById('raw');

    function setStatus(label, mode) {
      statusEl.textContent = label;
      statusEl.className = 'badge' + (mode ? ' ' + mode : '');
    }

    function renderTable(target, rows) {
      if (!rows?.length) {
        target.textContent = 'No rows';
        return;
      }
      const keys = Object.keys(rows[0]);
      target.innerHTML = '<table><thead><tr>' +
        keys.map((key) => '<th>' + key + '</th>').join('') +
        '</tr></thead><tbody>' +
        rows.map((row) => '<tr>' + keys.map((key) => '<td>' + String(row[key]) + '</td>').join('') + '</tr>').join('') +
        '</tbody></table>';
    }

    runButton.addEventListener('click', async () => {
      runButton.disabled = true;
      setStatus('Running', '');
      summary.classList.add('hidden');
      tables.classList.add('hidden');
      rawWrap.classList.add('hidden');

      try {
        const response = await fetch('/api/run', { method: 'POST' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Smoke test failed');

        setStatus('Passed', 'pass');
        dbEl.textContent = 'Database: ' + data.databaseUrl;
        overscope.textContent = data.overscopeBlocked ? 'Overscope blocked' : 'Overscope not blocked';
        overscope.className = data.overscopeBlocked ? 'badge pass' : 'badge fail';
        audit.textContent = 'Audit records: ' + data.auditRecordCount;
        audit.className = 'badge pass';
        columns.textContent = 'Encrypted columns: ' + data.encryptedColumns.length;
        columns.className = 'badge pass';
        renderTable(full, data.fullAccessRows);
        renderTable(limited, data.limitedRows);
        raw.textContent = JSON.stringify(data, null, 2);
        summary.classList.remove('hidden');
        tables.classList.remove('hidden');
        rawWrap.classList.remove('hidden');
      } catch (error) {
        setStatus('Failed', 'fail');
        raw.textContent = error instanceof Error ? error.message : String(error);
        rawWrap.classList.remove('hidden');
      } finally {
        runButton.disabled = false;
      }
    });
  </script>
</body>
</html>`;
}

async function handleRun(_req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const result = await runSmoke({ verbose: false });
    send(res, 200, JSON.stringify(result), 'application/json; charset=utf-8');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    send(res, 500, JSON.stringify({ error: message }), 'application/json; charset=utf-8');
  }
}

const server = createServer((req, res) => {
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? `localhost:${PORT}`}`);

  if (method === 'GET' && url.pathname === '/') {
    send(res, 200, page());
    return;
  }

  if (method === 'POST' && url.pathname === '/api/run') {
    handleRun(req, res);
    return;
  }

  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

server.listen(PORT, () => {
  console.log(`Agents++ smoke harness: http://localhost:${PORT}`);
});
