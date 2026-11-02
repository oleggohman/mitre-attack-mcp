#!/usr/bin/env node
// npm/npx launcher for the Python MCP server.
//
// Preferred: uvx installs the Python dependencies declared in the bundled
// pyproject.toml into an isolated environment and runs the server.
// Fallback: a system python3/python that already has the dependencies installed.

const { spawn } = require('child_process');
const path = require('path');

const pkgDir = __dirname;
const srcPath = path.join(pkgDir, 'src');

const candidates = [
  { cmd: 'uvx', args: ['--python', '3.12', '--from', pkgDir, 'mitre-mcp-server'], env: {} },
  { cmd: 'python3', args: ['-m', 'mitre_mcp_server.server'], env: { PYTHONPATH: srcPath } },
  { cmd: 'python', args: ['-m', 'mitre_mcp_server.server'], env: { PYTHONPATH: srcPath } },
];

function launch(i) {
  if (i >= candidates.length) {
    console.error('Failed to start server: none of uvx, python3, python were found on PATH.');
    console.error('Install uv (https://docs.astral.sh/uv/) or Python 3.12+ with the package dependencies.');
    process.exit(1);
  }
  const c = candidates[i];
  const env = { ...process.env };
  if (c.env.PYTHONPATH) {
    env.PYTHONPATH = c.env.PYTHONPATH + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : '');
  }

  // stdio must be inherited untouched: it carries the MCP JSON-RPC stream.
  const child = spawn(c.cmd, c.args, { stdio: 'inherit', env, cwd: pkgDir });

  child.on('error', (err) => {
    if (err.code === 'ENOENT') return launch(i + 1); // try next interpreter
    console.error(`Failed to start server with ${c.cmd}: ${err.message}`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
}

launch(0);
