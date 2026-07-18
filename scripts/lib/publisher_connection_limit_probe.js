#!/usr/bin/env node

// This probe intentionally has no user-controlled target or load parameters:
// it exists only to exercise the fixed loopback publisher boundary in CI.
const net = require('node:net');

const TARGET_HOST = '127.0.0.1';
const TARGET_PORT = 3000;
const CONNECTIONS = 70;
const HOLD_MS = 6_000;
const SETTLE_MS = 2_000;
const sockets = [];
let connected = 0;

function closeSockets() {
  for (const socket of sockets) socket.destroy();
}

for (let index = 0; index < CONNECTIONS; index += 1) {
  const socket = net.createConnection({ host: TARGET_HOST, port: TARGET_PORT });
  socket.setTimeout(HOLD_MS + SETTLE_MS, () => socket.destroy());
  socket.on('connect', () => {
    connected += 1;
  });
  socket.on('error', () => {});
  sockets.push(socket);
}

process.once('SIGTERM', () => {
  closeSockets();
  process.exit(143);
});

setTimeout(() => {
  process.stdout.write(`${JSON.stringify({ state: 'holding', requested: CONNECTIONS, connected })}\n`);
  if (connected < 64) {
    closeSockets();
    process.exitCode = 1;
    return;
  }

  setTimeout(() => {
    closeSockets();
  }, HOLD_MS);
}, SETTLE_MS);
