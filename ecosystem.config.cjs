// ecosystem.config.cjs — pm2 process definition for cpvpn-server
// v0.1.2 — CommonJS (.cjs). pm2 does not load ESM config files.

module.exports = {
  apps: [
    {
      name: 'cpvpn-server',
      script: 'server.js',
      cwd: '/var/www/cpvpn-server',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s',
      max_memory_restart: '300M',
      watch: false,
      env: {
        NODE_ENV: 'production',
      },
      out_file: '/root/.pm2/logs/cpvpn-server-out.log',
      error_file: '/root/.pm2/logs/cpvpn-server-error.log',
      merge_logs: true,
      time: true,
    },
  ],
};
