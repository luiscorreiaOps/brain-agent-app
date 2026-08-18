const grafanaConfig = require('@grafana/eslint-config').default;

module.exports = [
  ...grafanaConfig,
  {
    ignores: ['dist/', 'node_modules/', '.config/'],
  },
];
