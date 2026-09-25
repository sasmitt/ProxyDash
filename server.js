'use strict';
/**
 * ProxyCheck — entry point.
 * Developed by Diwas Khatri.
 */
const config = require('./src/config');
const logger = require('./src/logger');
const { GeoClient } = require('./src/geo/geoClient');
const { JobManager } = require('./src/jobs/manager');
const { createServer } = require('./src/server/httpServer');

function main() {
  const geo = new GeoClient();
  const manager = new JobManager(geo);
  const server = createServer({ manager, geo });

  server.listen(config.port, config.host, () => {
    logger.info('ProxyCheck listening', {
      host: config.host,
      port: config.port,
      version: config.version,
      env: config.env,
      allowPrivateProxies: config.checker.allowPrivateProxies,
    });
    logger.info('Developed by Diwas Khatri');
  });

  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('shutting down', { signal });
    manager.stop();
    geo.stop();
    server.close(() => {
      logger.info('server closed');
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => {
    logger.error('uncaughtException', { error: err.message, stack: err.stack });
  });
  process.on('unhandledRejection', (err) => {
    logger.error('unhandledRejection', { error: err && err.message, stack: err && err.stack });
  });
}

main();
