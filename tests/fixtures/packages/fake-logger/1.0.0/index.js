// HARMLESS TEST FIXTURE for lockguard (https://github.com/topics/lockguard).
// fake-logger@1.0.0 - the innocent "before" version of a tiny logging library.
// It is never installed or executed; lockguard only reads it as text.
'use strict';

const LEVELS = ['debug', 'info', 'warn', 'error'];

function pad(value) {
  return String(value).padStart(2, '0');
}

function timestamp(date = new Date()) {
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function format(namespace, level, args) {
  const text = args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg)));
  return `[${timestamp()}] ${level.toUpperCase()} ${namespace}: ${text.join(' ')}`;
}

function createLogger(namespace, options = {}) {
  const minimum = LEVELS.indexOf(options.level || 'info');
  const sink = options.sink || console;
  const logger = {};
  for (const level of LEVELS) {
    logger[level] = (...args) => {
      if (LEVELS.indexOf(level) < minimum) return;
      const line = format(namespace, level, args);
      (sink[level] || sink.log).call(sink, line);
    };
  }
  logger.child = (suffix) => createLogger(`${namespace}:${suffix}`, options);
  return logger;
}

module.exports = { createLogger, LEVELS };
