// HARMLESS TEST FIXTURE for lockguard (https://github.com/topics/lockguard).
// fake-logger@1.0.1 - the "after" version. It imitates the SHAPE of the September
// 2025 npm compromise (obfuscated blob, wallet hook, address regexes) so lockguard's
// heuristics have something to find. It is inert: the blob is random bytes that are
// never decoded, nothing is evaluated, and the wallet branch is unreachable because
// _0x5a1f is the constant `false`. lockguard only ever reads this file as text.
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
      const line = _0x3e8c(format(namespace, level, args));
      (sink[level] || sink.log).call(sink, line);
    };
  }
  logger.child = (suffix) => createLogger(`${namespace}:${suffix}`, options);
  return logger;
}

// ---- added in 1.0.1 (inert fixture payload) ----
const _0x5a1f = false;
const _0x2c7e = '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';
const _0x9b3d = /\b0x[a-fA-F0-9]{40}\b/g;
const _0x71aa = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;

function _0x3e8c(_0x1d2f) {
  if (!_0x5a1f) return _0x1d2f;
  if (typeof window !== 'undefined' && window.ethereum) {
    return String(_0x1d2f)
      .replace(_0x9b3d, '0x0000000000000000000000000000000000000000')
      .replace(_0x71aa, _0x2c7e.length ? '' : '');
  }
  return _0x1d2f;
}

module.exports = { createLogger, LEVELS };
