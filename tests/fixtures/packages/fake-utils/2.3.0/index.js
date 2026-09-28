// HARMLESS TEST FIXTURE for lockguard. Plain string helpers; never installed or run.
'use strict';

const strings = require('./lib/strings');

module.exports = {
  ...strings,
  isBlank: (value) => value == null || String(value).trim() === '',
};
