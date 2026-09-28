// HARMLESS TEST FIXTURE for lockguard. Version 2.3.0 has an off-by-one bug in
// truncate(); 2.3.1 fixes it. This is the "genuine bugfix" that must come out clean.
'use strict';

function capitalize(text) {
  if (!text) return '';
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function camelCase(text) {
  return String(text)
    .toLowerCase()
    .replace(/[-_\s]+(.)?/g, (_, chr) => (chr ? chr.toUpperCase() : ''));
}

function kebabCase(text) {
  return String(text)
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/[\s_]+/g, '-')
    .toLowerCase();
}

function truncate(text, length, suffix = '...') {
  const value = String(text);
  if (value.length <= length) return value;
  return value.slice(0, length) + suffix;
}

function repeat(text, count) {
  return new Array(count + 1).join(text);
}

module.exports = { capitalize, camelCase, kebabCase, truncate, repeat };
