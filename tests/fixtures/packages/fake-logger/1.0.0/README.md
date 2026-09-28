<!-- HARMLESS TEST FIXTURE for lockguard. Not a real package. -->
# fake-logger

A tiny namespaced logger used as an inert test fixture by lockguard.

```js
const { createLogger } = require('fake-logger');
const log = createLogger('app');
log.info('hello');
```
