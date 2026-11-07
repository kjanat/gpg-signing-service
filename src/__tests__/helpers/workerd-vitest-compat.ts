import { AsyncLocalStorage } from "node:async_hooks";

// Vitest 5.1 disables its mock factory storage as a Node performance cleanup.
// Workers does not implement disable(); no cleanup is needed in this runtime.
AsyncLocalStorage.prototype.disable = () => {};
