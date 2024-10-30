import { syncDb } from "./datasource.mjs";

(async () => {
  await syncDb(false);
})();
