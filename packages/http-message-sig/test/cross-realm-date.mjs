import { runInNewContext } from "node:vm";

export const crossRealmDate = runInNewContext(
  'new Date("2025-01-01T00:00:00Z")'
);
