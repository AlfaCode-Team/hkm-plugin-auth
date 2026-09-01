import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Without this, a component left mounted by one test is still in the
// document for the next, and a passing assertion may be reading the
// previous test's render.
afterEach(() => cleanup());

// Node 24+ ships its OWN localStorage, which shadows the one jsdom
// provides and is `undefined` unless node was started with
// --localstorage-file. Any component reading a stored preference
// then dies on `localStorage.getItem` of undefined — the shared
// ThemeProvider does exactly that, so a page wrapped in it fails to
// render for a reason that has nothing to do with the page.
//
// In a browser localStorage always exists, so the honest stand-in is
// a working in-memory one, not a throwing stub.
if (typeof globalThis.localStorage === "undefined" || globalThis.localStorage === null) {
  const store = new Map<string, string>();

  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
      key: (i: number) => [...store.keys()][i] ?? null,
      get length() {
        return store.size;
      },
    },
  });
}