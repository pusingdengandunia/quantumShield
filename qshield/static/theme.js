"use strict";

// Loaded in <head> without defer, so a saved theme is applied before first paint.
// No saved choice means the page follows the operating system setting.
(() => {
  const KEY = "qshield-theme";
  const root = document.documentElement;
  const system = matchMedia("(prefers-color-scheme: dark)");

  // Storage can be blocked (private window, strict settings); the toggle still
  // works for the current page, it just is not remembered.
  const load = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  const save = (value) => { try { localStorage.setItem(KEY, value); } catch { /* not remembered */ } };

  const saved = load();
  if (saved === "light" || saved === "dark") root.dataset.theme = saved;

  const active = () => root.dataset.theme || (system.matches ? "dark" : "light");

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-button");
    const sync = () => button.setAttribute("aria-pressed", String(active() === "dark"));
    sync();
    button.addEventListener("click", () => {
      const next = active() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      save(next);
      sync();
    });
    system.addEventListener("change", sync);
  });
})();
