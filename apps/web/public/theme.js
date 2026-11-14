// Runs before first paint (blocking, external so CSP needs no inline script).
// Applies the saved or system theme and the incoming page-transition state.
(function () {
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem("sw-theme"); } catch (e) {}
  var dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "dark" : "light";
  try {
    if (sessionStorage.getItem("sw-transition") === "1" && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) root.dataset.transition = "in";
    sessionStorage.removeItem("sw-transition");
  } catch (e) {}
})();
