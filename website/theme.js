(function () {
  "use strict";

  var key = "winnow-site-theme";
  var stored = "";
  try { stored = window.localStorage.getItem(key) || ""; } catch (error) {}
  var theme = stored === "light" ? "light" : "dark";

  function apply(value) {
    theme = value;
    document.documentElement.setAttribute("data-theme", value);
    var color = document.querySelector('meta[name="theme-color"]');
    if (color) color.setAttribute("content", value === "dark" ? "#0f1312" : "#f4f7f3");
    document.querySelectorAll(".theme-toggle").forEach(function (button) {
      var next = value === "dark" ? "light" : "dark";
      button.textContent = next === "light" ? "Light mode" : "Dark mode";
      button.setAttribute("aria-label", "Switch to " + next + " mode");
    });
  }

  apply(theme);
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".header-actions, .mobile-nav").forEach(function (host) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "theme-toggle";
      button.addEventListener("click", function () {
        var next = theme === "dark" ? "light" : "dark";
        try { window.localStorage.setItem(key, next); } catch (error) {}
        apply(next);
      });
      host.insertBefore(button, host.firstChild);
    });
    apply(theme);
  });
})();
