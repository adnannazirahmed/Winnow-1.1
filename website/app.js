(function () {
  "use strict";

  var mobileMenu = document.querySelector(".mobile-menu");
  if (mobileMenu) {
    var mobileLinks = mobileMenu.querySelectorAll("a");
    mobileLinks.forEach(function (link) {
      link.addEventListener("click", function () {
        mobileMenu.removeAttribute("open");
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && mobileMenu.hasAttribute("open")) {
        mobileMenu.removeAttribute("open");
        var summary = mobileMenu.querySelector("summary");
        if (summary) {
          summary.focus();
        }
      }
    });
  }

  var tabs = Array.prototype.slice.call(document.querySelectorAll("[data-workflow-tab]"));
  var panels = Array.prototype.slice.call(document.querySelectorAll("[data-workflow-panel]"));

  if (tabs.length && panels.length) {
    var activateTab = function (tab, shouldFocus) {
      var id = tab.getAttribute("data-workflow-tab");

      tabs.forEach(function (item) {
        var selected = item === tab;
        item.setAttribute("aria-selected", selected ? "true" : "false");
        item.setAttribute("tabindex", selected ? "0" : "-1");
      });

      panels.forEach(function (panel) {
        panel.hidden = panel.getAttribute("data-workflow-panel") !== id;
      });

      if (shouldFocus) {
        tab.focus();
      }
    };

    tabs.forEach(function (tab, index) {
      tab.addEventListener("click", function () {
        activateTab(tab);
      });

      tab.addEventListener("keydown", function (event) {
        var nextIndex = null;

        if (event.key === "ArrowDown" || event.key === "ArrowRight") {
          nextIndex = (index + 1) % tabs.length;
        } else if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
          nextIndex = (index - 1 + tabs.length) % tabs.length;
        } else if (event.key === "Home") {
          nextIndex = 0;
        } else if (event.key === "End") {
          nextIndex = tabs.length - 1;
        }

        if (nextIndex !== null) {
          event.preventDefault();
          activateTab(tabs[nextIndex], true);
        }
      });
    });
  }

  var copyStatus = document.querySelector("[data-copy-status]");

  var copyText = function (text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();

      try {
        document.execCommand("copy");
        area.remove();
        resolve();
      } catch (error) {
        area.remove();
        reject(error);
      }
    });
  };

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.querySelector(button.getAttribute("data-copy"));
      if (!target) {
        return;
      }

      copyText(target.innerText)
        .then(function () {
          var original = button.textContent;
          button.textContent = "Copied";
          if (copyStatus) {
            copyStatus.textContent = "Copied to clipboard.";
          }
          window.setTimeout(function () {
            button.textContent = original;
            if (copyStatus) {
              copyStatus.textContent = "";
            }
          }, 1600);
        })
        .catch(function () {
          if (copyStatus) {
            copyStatus.textContent = "Copy failed. Select the text manually.";
          }
        });
    });
  });

})();
