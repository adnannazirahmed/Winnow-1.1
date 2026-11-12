(function () {
  "use strict";

  var config = window.WINNOW_SUPABASE || {};
  var key = config.anonKey || "";
  var configured = Boolean(config.url && /^https:\/\//.test(config.url) && key &&
    !key.startsWith("sb_secret_") && window.supabase);
  if (configured && key.includes(".")) {
    try {
      var payload = key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      configured = JSON.parse(atob(payload)).role !== "service_role";
    } catch (error) {
      configured = false;
    }
  }

  var client = null;
  if (configured) {
    try {
      client = window.supabase.createClient(config.url, key);
    } catch (error) {
      client = null;
    }
  }

  var page = document.body.getAttribute("data-page") || "";
  var appPath = "app/";
  var authLinks = Array.prototype.slice.call(document.querySelectorAll("[data-auth-link]"));
  var appLinks = Array.prototype.slice.call(document.querySelectorAll("[data-app-link]"));

  function setLinks(session) {
    appLinks.forEach(function (link) {
      link.href = session ? appPath : "signup.html";
    });
    authLinks.forEach(function (link) {
      link.textContent = session ? "Account" : "Sign in";
      link.href = session ? "account.html" : "signup.html";
      if ((session && page === "account") || (!session && page === "auth")) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    });
  }

  function setAlert(selector, message) {
    var node = document.querySelector(selector);
    if (node) {
      node.textContent = message || "";
      node.className = "auth-alert" + (message ? " auth-alert--error" : "");
      node.hidden = !message;
    }
  }

  function unavailable() {
    setLinks(null);
    ["#auth-setup", "#account-setup"].forEach(function (selector) {
      var node = document.querySelector(selector);
      if (node) node.hidden = false;
    });
    var loading = document.querySelector("#account-loading");
    var card = document.querySelector("#account-card");
    if (loading) loading.hidden = true;
    if (card) card.hidden = false;
    ["#github-signin", "#sign-out"].forEach(function (selector) {
      var button = document.querySelector(selector);
      if (button) button.disabled = true;
    });
  }

  if (!client) {
    unavailable();
    return;
  }

  var githubButton = document.querySelector("#github-signin");
  if (githubButton) {
    githubButton.addEventListener("click", function () {
      githubButton.disabled = true;
      githubButton.setAttribute("aria-busy", "true");
      setAlert("#signin-alert", "");
      client.auth.signInWithOAuth({
        provider: "github",
        options: { redirectTo: new URL(appPath, window.location.href).href }
      }).then(function (result) {
        if (result.error) throw result.error;
      }).catch(function (error) {
        githubButton.disabled = false;
        githubButton.removeAttribute("aria-busy");
        setAlert("#signin-alert", error && error.message ? error.message : "Could not start GitHub sign-in.");
      });
    });
  }

  client.auth.getSession().then(function (result) {
    if (result.error) throw result.error;
    var session = result.data && result.data.session;
    setLinks(session);
    if (page === "auth" && session) {
      window.location.replace(appPath);
      return;
    }
    if (page === "account") {
      if (!session) {
        window.location.replace("signup.html");
        return;
      }
      var loading = document.querySelector("#account-loading");
      var card = document.querySelector("#account-card");
      if (loading) loading.hidden = true;
      if (card) card.hidden = false;
      var user = session.user || {};
      var metadata = user.user_metadata || {};
      var name = metadata.full_name || metadata.name || metadata.user_name ||
        (user.email ? user.email.split("@")[0] : "GitHub user");
      var email = document.querySelector("#account-email");
      var nameNode = document.querySelector("#account-name");
      var avatar = document.querySelector("#account-avatar");
      if (email) email.textContent = user.email || "Signed in with GitHub";
      if (nameNode) nameNode.textContent = name;
      if (avatar) avatar.textContent = name.charAt(0).toUpperCase();
    }
  }).catch(unavailable);

  client.auth.onAuthStateChange(function (event, session) {
    setLinks(session);
    if (event === "SIGNED_OUT" && page === "account") {
      window.location.replace("signup.html");
    }
  });

  var signOut = document.querySelector("#sign-out");
  if (signOut) {
    signOut.addEventListener("click", function () {
      signOut.disabled = true;
      client.auth.signOut().then(function (result) {
        if (result.error) throw result.error;
        window.location.replace("signup.html");
      }).catch(function () {
        signOut.disabled = false;
        setAlert("#account-alert", "Could not sign out. Try again.");
      });
    });
  }
})();
