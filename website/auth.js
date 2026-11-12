(function () {
  "use strict";

  var config = window.WINNOW_SUPABASE || {};
  var isServiceRole = false;
  var isSecretKey = Boolean(config.anonKey && config.anonKey.indexOf("sb_secret_") === 0);

  if (config.anonKey && config.anonKey.indexOf(".") !== -1) {
    try {
      var payload = config.anonKey.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      while (payload.length % 4) {
        payload += "=";
      }
      isServiceRole = JSON.parse(atob(payload)).role === "service_role";
    } catch (error) {
      isServiceRole = false;
    }
  }

  var configured = Boolean(
    config.url &&
      config.anonKey &&
      window.supabase &&
      /^https?:\/\//.test(config.url) &&
      !isServiceRole &&
      !isSecretKey
  );
  var client = null;
  if (configured) {
    try {
      client = window.supabase.createClient(config.url, config.anonKey);
    } catch (error) {
      client = null;
    }
  }
  var page = document.body.getAttribute("data-page") || "";
  var appPath = "app/";
  var authLinks = Array.prototype.slice.call(document.querySelectorAll("[data-auth-link]"));
  var appLinks = Array.prototype.slice.call(document.querySelectorAll("[data-app-link]"));

  var redirect = function (path) {
    window.location.href = path;
  };

  var redirectUrl = function (path) {
    try {
      return new URL(path, window.location.href).href;
    } catch (error) {
      return path;
    }
  };

  var setAuthLinks = function (session) {
    appLinks.forEach(function (link) {
      link.setAttribute("href", session ? appPath : "signup.html");
    });
    authLinks.forEach(function (link) {
      if (session) {
        link.textContent = "Account";
        link.setAttribute("href", "account.html");
        if (page === "account") {
          link.setAttribute("aria-current", "page");
        } else {
          link.removeAttribute("aria-current");
        }
      } else {
        link.textContent = "Sign in";
        link.setAttribute("href", "signup.html");
        if (page === "auth") {
          link.setAttribute("aria-current", "page");
        } else {
          link.removeAttribute("aria-current");
        }
      }
    });
  };

  var showSetup = function (selector) {
    var node = document.querySelector(selector);
    if (node) {
      node.hidden = false;
    }
  };

  var disableForms = function () {
    document.querySelectorAll(".auth-form").forEach(function (form) {
      form.querySelectorAll("input, button").forEach(function (control) {
        control.disabled = true;
      });
    });
  };

  var handleUnavailable = function () {
    setAuthLinks(null);
    showSetup("#auth-setup");

    var resetSetup = document.querySelector("#reset-setup");
    if (resetSetup) {
      resetSetup.hidden = false;
      var resetLoading = document.querySelector("#reset-loading");
      var resetCard = document.querySelector("#reset-card");
      if (resetLoading) {
        resetLoading.hidden = true;
      }
      if (resetCard) {
        resetCard.hidden = false;
      }
    }

    var accountSetup = document.querySelector("#account-setup");
    if (accountSetup) {
      accountSetup.hidden = false;
      var accountLoading = document.querySelector("#account-loading");
      var accountCard = document.querySelector("#account-card");
      if (accountLoading) {
        accountLoading.hidden = true;
      }
      if (accountCard) {
        accountCard.hidden = false;
      }
      var signOut = document.querySelector("#sign-out");
      if (signOut) {
        signOut.disabled = true;
      }
    }

    disableForms();
  };

  var setAlert = function (selector, message, tone) {
    var node = document.querySelector(selector);
    if (!node) {
      return;
    }
    node.textContent = message || "";
    node.className = "auth-alert";
    if (tone === "success") {
      node.classList.add("auth-alert--success");
    }
    if (tone === "error") {
      node.classList.add("auth-alert--error");
    }
    node.hidden = !message;
  };

  var setBusy = function (button, busy, label) {
    if (!button) {
      return;
    }
    if (busy) {
      button.dataset.original = button.innerHTML;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.innerHTML =
        '<span class="spinner" aria-hidden="true"></span><span>' + label + "</span>";
      return;
    }
    button.disabled = false;
    button.removeAttribute("aria-busy");
    if (button.dataset.original) {
      button.innerHTML = button.dataset.original;
      delete button.dataset.original;
    }
  };

  var messageFor = function (error) {
    var message = error && error.message ? error.message : "Something went wrong. Try again.";
    var lower = message.toLowerCase();
    if (lower.indexOf("invalid login credentials") !== -1) {
      return "Email or password is incorrect.";
    }
    if (lower.indexOf("email not confirmed") !== -1) {
      return "Check your email to confirm your account before signing in.";
    }
    if (lower.indexOf("user already registered") !== -1) {
      return "An account with this email already exists. Sign in instead.";
    }
    if (lower.indexOf("password should be") !== -1) {
      return "Use a stronger password with at least 8 characters.";
    }
    if (lower.indexOf("for security purposes") !== -1) {
      return message;
    }
    if (lower.indexOf("failed to fetch") !== -1 || lower.indexOf("network") !== -1) {
      return "Could not reach Supabase. Check your connection and project settings.";
    }
    return message;
  };

  var validEmail = function (value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  };

  var getField = function (form, name) {
    return form.elements[name];
  };

  var setFieldError = function (input, message) {
    if (!input) {
      return;
    }
    var wrapper = input.closest(".field");
    var error = wrapper ? wrapper.querySelector(".field-error") : null;
    if (!wrapper || !error) {
      return;
    }
    if (message) {
      wrapper.classList.add("has-error");
      input.setAttribute("aria-invalid", "true");
      error.textContent = message;
      error.hidden = false;
    } else {
      wrapper.classList.remove("has-error");
      input.removeAttribute("aria-invalid");
      error.textContent = "";
      error.hidden = true;
    }
  };

  var validate = function (input, message) {
    setFieldError(input, message);
    return !message;
  };

  var focusFirstInvalid = function (form) {
    var invalid = form.querySelector('[aria-invalid="true"]');
    if (invalid) {
      invalid.focus();
    }
  };

  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var input = document.getElementById(button.getAttribute("data-toggle-password"));
      if (!input) {
        return;
      }
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  document.querySelectorAll(".auth-form input").forEach(function (input) {
    input.addEventListener("input", function () {
      if (input.getAttribute("aria-invalid") === "true") {
        setFieldError(input, "");
      }
    });
  });

  var authTabs = Array.prototype.slice.call(document.querySelectorAll("[data-auth-tab]"));
  var authPanels = Array.prototype.slice.call(document.querySelectorAll("[data-auth-panel]"));

  if (authTabs.length && authPanels.length) {
    var activate = function (tab, shouldFocus) {
      var id = tab.getAttribute("data-auth-tab");
      authTabs.forEach(function (item) {
        var selected = item === tab;
        item.setAttribute("aria-selected", selected ? "true" : "false");
        item.setAttribute("tabindex", selected ? "0" : "-1");
      });
      authPanels.forEach(function (panel) {
        panel.hidden = panel.getAttribute("data-auth-panel") !== id;
      });
      if (shouldFocus) {
        tab.focus();
      }
    };

    authTabs.forEach(function (tab, index) {
      tab.addEventListener("click", function () {
        activate(tab);
      });
      tab.addEventListener("keydown", function (event) {
        var next = null;
        if (event.key === "ArrowRight" || event.key === "ArrowDown") {
          next = (index + 1) % authTabs.length;
        } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
          next = (index - 1 + authTabs.length) % authTabs.length;
        } else if (event.key === "Home") {
          next = 0;
        } else if (event.key === "End") {
          next = authTabs.length - 1;
        }
        if (next !== null) {
          event.preventDefault();
          activate(authTabs[next], true);
        }
      });
    });

    var requestedMode = new URLSearchParams(window.location.search).get("mode");
    if (requestedMode === "signup") {
      var signupTab = document.querySelector('[data-auth-tab="signup"]');
      if (signupTab) {
        activate(signupTab);
      }
    }
  }

  if (!client) {
    handleUnavailable();
  } else {
    client.auth
      .getSession()
      .then(function (result) {
        var session = result.data ? result.data.session : null;
        setAuthLinks(session);

        if (page === "auth" && session) {
          redirect(appPath);
          return;
        }

        if (page === "account") {
          var loading = document.querySelector("#account-loading");
          var card = document.querySelector("#account-card");
          if (!session) {
            redirect("signup.html");
            return;
          }
          if (loading) {
            loading.hidden = true;
          }
          if (card) {
            card.hidden = false;
          }
          var user = session.user || {};
          var email = user.email || "";
          var name =
            (user.user_metadata && user.user_metadata.full_name) ||
            email.split("@")[0] ||
            "there";
          var emailNode = document.querySelector("#account-email");
          var nameNode = document.querySelector("#account-name");
          var avatar = document.querySelector("#account-avatar");
          if (emailNode) {
            emailNode.textContent = email;
          }
          if (nameNode) {
            nameNode.textContent = name;
          }
          if (avatar) {
            avatar.textContent = name.charAt(0).toUpperCase();
          }
        }

        if (page === "reset") {
          var resetLoading = document.querySelector("#reset-loading");
          var resetCard = document.querySelector("#reset-card");
          if (resetLoading) {
            resetLoading.hidden = true;
          }
          if (resetCard) {
            resetCard.hidden = false;
          }
          if (!session) {
            setAlert(
              "#reset-alert",
              "This reset link is invalid or has expired. Request a new one from the sign-in page.",
              "error"
            );
            var resetForm = document.querySelector("#password-reset-form");
            if (resetForm) {
              resetForm.hidden = true;
            }
          }
        }
      })
      .catch(function () {
        handleUnavailable();
      });

    client.auth.onAuthStateChange(function (event, session) {
      setAuthLinks(session);
      if (event === "PASSWORD_RECOVERY" && page === "reset" && session) {
        var recoveryLoading = document.querySelector("#reset-loading");
        var recoveryCard = document.querySelector("#reset-card");
        var recoveryForm = document.querySelector("#password-reset-form");
        if (recoveryLoading) {
          recoveryLoading.hidden = true;
        }
        if (recoveryCard) {
          recoveryCard.hidden = false;
        }
        if (recoveryForm) {
          recoveryForm.hidden = false;
        }
        setAlert("#reset-alert", "");
      }
      if (event === "SIGNED_OUT" && page === "account") {
        redirect("signup.html");
      }
    });
  }

  var signinForm = document.querySelector("#signin-form");
  if (signinForm) {
    signinForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!client) {
        return;
      }

      var email = getField(signinForm, "email");
      var password = getField(signinForm, "password");
      var ok = true;
      ok =
        validate(
          email,
          !email.value.trim()
            ? "Enter your email."
            : !validEmail(email.value.trim())
              ? "Enter a valid email address."
              : ""
        ) && ok;
      ok = validate(password, !password.value ? "Enter your password." : "") && ok;
      setAlert("#signin-alert", "");

      if (!ok) {
        focusFirstInvalid(signinForm);
        return;
      }

      var submit = signinForm.querySelector('button[type="submit"]');
      setBusy(submit, true, "Signing in…");
      client.auth
        .signInWithPassword({
          email: email.value.trim(),
          password: password.value
        })
        .then(function (result) {
          if (result.error) {
            throw result.error;
          }
          redirect(appPath);
        })
        .catch(function (error) {
          setBusy(submit, false);
          setAlert("#signin-alert", messageFor(error), "error");
        });
    });

    var forgot = document.querySelector("#forgot-password");
    if (forgot) {
      forgot.addEventListener("click", function () {
        if (!client) {
          return;
        }
        var email = getField(signinForm, "email");
        var value = email.value.trim();
        if (!value || !validEmail(value)) {
          setAlert("#signin-alert", "Enter your email first, then choose Forgot password.", "error");
          email.focus();
          return;
        }

        setAlert("#signin-alert", "");
        forgot.disabled = true;
        client.auth
          .resetPasswordForEmail(value, {
            redirectTo: redirectUrl("reset-password.html")
          })
          .then(function (result) {
            forgot.disabled = false;
            if (result.error) {
              throw result.error;
            }
            setAlert("#signin-alert", "Password reset link sent. Check your email.", "success");
          })
          .catch(function (error) {
            forgot.disabled = false;
            setAlert("#signin-alert", messageFor(error), "error");
          });
      });
    }
  }

  var signupForm = document.querySelector("#signup-form");
  if (signupForm) {
    signupForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!client) {
        return;
      }

      var name = getField(signupForm, "fullName");
      var email = getField(signupForm, "email");
      var password = getField(signupForm, "password");
      var confirm = getField(signupForm, "confirmPassword");
      var ok = true;
      ok =
        validate(
          name,
          !name.value.trim()
            ? "Enter your full name."
            : name.value.trim().length < 2
              ? "Use at least 2 characters."
              : ""
        ) && ok;
      ok =
        validate(
          email,
          !email.value.trim()
            ? "Enter your email."
            : !validEmail(email.value.trim())
              ? "Enter a valid email address."
              : ""
        ) && ok;
      ok =
        validate(
          password,
          !password.value
            ? "Create a password."
            : password.value.length < 8
              ? "Use at least 8 characters."
              : ""
        ) && ok;
      ok =
        validate(
          confirm,
          !confirm.value
            ? "Confirm your password."
            : confirm.value !== password.value
              ? "Passwords do not match."
              : ""
        ) && ok;
      setAlert("#signup-alert", "");

      if (!ok) {
        focusFirstInvalid(signupForm);
        return;
      }

      var submit = signupForm.querySelector('button[type="submit"]');
      setBusy(submit, true, "Creating account…");
      client.auth
        .signUp({
          email: email.value.trim(),
          password: password.value,
          options: {
            data: { full_name: name.value.trim() },
            emailRedirectTo: redirectUrl(appPath)
          }
        })
        .then(function (result) {
          if (result.error) {
            throw result.error;
          }
          if (result.data && result.data.session) {
            redirect(appPath);
            return;
          }
          setBusy(submit, false);
          var signupEmail = email.value.trim();
          var successMessage =
            "Account created. Check " + signupEmail + " for a confirmation link, then sign in.";
          signupForm.reset();
          setAlert("#signup-alert", "");
          var signinEmail = document.querySelector("#signin-email");
          if (signinEmail && !signinEmail.value) {
            signinEmail.value = signupEmail;
            setFieldError(signinEmail, "");
          }
          var signinTab = document.querySelector('[data-auth-tab="signin"]');
          if (signinTab) {
            signinTab.click();
            setAlert("#signin-alert", successMessage, "success");
          } else {
            setAlert("#signup-alert", successMessage, "success");
          }
        })
        .catch(function (error) {
          setBusy(submit, false);
          setAlert("#signup-alert", messageFor(error), "error");
        });
    });
  }

  var resetForm = document.querySelector("#password-reset-form");
  if (resetForm) {
    resetForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (!client) {
        return;
      }

      var password = getField(resetForm, "password");
      var confirm = getField(resetForm, "confirmPassword");
      var ok = true;
      ok =
        validate(
          password,
          !password.value
            ? "Enter a new password."
            : password.value.length < 8
              ? "Use at least 8 characters."
              : ""
        ) && ok;
      ok =
        validate(
          confirm,
          !confirm.value
            ? "Confirm your new password."
            : confirm.value !== password.value
              ? "Passwords do not match."
              : ""
        ) && ok;
      setAlert("#reset-alert", "");

      if (!ok) {
        focusFirstInvalid(resetForm);
        return;
      }

      var submit = resetForm.querySelector('button[type="submit"]');
      setBusy(submit, true, "Updating password…");
      client.auth
        .updateUser({ password: password.value })
        .then(function (result) {
          if (result.error) {
            throw result.error;
          }
          setBusy(submit, false);
          resetForm.hidden = true;
          setAlert("#reset-alert", "Password updated. Taking you to Winnow…", "success");
          window.setTimeout(function () {
            redirect(appPath);
          }, 1400);
        })
        .catch(function (error) {
          setBusy(submit, false);
          setAlert("#reset-alert", messageFor(error), "error");
        });
    });
  }

  var signOut = document.querySelector("#sign-out");
  if (signOut && client) {
    signOut.addEventListener("click", function () {
      signOut.disabled = true;
      client.auth
        .signOut()
        .then(function () {
          redirect("signup.html");
        })
        .catch(function () {
          signOut.disabled = false;
          setAlert("#account-alert", "Could not sign out. Try again.", "error");
        });
    });
  }
})();
