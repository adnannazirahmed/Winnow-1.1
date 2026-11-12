(function () {
  'use strict';
  if (!window.WINNOW_PUBLIC_MODE) return;
  var config = window.WINNOW_SUPABASE || {};
  if (window.WINNOW_PUBLIC_MODE && (!config.url || !config.anonKey || !window.supabase)) {
    window.location.replace('../signup.html');
    return;
  }
  if (!config.url || !config.anonKey || !window.supabase) return;
  window.WINNOW_PUBLIC_APP = true;
  document.body.classList.add('hosted');
  var accountLink = document.getElementById('hosted-account-link');
  var client = window.supabase.createClient(config.url, config.anonKey);
  var originalFetch = window.fetch.bind(window);
  function accountName(user) {
    var metadata = user.user_metadata || {};
    var identities = user.identities || [];
    var github = identities.find(function (identity) { return identity.provider === 'github'; });
    var identityData = github && github.identity_data || {};
    var candidates = [metadata.full_name, metadata.name, identityData.full_name,
      identityData.name, metadata.user_name, identityData.user_name,
      metadata.preferred_username, identityData.preferred_username];
    for (var i = 0; i < candidates.length; i++) {
      if (typeof candidates[i] === 'string' && candidates[i].trim()) return candidates[i].trim();
    }
    if (typeof user.email === 'string' && user.email.includes('@')) return user.email.split('@')[0];
    return 'Your account';
  }
  function showAccount(session) {
    if (!session || !session.user) return;
    var name = accountName(session.user);
    accountLink.textContent = name;
    accountLink.title = 'Account: ' + name;
    accountLink.setAttribute('aria-label', 'Account for ' + name);
    accountLink.hidden = false;
  }
  function getSession() {
    return client.auth.getSession().then(function (result) {
      if (result.error) throw result.error;
      return result.data && result.data.session;
    });
  }
  var sessionReady = getSession();

  function signIn() { window.location.replace('../signup.html'); }
  sessionReady.then(function (session) {
    if (!session) { signIn(); return; }
    showAccount(session);
  }).catch(signIn);
  client.auth.onAuthStateChange(function (event, session) {
    if (session) showAccount(session);
    else accountLink.hidden = true;
  });

  window.fetch = function (input, options) {
    var url = typeof input === 'string' ? input : input.url;
    if (!/^\/api\//.test(url)) return originalFetch(input, options);
    return getSession().then(function (session) {
      if (!session) { signIn(); throw new Error('Sign in to continue.'); }
      var headers = new Headers((options && options.headers) || (input.headers || {}));
      headers.set('Authorization', 'Bearer ' + session.access_token);
      var requestOptions = Object.assign({}, options || {}, { headers: headers });
      var apiOrigin = (window.WINNOW_API_ORIGIN || '').replace(/\/$/, '');
      if (!/^https:\/\//.test(apiOrigin)) throw new Error('Winnow API is not configured.');
      return originalFetch(apiOrigin + url, requestOptions).then(function (response) {
        if (response.status === 401) signIn();
        return response;
      });
    });
  };

  document.querySelectorAll('[data-load-demo], [data-source-tab="demo"], #reanalyze, #scan-aws, [data-scan-aws], [data-source-tab="live"], #scan-organization, [data-goto="settings"]').forEach(function (element) {
    element.hidden = true;
  });
})();
