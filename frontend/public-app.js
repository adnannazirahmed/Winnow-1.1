(function () {
  'use strict';
  if (!window.WINNOW_PUBLIC_MODE) return;
  var config = window.WINNOW_SUPABASE || {};
  if (window.WINNOW_PUBLIC_MODE && (!config.url || !config.anonKey || !window.supabase)) {
    window.location.replace('/signup.html');
    return;
  }
  if (!config.url || !config.anonKey || !window.supabase) return;
  window.WINNOW_PUBLIC_APP = true;
  document.body.classList.add('hosted');
  document.getElementById('hosted-account-link').hidden = false;
  var client = window.supabase.createClient(config.url, config.anonKey);
  var originalFetch = window.fetch.bind(window);
  var sessionReady = client.auth.getSession().then(function (result) {
    return result.data && result.data.session;
  });

  function signIn() { window.location.replace('../signup.html'); }
  sessionReady.then(function (session) { if (!session) signIn(); }).catch(signIn);

  window.fetch = function (input, options) {
    var url = typeof input === 'string' ? input : input.url;
    if (!/^\/api\//.test(url)) return originalFetch(input, options);
    return sessionReady.then(function (session) {
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
