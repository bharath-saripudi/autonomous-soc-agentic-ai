(function() {
  var SOC = 'http://localhost:8000';
  var T = window.location.hostname;
  var n = 0;
  var _origFetch = window.fetch.bind(window);

  _origFetch(SOC + '/targets', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: window.location.origin, name: T})
  }).catch(function(){});

  function send(method, path, qs, body) {
    n++;
    _origFetch(SOC + '/targets/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target:T, method:method, path:path, query_string:qs||'', body:body||'', source_ip:'browser', user_agent:navigator.userAgent})
    }).then(function(r){return r.json()}).then(function(d) {
      if (d.attacks_detected > 0) console.log('%c[SOC] ATTACK: ' + d.attacks.map(function(a){return a.data.event_type}).join(', '), 'color:red;font-weight:bold');
      else console.log('[SOC] OK:', method, path, '(#' + n + ')');
    }).catch(function(){});
  }

  document.addEventListener('click', function(e) {
    var a = e.target.closest('a[href]');
    if (a) { try { var u = new URL(a.href); send('GET', u.pathname, u.search.slice(1), ''); } catch(x){} }
  }, true);

  document.addEventListener('submit', function(e) {
    if (e.target.tagName === 'FORM') {
      var f = e.target, fd = new URLSearchParams(new FormData(f)).toString();
      try { var u = new URL(f.action||location.href); send(f.method||'POST', u.pathname, u.search.slice(1), fd); } catch(x){}
    }
  }, true);

  window.fetch = function(i, o) {
    try {
      var url = new URL(i, location.origin);
      if (url.hostname === T) {
        send((o&&o.method)||'GET', url.pathname, url.search.slice(1), (o&&typeof o.body==='string')?o.body:'');
      }
    } catch(x){}
    return _origFetch.apply(window, arguments);
  };

  var _origOpen = XMLHttpRequest.prototype.open;
  var _origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u) { this._m=m; this._u=u; return _origOpen.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(b) {
    try {
      var url = new URL(this._u, location.origin);
      if (url.hostname === T) {
        send(this._m, url.pathname, url.search.slice(1), b||'');
      }
    } catch(x){}
    return _origSend.apply(this, arguments);
  };

  send('GET', location.pathname, location.search.slice(1), '');
  console.log('%c[SOC] Traffic monitor active for: ' + T, 'color:#3edfcf;font-weight:bold;font-size:14px');
  console.log('[SOC] Browse the site - attacks will appear on your dashboard');
})();