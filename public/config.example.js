/* Copy to config.js next to index.html. Hosting with PHP proxy: */
window.NIGHT_CONFIG = {
  midnight: function (a) { return 'proxy.php?t=midnight&a=' + encodeURIComponent(a); },
  koios: function (p) { return 'proxy.php?t=koios&p=' + encodeURIComponent(p); },
  // track: 'track.php',        // optional anonymous counters (see server/php/track.php)
  // ga: 'G-XXXXXXXXXX',        // optional Google Analytics (also add Google hosts to your CSP)
  // officialHosts: ['your.domain']  // hosts that do NOT show the "not the official site" warning
};
