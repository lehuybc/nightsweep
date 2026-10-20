/* Cấu hình cho Cloudflare Pages: proxy chạy ở /api/proxy (Pages Function). */
window.NIGHT_CONFIG = {
  midnight: function (a) { return '/api/proxy?t=midnight&a=' + encodeURIComponent(a); },
  koios: function (p) { return '/api/proxy?t=koios&p=' + encodeURIComponent(p); },
  ga: 'G-8J8BEL62LT'
};
