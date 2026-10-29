document.addEventListener('submit', function (e) {
  var m = e.target.getAttribute('data-confirm');
  if (m && !window.confirm(m)) e.preventDefault();
});

document.addEventListener('click', function (e) {
  var b = e.target.closest('[data-eye]');
  if (!b) return;
  var i = b.parentNode.querySelector('input');
  i.type = i.type === 'password' ? 'text' : 'password';
  b.classList.toggle('on');
});

document.addEventListener('click', function (e) {
  var b = e.target.closest('[data-theme-toggle]');
  if (!b) return;
  var h = document.documentElement, cur = h.getAttribute('data-theme') ||
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  var next = cur === 'dark' ? 'light' : 'dark';
  h.setAttribute('data-theme', next);
  try { localStorage.setItem('theme', next); } catch (err) {}
});
