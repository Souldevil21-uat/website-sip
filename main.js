// Mobile nav toggle
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.nav-toggle');
  if (!btn) return;
  var nav = document.querySelector('.site-nav');
  var expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  nav.classList.toggle('open');
});

// Theme toggle with localStorage
(function(){
  var root = document.documentElement;
  var key = 'site-theme';
  var saved = localStorage.getItem(key);
  if(saved){ root.setAttribute('data-theme', saved); }

  document.addEventListener('click', function(e){
    var t = e.target.closest('.theme-toggle');
    if(!t) return;
    var cur = root.getAttribute('data-theme') || 'arcade';
    var next = (cur === 'sunrise') ? 'arcade' : 'sunrise';
    root.setAttribute('data-theme', next);
    localStorage.setItem(key, next);
  });
})();

// Set active nav link by page key
function setActive(key){
  document.querySelectorAll('.site-nav a').forEach(function(a){
    if(a.dataset.nav === key){ a.classList.add('active'); }
  });
}

// Footer year
document.addEventListener('DOMContentLoaded', function(){
  var y = document.getElementById('year');
  if(y){ y.textContent = new Date().getFullYear(); }
});

