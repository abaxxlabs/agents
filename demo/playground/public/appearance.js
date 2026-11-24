const toggle = document.getElementById('theme-toggle');
const label = document.getElementById('theme-label');

toggle.addEventListener('click', () => {
  const light = document.documentElement.dataset.theme !== 'light';
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  toggle.setAttribute('aria-checked', String(light));
  label.textContent = light ? 'Light' : 'Dark';
});
