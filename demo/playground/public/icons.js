const NS = 'http://www.w3.org/2000/svg';
const IMAGES = {
  'brand-dark': ['/abaxx-labs-dark.svg', 184, 31],
  'brand-light': ['/abaxx-labs-light.svg', 184, 31],
  agent: ['/agent-icon.svg', 30, 30],
  database: ['/database-icon.svg', 22, 22],
};
let sequence = 0;

function node(tag, attributes) {
  const element = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

export function createSvgIcon(name, className = '') {
  const svg = node('svg', {
    xmlns: NS, fill: 'none', 'aria-hidden': 'true', focusable: 'false',
    class: `block shrink-0 ${className}`,
  });
  let width, height;
  if (name in IMAGES) {
    const [href, w, h] = IMAGES[name];
    width = w;
    height = h;
    svg.append(node('image', { href, width, height, preserveAspectRatio: 'xMidYMid slice' }));
  } else if (name === 'credential') {
    width = 77;
    height = 76;
    const id = `credential-clip-${++sequence}`;
    const defs = node('defs', {});
    const clip = node('clipPath', { id });
    clip.append(node('rect', { x: 0, y: 13, width: 77, height: 53 }));
    defs.append(clip);
    svg.append(
      defs,
      node('image', { href: '/credential-glow-dark.svg', x: -39, y: -40, width: 156, height: 156, class: 'light:hidden' }),
      node('image', { href: '/credential-glow-light.svg', x: -39, y: -40, width: 156, height: 156, class: 'hidden light:block' }),
      node('image', { href: '/credential-icon.svg', x: -19, y: -17, width: 116, height: 116, 'clip-path': `url(#${id})` }),
    );
    svg.setAttribute('overflow', 'visible');
  } else if (name === 'check' || name === 'close') {
    width = height = 12;
    svg.append(node('path', {
      d: name === 'check' ? 'M2.25 6.25L4.5 8.5L9.75 3.25' : 'M3 3L9 9M9 3L3 9',
      stroke: 'currentColor', 'stroke-width': 1.25, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    }));
  } else if (name === 'chevron') {
    width = height = 9;
    svg.append(node('path', { d: 'M2.25 3.375L4.5 5.625L6.75 3.375', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round' }));
  } else if (name === 'lock') {
    width = height = 11;
    const id = `lock-clip-${++sequence}`;
    const defs = node('defs', {});
    const clip = node('clipPath', { id });
    const d = 'M2.2 5.07692V2.53846C2.2 -0.846154 8.8 -0.846154 8.8 2.53846V5.07692H11V11H0V5.07692H2.2Z';
    clip.append(node('path', { d }));
    defs.append(clip);
    svg.append(defs, node('path', { d, stroke: 'currentColor', 'stroke-width': 1.1, 'clip-path': `url(#${id})` }), node('path', { d: 'M2.2 5.07692H8.8', stroke: 'currentColor', 'stroke-width': 0.55 }));
  }
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  return svg;
}

export function mountIcons() {
  for (const target of document.querySelectorAll('[data-icon]')) {
    target.replaceChildren(createSvgIcon(target.dataset.icon));
  }
}
