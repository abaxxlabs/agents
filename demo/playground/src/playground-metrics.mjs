const DEFAULT_BUCKETS = Object.freeze([0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]);
const MAX_LABEL_LENGTH = 100;
const SECRET_LABEL = /secret|token|password|key|cookie|authorization/i;

function escapeLabel(value) {
  return String(value).slice(0, MAX_LABEL_LENGTH).replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('\n', '\\n');
}

function normalizeLabels(labels = {}) {
  return Object.entries(labels)
    .filter(([name, value]) => !SECRET_LABEL.test(name) && value !== undefined && value !== null)
    .map(([name, value]) => [name, escapeLabel(value)])
    .sort(([left], [right]) => left.localeCompare(right));
}

function labelsKey(labels) {
  return labels.map(([name, value]) => `${name}="${value}"`).join(',');
}

function formatValue(value) {
  if (Number.isInteger(value)) return String(value);
  if (!Number.isFinite(value)) return '0';
  return value.toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
}

/**
 * Minimal Prometheus text registry for the Playground. It intentionally stays
 * dependency free and labels every series through a fixed allowlist at call sites.
 */
export function createPlaygroundMetrics() {
  const series = new Map();
  const buckets = new Map();

  function entry(type, name, labels, initial) {
    const normalized = normalizeLabels(labels);
    const key = `${name}|${labelsKey(normalized)}`;
    let current = series.get(key);
    if (!current) {
      current = { type, name, labels: normalized, ...initial };
      series.set(key, current);
    }
    return current;
  }

  function counter(name, labels = {}, value = 1) {
    const current = entry('counter', name, labels, { value: 0 });
    current.value += value;
    return current.value;
  }

  function gauge(name, labels = {}, value) {
    const current = entry('gauge', name, labels, { value: 0 });
    current.value = value;
    return current.value;
  }

  function observe(name, labels = {}, value, buckets = DEFAULT_BUCKETS) {
    const current = entry('histogram', name, labels, {
      count: 0,
      sum: 0,
      buckets: buckets.map(() => 0),
      bucketBounds: [...buckets],
    });
    current.count += 1;
    current.sum += value;
    for (const [index, bound] of current.bucketBounds.entries()) {
      if (value <= bound) current.buckets[index] += 1;
    }
    return current;
  }

  function render() {
    const grouped = new Map();
    for (const current of series.values()) {
      if (!grouped.has(current.name)) grouped.set(current.name, []);
      grouped.get(current.name).push(current);
    }
    const lines = [];
    for (const [name, entries] of [...grouped.entries()].sort(([left], [right]) => left.localeCompare(right))) {
      lines.push(`# TYPE ${name} ${entries[0].type}`);
      for (const current of entries.sort((left, right) => labelsKey(left.labels).localeCompare(labelsKey(right.labels)))) {
        const suffix = current.labels.length ? `{${labelsKey(current.labels)}}` : '';
        if (current.type === 'histogram') {
          for (const [index, bound] of current.bucketBounds.entries()) {
            lines.push(`${name}_bucket{${labelsKey([...current.labels, ['le', String(bound)]])}} ${formatValue(current.buckets[index])}`);
          }
          lines.push(`${name}_bucket{${labelsKey([...current.labels, ['le', '+Inf']])}} ${formatValue(current.count)}`);
          lines.push(`${name}_sum${suffix} ${formatValue(current.sum)}`);
          lines.push(`${name}_count${suffix} ${formatValue(current.count)}`);
        } else {
          lines.push(`${name}${suffix} ${formatValue(current.value)}`);
        }
      }
    }
    return `${lines.join('\n')}\n`;
  }

  function bucketLabel(name, value, { max = 128, fallback = 'other' } = {}) {
    let values = buckets.get(name);
    if (!values) {
      values = new Set();
      buckets.set(name, values);
    }
    const text = String(value);
    if (values.has(text)) return text;
    if (values.size >= max) return fallback;
    values.add(text);
    return text;
  }

  return { counter, gauge, observe, bucketLabel, render };
}
