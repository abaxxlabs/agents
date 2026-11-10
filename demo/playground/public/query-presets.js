const PRESETS = [
  {
    label: '✗ outside scope',
    cls: 'bad',
    getSql: () => 'SELECT instrument, price, counterparty FROM orders',
  },
  {
    label: '✗ write attempt',
    cls: 'bad',
    getSql: () => 'DELETE FROM orders WHERE id = 1',
  },
  {
    label: '✓ allowed columns',
    cls: 'good',
    getSql: (columns) => {
      if (!columns.length) return null;
      const names = columns.map((column) => column.replace(/^orders\./, ''));
      return `SELECT ${names.join(', ')} FROM orders`;
    },
  },
];

export function createQueryPresets(getColumns, onQueryChange) {
  const input = document.getElementById('sql-input');
  const container = document.getElementById('query-presets');
  const buttons = new Map();
  let selected = PRESETS.find((preset) => preset.getSql(getColumns()) === input.value.trim()) ?? null;

  function syncSelection() {
    if (selected?.getSql(getColumns()) !== input.value.trim()) selected = null;
    for (const [preset, button] of buttons) {
      button.setAttribute('aria-pressed', String(preset === selected));
    }
  }

  for (const preset of PRESETS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = preset.label;
    button.className = [
      preset.cls,
      'min-h-[32px] cursor-pointer rounded-[8px] border border-[rgba(var(--preset-rgb),0.45)] bg-[rgba(var(--preset-rgb),0.06)] py-[6px] px-[12px] font-pg text-[12px] font-semibold leading-[18px] text-preset-accent',
      '[transition:background-color_0.15s,border-color_0.15s,box-shadow_0.15s] hover:border-preset-accent hover:bg-[rgba(var(--preset-rgb),0.14)] aria-pressed:border-preset-accent aria-pressed:bg-[rgba(var(--preset-rgb),0.22)] aria-pressed:[box-shadow:inset_0_0_0_1px_var(--preset-accent)] aria-pressed:hover:bg-[rgba(var(--preset-rgb),0.3)] focus-visible:[outline:2px_solid_var(--playground-text,#fff)] focus-visible:outline-offset-[3px]',
      preset.cls === 'good'
        ? '[--preset-rgb:16,185,129] [--preset-accent:#6ee7b7]'
        : '[--preset-rgb:239,68,68] [--preset-accent:#fca5a5]',
    ].join(' ');
    button.addEventListener('click', () => {
      const sql = preset.getSql(getColumns());
      if (!sql) return;
      input.value = sql;
      selected = preset;
      syncSelection();
      onQueryChange();
    });
    buttons.set(preset, button);
    container.appendChild(button);
  }

  input.addEventListener('input', syncSelection);
  syncSelection();
  return syncSelection;
}
