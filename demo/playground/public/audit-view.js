export function renderAuditRecords(records, hiddenCount, onExpand) {
  const output = document.getElementById('audit-output');
  output.replaceChildren();
  for (const record of records) {
    const item = document.createElement('div');
    const success = record.status === 'success';
    item.className = [
      'audit-item flex flex-col gap-[8px] rounded-[8px] border bg-[rgba(255,255,255,0.01)] p-[16px] font-pg text-[12px] leading-[18px]',
      success ? 'success border-pg-success' : 'rejected border-pg-error',
    ].join(' ');
    const head = document.createElement('div');
    head.className =
      'head flex flex-wrap items-center gap-[12px] text-[12px] leading-[18px] text-pg-subtle mobile:flex-col mobile:items-start mobile:gap-[4px]';
    const status = document.createElement('span');
    status.className = `text-[11px] font-extrabold ${success ? 'st-success text-legacy-green' : 'st-rejected text-legacy-red'}`;
    status.textContent = success ? '✓ SUCCESS' : '✗ REJECTED';
    const facts = [
      new Date(record.timestamp).toLocaleTimeString(),
      `agent ${String(record.agentDid).slice(0, 22)}…`,
      `cols [${Array.isArray(record.columnsAccessed) ? record.columnsAccessed.join(', ') : ''}]`,
      `${record.durationMs}ms`,
    ];
    const factClasses = [
      'text-pg-muted',
      '',
      'text-[13px] text-[#e2e8f0]',
      'text-[13px] text-pg-success',
    ];
    head.append(
      status,
      ...facts.map((fact, index) => {
        const span = document.createElement('span');
        span.className = factClasses[index];
        span.textContent = fact;
        return span;
      }),
    );
    item.appendChild(head);
    if (record.reason) {
      const detail = document.createElement('div');
      detail.className = 'detail break-all font-pg text-[13px] leading-[18px] text-pg-error';
      detail.textContent = `reason: ${record.reason}`;
      item.appendChild(detail);
    }
    const hash = document.createElement('div');
    hash.className = 'hash break-all text-[11px] leading-[16px] text-pg-dim';
    hash.textContent = `hash ← ${String(record.previousHash).slice(0, 16)}… · recorded signature ${String(record.signature).slice(0, 20)}… (not verified here)`;
    item.appendChild(hash);
    output.appendChild(item);
  }
  if (hiddenCount) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className =
      'audit-expand min-h-0 cursor-pointer self-start rounded-[4px] border border-legacy-border bg-transparent py-[0.35rem] px-[0.55rem] font-legacy-mono text-[0.68rem] font-normal leading-[1.2] text-legacy-muted [transition:background_0.15s] hover:border-[#586273] hover:bg-[#1b222c] hover:text-legacy-text';
    button.textContent = `Show ${hiddenCount} more audit ${hiddenCount === 1 ? 'record' : 'records'}`;
    button.addEventListener('click', onExpand);
    output.appendChild(button);
  }
}
