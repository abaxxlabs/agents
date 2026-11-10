const $ = (id) => document.getElementById(id);

export function renderAgentSdkPreview(name) {
  $('agent-sdk-code').textContent = `const agent = await scope.createAgentIdentity({
  name: ${JSON.stringify(name)},
  ownerDid: session.humanDid,
});`;
}

export function renderSdkFlow() {
  const columns = [...document.querySelectorAll('#columns-picker input:checked')]
    .map((input) => `orders.${input.value}`);
  const expiresIn = $('credential-ttl').value;
  const sql = $('sql-input').value.trim();
  $('credential-sdk-code').textContent = `const credential = await session.issueCredential({
  agent: agent.did,
  columns: ${JSON.stringify(columns, null, 2)},
  actions: ['read'],
  expiresIn: ${JSON.stringify(expiresIn)},
});`;
  $('sdk-flow-code').textContent = `const result = await scope.query({
  agent: agent.did,
  credential,
  table: 'orders',
  sql: ${JSON.stringify(sql)},
});`;
}
