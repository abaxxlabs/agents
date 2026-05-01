/**
 * Making developing with decentralized identity components simple.
 *
 * ID SDK consists of the following components:
 * - Decentralized Identifiers
 * - Verifiable Credentials
 * - DWN personal and shareable datastores
 *
 * [Link to GitHub Repo](https://github.com/d-protocol/id-sdk)
 *
 * @packageDocumentation
 */
export * from './did-api.js';
export * from './dwn-api.js';
export * from './protocol.js';
export * from './record.js';
export * from './vc-api.js';
export * from './iddwn.js';
export * from './service-options.js';
export * from './credentials/credential-bbs.js';
export { Bbs } from './crypto/crypto-primitives/bbs.js';
export { BbsAlgorithm } from './crypto/crypto-algorithms/bbs.js';
import * as utils from './utils.js';
export { utils };
//# sourceMappingURL=index.js.map