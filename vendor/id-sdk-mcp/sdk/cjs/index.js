"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.BbsAlgorithm = exports.Bbs = void 0;
__exportStar(require("./did-api.js"), exports);
__exportStar(require("./dwn-api.js"), exports);
__exportStar(require("./protocol.js"), exports);
__exportStar(require("./record.js"), exports);
__exportStar(require("./vc-api.js"), exports);
__exportStar(require("./iddwn.js"), exports);
__exportStar(require("./service-options.js"), exports);
__exportStar(require("./credentials/credential-bbs.js"), exports);
var bbs_js_1 = require("./crypto/crypto-primitives/bbs.js");
Object.defineProperty(exports, "Bbs", { enumerable: true, get: function () { return bbs_js_1.Bbs; } });
var bbs_js_2 = require("./crypto/crypto-algorithms/bbs.js");
Object.defineProperty(exports, "BbsAlgorithm", { enumerable: true, get: function () { return bbs_js_2.BbsAlgorithm; } });
const utils = __importStar(require("./utils.js"));
exports.utils = utils;
//# sourceMappingURL=index.js.map