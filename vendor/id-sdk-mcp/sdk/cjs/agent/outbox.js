"use strict";
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Outbox = void 0;
const level_1 = require("level");
const index_js_1 = require("../common/index.js");
/**
 * Persists outbound DWN send requests that failed due to network and replays
 * them when draining. Entries are stored in FIFO order (by key).
 */
class Outbox {
    constructor(options = {}) {
        const { agent, dataPath = 'data/AGENT/OUTBOX', db } = options;
        this._agent = agent;
        if (db) {
            this._store = db.sublevel('outbox');
        }
        else {
            this._store = new level_1.Level(dataPath);
        }
    }
    get agent() {
        if (this._agent === undefined) {
            throw new Error('Outbox: Unable to determine agent execution context.');
        }
        return this._agent;
    }
    set agent(agent) {
        this._agent = agent;
    }
    /**
     * Enqueue a failed send for later replay. Payload must be the serializable
     * form (message object and optional data as base64).
     */
    async enqueue(entry) {
        const key = `seq-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
        const value = JSON.stringify(entry);
        await this._store.put(key, value);
    }
    /**
     * Try each queued item: for each entry, try each dwnUrl until one succeeds;
     * on success delete from queue; on total failure leave in queue for next drain.
     */
    async drain() {
        var _a, e_1, _b, _c;
        const agent = this.agent;
        const entries = [];
        try {
            for (var _d = true, _e = __asyncValues(this._store.iterator()), _f; _f = await _e.next(), _a = _f.done, !_a; _d = true) {
                _c = _f.value;
                _d = false;
                const [key, value] = _c;
                if (!key.startsWith('seq-'))
                    continue;
                try {
                    const payload = JSON.parse(value);
                    entries.push([key, payload]);
                }
                catch (_g) {
                    // Skip malformed entries
                }
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (!_d && !_a && (_b = _e.return)) await _b.call(_e);
            }
            finally { if (e_1) throw e_1.error; }
        }
        for (const [key, payload] of entries) {
            const { targetDid, dwnUrls, message, dataBase64 } = payload;
            let sent = false;
            for (const dwnUrl of dwnUrls) {
                try {
                    const request = Object.assign({ dwnUrl,
                        targetDid,
                        message }, (dataBase64 !== undefined
                        ? {
                            data: new Blob([
                                new Uint8Array(index_js_1.Convert.base64Url(dataBase64).toUint8Array()),
                            ]),
                        }
                        : {}));
                    await agent.rpcClient.sendDwnRequest(request);
                    sent = true;
                    break;
                }
                catch (_h) {
                    // Try next endpoint
                }
            }
            if (sent) {
                await this._store.del(key);
            }
        }
    }
    /**
     * Clear all queued entries (for tests or reset).
     */
    async clear() {
        var _a, e_2, _b, _c;
        const keys = [];
        try {
            for (var _d = true, _e = __asyncValues(this._store.iterator()), _f; _f = await _e.next(), _a = _f.done, !_a; _d = true) {
                _c = _f.value;
                _d = false;
                const [key] = _c;
                if (key.startsWith('seq-'))
                    keys.push(key);
            }
        }
        catch (e_2_1) { e_2 = { error: e_2_1 }; }
        finally {
            try {
                if (!_d && !_a && (_b = _e.return)) await _b.call(_e);
            }
            finally { if (e_2) throw e_2.error; }
        }
        await this._store.batch(keys.map((key) => ({ type: 'del', key })));
    }
}
exports.Outbox = Outbox;
//# sourceMappingURL=outbox.js.map