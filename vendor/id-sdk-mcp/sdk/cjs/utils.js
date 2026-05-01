"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dataToBlob = void 0;
const index_js_1 = require("./common/index.js");
/**
 * Set/detect the media type and return the data as bytes.
 *
 * @beta
 */
const dataToBlob = (data, dataFormat) => {
    let dataBlob;
    // Check for Object or String, and if neither, assume bytes.
    const detectedType = (0, index_js_1.universalTypeOf)(data);
    if (dataFormat === 'text/plain' || detectedType === 'String') {
        dataBlob = new Blob([data], { type: 'text/plain' });
    }
    else if (dataFormat === 'application/json' || detectedType === 'Object') {
        const dataBytes = index_js_1.Convert.object(data).toUint8Array();
        dataBlob = new Blob([dataBytes], { type: 'application/json' });
    }
    else if (detectedType === 'Uint8Array' || detectedType === 'ArrayBuffer') {
        dataBlob = new Blob([data], { type: 'application/octet-stream' });
    }
    else if (detectedType === 'Blob') {
        dataBlob = data;
    }
    else {
        throw new Error('data type not supported.');
    }
    dataFormat = dataFormat || dataBlob.type || 'application/octet-stream';
    return { dataBlob, dataFormat };
};
exports.dataToBlob = dataToBlob;
//# sourceMappingURL=utils.js.map