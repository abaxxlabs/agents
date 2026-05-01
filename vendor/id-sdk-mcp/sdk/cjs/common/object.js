"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeUndefinedProperties = exports.removeEmptyObjects = exports.isEmptyObject = void 0;
/**
 * Checks whether the given object has any properties.
 */
function isEmptyObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }
    if (Object.getOwnPropertySymbols(obj).length > 0) {
        return false;
    }
    return Object.keys(obj).length === 0;
}
exports.isEmptyObject = isEmptyObject;
/**
 * Recursively removes all properties with an empty object or array as its value from the given object.
 */
function removeEmptyObjects(obj) {
    Object.keys(obj).forEach(key => {
        if (typeof (obj[key]) === 'object') {
            // recursive remove empty object or array properties in nested objects
            removeEmptyObjects(obj[key]);
        }
        if (isEmptyObject(obj[key])) {
            delete obj[key];
        }
    });
}
exports.removeEmptyObjects = removeEmptyObjects;
/**
 * Recursively removes all properties with `undefined` as its value from the given object.
 */
function removeUndefinedProperties(obj) {
    Object.keys(obj).forEach(key => {
        if (obj[key] === undefined) {
            delete obj[key];
        }
        else if (typeof (obj[key]) === 'object') {
            removeUndefinedProperties(obj[key]); // recursive remove `undefined` properties in nested objects
        }
    });
}
exports.removeUndefinedProperties = removeUndefinedProperties;
//# sourceMappingURL=object.js.map