"use strict";
/**
 * The methods of KeyManager and KeyManagementSystem interfaces return
 * errors by rejecting the returned promise with a predefined exception
 * defined in ECMAScript [ECMA-262] or DOMException.
 *
 * The following predefined exceptions are used: TypeError.
 *
 * The following DOMException types from [DOM4] are used:
 *   DataError: Data provided to an operation does not meet requirements
 *   InvalidAccessError: The requested operation is not valid for the provided key
 *   NotSupportedError: The algorithm is not supported
 *   OperationError: The operation failed for an operation-specific reason
 *   SyntaxError: A required parameter was missing or out-of-range
 *
 * Reference: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
 *            Section 14.4. Exceptions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SyntaxError = exports.OperationError = exports.NotSupportedError = exports.InvalidAccessError = exports.DataError = exports.CryptoError = void 0;
class CryptoError extends Error {
}
exports.CryptoError = CryptoError;
class DataError extends CryptoError {
}
exports.DataError = DataError;
class InvalidAccessError extends CryptoError {
}
exports.InvalidAccessError = InvalidAccessError;
class NotSupportedError extends CryptoError {
}
exports.NotSupportedError = NotSupportedError;
class OperationError extends CryptoError {
}
exports.OperationError = OperationError;
class SyntaxError extends CryptoError {
}
exports.SyntaxError = SyntaxError;
//# sourceMappingURL=errors.js.map