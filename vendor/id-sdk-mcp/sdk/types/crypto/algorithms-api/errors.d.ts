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
export declare class CryptoError extends Error {
}
export declare class DataError extends CryptoError {
}
export declare class InvalidAccessError extends CryptoError {
}
export declare class NotSupportedError extends CryptoError {
}
export declare class OperationError extends CryptoError {
}
export declare class SyntaxError extends CryptoError {
}
//# sourceMappingURL=errors.d.ts.map