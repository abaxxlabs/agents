"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isValidXmlSchema112Timestamp = exports.getFutureXmlSchema112Timestamp = exports.getCurrentXmlSchema112Timestamp = void 0;
/**
 * Retrieves the current timestamp in XML Schema 1.1.2 date-time format.
 *
 * This function omits the milliseconds part from the ISO 8601 timestamp, returning a date-time
 * string in the format "yyyy-MM-ddTHH:mm:ssZ".
 *
 * @returns The current timestamp in XML Schema 1.1.2 format.
 *
 * @example
 * const currentTimestamp = getCurrentXmlSchema112Timestamp(); // "2023-08-23T12:34:56Z"
 */
function getCurrentXmlSchema112Timestamp() {
    // Omit the milliseconds part from toISOString() output
    return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}
exports.getCurrentXmlSchema112Timestamp = getCurrentXmlSchema112Timestamp;
/**
 * Calculates a future timestamp in XML Schema 1.1.2 date-time format based on a given number of
 * seconds.
 *
 * This function takes a number of seconds and adds it to the current timestamp, returning a
 * date-time string in the format "yyyy-MM-ddTHH:mm:ssZ" without milliseconds.
 *
 * @param secondsInFuture - The number of seconds to project into the future.
 * @returns The future timestamp in XML Schema 1.1.2 format.
 *
 * @example
 * const futureTimestamp = getFutureXmlSchema112Timestamp(60); // "2023-08-23T12:35:56Z"
 */
function getFutureXmlSchema112Timestamp(secondsInFuture) {
    const futureDate = new Date(Date.now() + secondsInFuture * 1000);
    return futureDate.toISOString().replace(/\.\d+Z$/, 'Z');
}
exports.getFutureXmlSchema112Timestamp = getFutureXmlSchema112Timestamp;
/**
 * Validates a timestamp string against the XML Schema 1.1.2 date-time format.
 *
 * This function checks whether the provided timestamp string conforms to the
 * format "yyyy-MM-ddTHH:mm:ssZ", without milliseconds, as defined in XML Schema 1.1.2.
 *
 * @param timestamp - The timestamp string to validate.
 * @returns `true` if the timestamp is valid, `false` otherwise.
 *
 * @example
 * const isValid = isValidXmlSchema112Timestamp('2023-08-23T12:34:56Z'); // true
 */
function isValidXmlSchema112Timestamp(timestamp) {
    // Format: yyyy-MM-ddTHH:mm:ssZ
    const regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
    if (!regex.test(timestamp)) {
        return false;
    }
    const date = new Date(timestamp);
    return !isNaN(date.getTime());
}
exports.isValidXmlSchema112Timestamp = isValidXmlSchema112Timestamp;
//# sourceMappingURL=utils.js.map