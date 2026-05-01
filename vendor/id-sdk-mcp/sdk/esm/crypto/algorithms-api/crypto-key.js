export class CryptoKey {
    constructor(algorithm, extractable, material, type, usages) {
        this.algorithm = algorithm;
        this.extractable = extractable;
        this.material = material;
        this.type = type;
        this.usages = usages;
        // ensure values are not writeable
        Object.defineProperties(this, {
            // TODO
            // These properties can't be fixed immediately on creation of the
            // object because the implementation may build it up in stages.
            // At some point in the operations before returning a key we should
            // freeze the object to prevent further manipulation.
            type: {
                enumerable: true,
                writable: false,
                value: type
            },
            extractable: {
                enumerable: true,
                writable: true,
                value: extractable
            },
            algorithm: {
                enumerable: true,
                writable: false,
                value: algorithm
            },
            usages: {
                enumerable: true,
                writable: true,
                value: usages
            },
            // this is the "key material" used internally
            // it is not enumerable, but we need it to be
            // accessible by algorithm implementations
            material: {
                enumerable: false,
                writable: false,
                value: material
            }
        });
    }
}
//# sourceMappingURL=crypto-key.js.map