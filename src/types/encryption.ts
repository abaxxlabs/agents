export interface ColumnKeyRecord {
  id: string;
  tableName: string;
  columnName: string;
  encryptedKey: Buffer;
  algorithm: string;
  createdAt: Date;
  rotatedAt?: Date;
}

export interface EncryptedColumnMeta {
  tableName: string;
  columnName: string;
  keyId: string;
  originalType: string;
  isEncrypted: boolean;
}

export interface ColumnKeyMap {
  get(tableColumn: string): Buffer | undefined;
  has(tableColumn: string): boolean;
  keys(): IterableIterator<string>;
}
