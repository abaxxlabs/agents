// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
