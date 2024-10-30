import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  Relation,
  JoinColumn,
} from "typeorm";
import { User } from "./user.mjs";

@Entity()
export class Passkey {
  @PrimaryGeneratedColumn()
  id: number;

  // SQL: Store as `TEXT`. Index this column
  @Column({ type: "text" })
  credentialId: string;

  // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
  //      Caution: Node ORM's may map this to a Buffer on retrieval,
  //      convert to Uint8Array as necessary
  @Column({ type: "text" })
  publicKey: string;

  // SQL: Foreign Key to an instance of your internal user model
  @Column({ type: "varchar" })
  userId: string;

  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  @Column({ type: "bigint" })
  counter: number;

  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'
  @Column({ type: "varchar", length: 32 })
  deviceType: "singleDevice" | "multiDevice";

  // SQL: `BOOL` or whatever similar type is supported
  @Column({ type: "boolean" })
  backedUp: boolean;

  // SQL: `VARCHAR(255)` and store string array as a CSV string
  // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
  @Column({ type: "varchar", length: 255, nullable: true, default: null })
  transports?: string;

  @ManyToOne(() => User, (user) => user.passkeys, {
    createForeignKeyConstraints: false,
  })
  @JoinColumn({ name: "userId", referencedColumnName: "id" })
  user: Relation<User>;
}
