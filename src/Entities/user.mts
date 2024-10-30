import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  Index,
  Relation,
  JoinColumn,
} from "typeorm";
import { Passkey } from "./passkey.mjs";

@Entity()
export class User {
  @PrimaryGeneratedColumn("uuid")
  public id: string;

  @Column({ type: "varchar" })
  public displayName: string;

  @Column({ type: "varchar" })
  public name: string;

  @Index({ unique: true })
  @Column({ type: "varchar" })
  public email: string;

  @Column({ type: "varchar" })
  public pw: string;

  @OneToMany(() => Passkey, (passkey) => passkey.user, {
    createForeignKeyConstraints: false,
  })
  @JoinColumn({ name: "id", referencedColumnName: "userId" })
  public passkeys: Relation<Passkey[]>;
}
