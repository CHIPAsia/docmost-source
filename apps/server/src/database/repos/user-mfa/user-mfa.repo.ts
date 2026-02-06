import {
  InsertableUserMFA,
  UpdatableUserMFA,
  UserMFA,
} from '@docmost/db/types/entity.types';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';

@Injectable()
export class UserMfaRepo {
  constructor(@InjectKysely() private readonly db: KyselyDB) {}

  async findByUserId(
    userId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<UserMFA | undefined> {
    const db = dbOrTx(this.db, trx);
    return db
      .selectFrom('userMfa')
      .selectAll()
      .where('userId', '=', userId)
      .where('workspaceId', '=', workspaceId)
      .executeTakeFirst();
  }

  async create(
    data: InsertableUserMFA,
    trx?: KyselyTransaction,
  ): Promise<UserMFA> {
    const db = dbOrTx(this.db, trx);
    const result = await db
      .insertInto('userMfa')
      .values(data)
      .returningAll()
      .executeTakeFirstOrThrow();
    return result;
  }

  async update(
    userId: string,
    workspaceId: string,
    data: UpdatableUserMFA,
    trx?: KyselyTransaction,
  ): Promise<void> {
    const db = dbOrTx(this.db, trx);
    await db
      .updateTable('userMfa')
      .set({ ...data, updatedAt: new Date() })
      .where('userId', '=', userId)
      .where('workspaceId', '=', workspaceId)
      .execute();
  }

  async deleteByUserId(
    userId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<void> {
    const db = dbOrTx(this.db, trx);
    await db
      .deleteFrom('userMfa')
      .where('userId', '=', userId)
      .where('workspaceId', '=', workspaceId)
      .execute();
  }

  async findByWorkspaceId(
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<Array<{ userId: string; isEnabled: boolean | null }>> {
    const db = dbOrTx(this.db, trx);
    const rows = await db
      .selectFrom('userMfa')
      .select(['userId', 'isEnabled'])
      .where('workspaceId', '=', workspaceId)
      .execute();
    return rows;
  }
}
