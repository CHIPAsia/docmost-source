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
    // Join with users to get MFA status for workspace members.
    // user_mfa has unique constraint on user_id only, so one user has one MFA record.
    // We match by workspace members (users.workspace_id) rather than user_mfa.workspace_id,
    // since the MFA record's workspace_id may differ from the viewed workspace.
    const rows = await db
      .selectFrom('userMfa')
      .innerJoin('users', 'users.id', 'userMfa.userId')
      .select(['userMfa.userId', 'userMfa.isEnabled'])
      .where('users.workspaceId', '=', workspaceId)
      .execute();
    return rows;
  }
}
