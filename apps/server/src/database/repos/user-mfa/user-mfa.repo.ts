import {
  InsertableUserMFA,
  UpdatableUserMFA,
  UserMFA,
} from '@docmost/db/types/entity.types';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { sql } from 'kysely';

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
    // Same email can have different user records per workspace (users_email_workspace_id_unique).
    // user_mfa is unique on user_id only, so MFA may be tied to a different workspace's user.
    // Match by email: if any user with same email has MFA enabled, show enabled for this member.
    const rows = await db
      .selectFrom('users')
      .select([
        'users.id as userId',
        sql<boolean>`EXISTS (
          SELECT 1 FROM users u2
          INNER JOIN user_mfa m ON m.user_id = u2.id
          WHERE u2.email = users.email AND m.is_enabled = true
        )`.as('isEnabled'),
      ])
      .where('users.workspaceId', '=', workspaceId)
      .execute();
    return rows.map((r) => ({
      userId: r.userId,
      isEnabled: r.isEnabled ?? false,
    }));
  }
}
