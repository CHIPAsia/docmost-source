import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as OTPAuth from 'otpauth';
import * as QRCode from 'qrcode';
import * as bcrypt from 'bcrypt';
import { UserMfaRepo } from '@docmost/db/repos/user-mfa/user-mfa.repo';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { TokenService } from '../auth/services/token.service';
import { comparePasswordHash } from '../../common/helpers';
import { User, Workspace } from '@docmost/db/types/entity.types';

const BACKUP_CODE_LENGTH = 8;
const BACKUP_CODE_COUNT = 10;

export interface CheckMfaRequirementsResult {
  userHasMfa: boolean;
  requiresMfaSetup: boolean;
  isMfaEnforced: boolean;
  authToken?: string;
  user?: User;
}

@Injectable()
export class MfaService {
  constructor(
    private userMfaRepo: UserMfaRepo,
    private userRepo: UserRepo,
    private workspaceRepo: WorkspaceRepo,
    private tokenService: TokenService,
  ) {}

  async checkMfaRequirements(
    email: string,
    password: string,
    workspace: Workspace,
  ): Promise<CheckMfaRequirementsResult | null> {
    const user = await this.userRepo.findByEmail(email, workspace.id, {
      includePassword: true,
      includeUserMfa: true,
    });

    if (!user || user.deletedAt) {
      return null;
    }

    const isPasswordMatch = await comparePasswordHash(password, user.password);
    if (!isPasswordMatch) {
      return null;
    }

    user.lastLoginAt = new Date();
    await this.userRepo.updateLastLogin(user.id, workspace.id);

    const userHasMfa = (user as any).mfa?.isEnabled ?? false;
    const workspaceEnforcesMfa = workspace.enforceMfa ?? false;

    const { password: _pw, ...userWithoutPassword } = user;

    if (userHasMfa) {
      return {
        userHasMfa: true,
        requiresMfaSetup: false,
        isMfaEnforced: workspaceEnforcesMfa,
        user: userWithoutPassword as User,
      };
    }

    if (workspaceEnforcesMfa) {
      return {
        userHasMfa: false,
        requiresMfaSetup: true,
        isMfaEnforced: true,
        user: userWithoutPassword as User,
      };
    }

    const authToken = await this.tokenService.generateAccessToken(user);
    return {
      userHasMfa: false,
      requiresMfaSetup: false,
      isMfaEnforced: false,
      authToken,
    };
  }

  async getStatus(user: User, workspaceId: string) {
    const mfa = await this.userMfaRepo.findByUserId(user.id, workspaceId);

    if (!mfa) {
      return {
        isEnabled: false,
        method: null,
        backupCodesCount: 0,
      };
    }

    return {
      isEnabled: mfa.isEnabled ?? false,
      method: mfa.method,
      backupCodesCount: mfa.backupCodes?.length ?? 0,
    };
  }

  async setup(user: User, workspaceId: string) {
    const secret = new OTPAuth.Secret({ size: 20 });
    const totp = new OTPAuth.TOTP({
      issuer: 'Docmost',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    const uri = totp.toString();
    const qrCode = await QRCode.toDataURL(uri);
    const manualKey = secret.base32;

    const existing = await this.userMfaRepo.findByUserId(user.id, workspaceId);
    if (existing) {
      await this.userMfaRepo.update(user.id, workspaceId, {
        secret: secret.base32,
        method: 'totp',
        isEnabled: false,
        backupCodes: null,
      });
    } else {
      await this.userMfaRepo.create({
        userId: user.id,
        workspaceId,
        method: 'totp',
        secret: secret.base32,
        isEnabled: false,
        backupCodes: null,
      });
    }

    return {
      method: 'totp',
      qrCode,
      secret: secret.base32,
      manualKey,
    };
  }

  async enable(
    user: User,
    workspaceId: string,
    secret: string,
    verificationCode: string,
  ) {
    const totp = new OTPAuth.TOTP({
      issuer: 'Docmost',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });

    const delta = totp.validate({ token: verificationCode, window: 1 });
    if (delta === null) {
      throw new BadRequestException('Invalid verification code');
    }

    const backupCodes = this.generateBackupCodes();
    const hashedBackupCodes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, 12)),
    );

    await this.userMfaRepo.update(user.id, workspaceId, {
      isEnabled: true,
      backupCodes: hashedBackupCodes,
    });

    return {
      success: true,
      backupCodes,
    };
  }

  async disable(user: User, workspaceId: string, password?: string) {
    const fullUser = await this.userRepo.findById(user.id, workspaceId, {
      includePassword: true,
    });

    if (password && fullUser?.password) {
      const isValid = await comparePasswordHash(password, fullUser.password);
      if (!isValid) {
        throw new BadRequestException('Invalid password');
      }
    }

    await this.userMfaRepo.deleteByUserId(user.id, workspaceId);
    return { success: true };
  }

  async verify(
    userId: string,
    workspaceId: string,
    code: string,
  ): Promise<string> {
    const mfa = await this.userMfaRepo.findByUserId(userId, workspaceId);
    if (!mfa || !mfa.isEnabled) {
      throw new UnauthorizedException('MFA is not enabled');
    }

    const isTotp = /^\d{6}$/.test(code);
    if (isTotp) {
      const totp = new OTPAuth.TOTP({
        issuer: 'Docmost',
        label: 'user',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(mfa.secret!),
      });

      const delta = totp.validate({ token: code, window: 1 });
      if (delta === null) {
        throw new UnauthorizedException('Invalid verification code');
      }
    } else {
      const backupCodes = mfa.backupCodes ?? [];
      let matchedIndex = -1;
      for (let i = 0; i < backupCodes.length; i++) {
        const isMatch = await bcrypt.compare(code, backupCodes[i]);
        if (isMatch) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        throw new UnauthorizedException('Invalid backup code');
      }

      const newBackupCodes = backupCodes.filter((_, i) => i !== matchedIndex);
      await this.userMfaRepo.update(userId, workspaceId, {
        backupCodes: newBackupCodes,
      });
    }

    const user = await this.userRepo.findById(userId, workspaceId);
    if (!user || user.deactivatedAt || user.deletedAt) {
      throw new UnauthorizedException();
    }

    return this.tokenService.generateAccessToken(user);
  }

  async regenerateBackupCodes(
    user: User,
    workspaceId: string,
    password?: string,
  ) {
    const fullUser = await this.userRepo.findById(user.id, workspaceId, {
      includePassword: true,
    });

    if (password && fullUser?.password) {
      const isValid = await comparePasswordHash(password, fullUser.password);
      if (!isValid) {
        throw new BadRequestException('Invalid password');
      }
    }

    const mfa = await this.userMfaRepo.findByUserId(user.id, workspaceId);
    if (!mfa || !mfa.isEnabled) {
      throw new BadRequestException('MFA is not enabled');
    }

    const backupCodes = this.generateBackupCodes();
    const hashedBackupCodes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, 12)),
    );

    await this.userMfaRepo.update(user.id, workspaceId, {
      backupCodes: hashedBackupCodes,
    });

    return { backupCodes };
  }

  async validateAccess(
    user: { user: User; workspace: Workspace },
    tokenType: string,
  ) {
    const mfa = await this.userMfaRepo.findByUserId(
      user.user.id,
      user.workspace.id,
    );

    const userHasMfa = mfa?.isEnabled ?? false;
    const isMfaEnforced = user.workspace.enforceMfa ?? false;

    if (tokenType === 'mfa_token') {
      return {
        valid: true,
        isTransferToken: true,
        userHasMfa,
        requiresMfaSetup: !userHasMfa && isMfaEnforced,
        isMfaEnforced,
      };
    }

    return {
      valid: true,
      isTransferToken: false,
      userHasMfa,
      requiresMfaSetup: false,
      isMfaEnforced,
    };
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
      let code = '';
      for (let j = 0; j < BACKUP_CODE_LENGTH; j++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      codes.push(code);
    }

    return codes;
  }
}
