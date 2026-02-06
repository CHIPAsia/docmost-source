import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';
import { MfaService } from './mfa.service';
import { MfaTokenGuard } from './guards/mfa-token.guard';
import { MfaOrJwtGuard } from './guards/mfa-or-jwt.guard';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { MfaSetupDto } from './dto/mfa-setup.dto';
import { MfaEnableDto } from './dto/mfa-enable.dto';
import { MfaVerifyDto } from './dto/mfa-verify.dto';
import { MfaDisableDto } from './dto/mfa-disable.dto';
import { MfaGenerateBackupCodesDto } from './dto/mfa-generate-backup-codes.dto';
import WorkspaceAbilityFactory from '../casl/abilities/workspace-ability.factory';
import {
  WorkspaceCaslAction,
  WorkspaceCaslSubject,
} from '../casl/interfaces/workspace-ability.type';
import { UserRole } from '../../common/helpers/types/permission';

@Controller('mfa')
export class MfaController {
  constructor(
    private mfaService: MfaService,
    private environmentService: EnvironmentService,
    private workspaceAbility: WorkspaceAbilityFactory,
  ) {}

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('status')
  async getStatus(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.mfaService.getStatus(user, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('setup')
  async setup(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() _dto: MfaSetupDto,
  ) {
    return this.mfaService.setup(user, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('enable')
  async enable(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() dto: MfaEnableDto,
  ) {
    return this.mfaService.enable(
      user,
      workspace.id,
      dto.secret,
      dto.verificationCode,
    );
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('disable')
  async disable(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() dto: MfaDisableDto,
  ) {
    return this.mfaService.disable(user, workspace.id, dto.confirmPassword);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('generate-backup-codes')
  async generateBackupCodes(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Body() dto: MfaGenerateBackupCodesDto,
  ) {
    return this.mfaService.regenerateBackupCodes(
      user,
      workspace.id,
      dto.confirmPassword,
    );
  }

  @UseGuards(MfaTokenGuard)
  @HttpCode(HttpStatus.OK)
  @Post('verify')
  async verify(
    @Req() req: FastifyRequest & { user: { user: User; workspace: Workspace } },
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() dto: MfaVerifyDto,
  ) {
    const { user, workspace } = req.user;
    const authToken = await this.mfaService.verify(
      user.id,
      workspace.id,
      dto.code,
    );

    res.setCookie('authToken', authToken, {
      httpOnly: true,
      path: '/',
      expires: this.environmentService.getCookieExpiresIn(),
      secure: this.environmentService.isHttps(),
    });

    return {};
  }

  @UseGuards(MfaOrJwtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('validate-access')
  async validateAccess(
    @Req() req: FastifyRequest & {
      user: { user: User; workspace: Workspace; tokenType: string };
    },
  ) {
    return this.mfaService.validateAccess(req.user, req.user.tokenType);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('admin/status/:userId')
  async getAdminStatus(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Param('userId') targetUserId: string,
  ) {
    const ability = this.workspaceAbility.createForUser(user, workspace);
    if (
      ability.cannot(WorkspaceCaslAction.Manage, WorkspaceCaslSubject.Member)
    ) {
      throw new ForbiddenException();
    }
    return this.mfaService.getStatusForUser(targetUserId, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('admin/disable/:userId')
  async adminDisable(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
    @Param('userId') targetUserId: string,
  ) {
    // Only owners can disable 2FA for other members (e.g. when they lose their device)
    if (user.role !== UserRole.OWNER) {
      throw new ForbiddenException(
        'Only workspace owners can disable 2FA for other members',
      );
    }
    await this.mfaService.adminDisable(targetUserId, workspace.id);
    return { success: true };
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('admin/members-status')
  async getMembersMfaStatus(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    const ability = this.workspaceAbility.createForUser(user, workspace);
    if (
      ability.cannot(WorkspaceCaslAction.Read, WorkspaceCaslSubject.Member)
    ) {
      throw new ForbiddenException();
    }
    return this.mfaService.getMembersMfaStatus(workspace.id);
  }
}
