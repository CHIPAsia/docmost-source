import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { FastifyRequest } from 'fastify';
import { TokenService } from '../../auth/services/token.service';
import { JwtType } from '../../auth/dto/jwt-payload';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { extractBearerTokenFromHeader } from '../../../common/helpers';

/**
 * Guard that accepts either MFA token or access token.
 * Used for validate-access endpoint to support both MFA challenge flow and full auth.
 */
@Injectable()
export class MfaOrJwtGuard implements CanActivate {
  constructor(
    private tokenService: TokenService,
    private userRepo: UserRepo,
    private workspaceRepo: WorkspaceRepo,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const token =
      request.cookies?.authToken || extractBearerTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.tokenService.verifyJwt(token, JwtType.MFA_TOKEN);
      const workspace = await this.workspaceRepo.findById(payload.workspaceId);
      if (!workspace) throw new UnauthorizedException();

      const user = await this.userRepo.findById(payload.sub, payload.workspaceId);
      if (!user || user.deactivatedAt || user.deletedAt) {
        throw new UnauthorizedException();
      }

      request['user'] = { user, workspace, tokenType: JwtType.MFA_TOKEN };
      return true;
    } catch {
      // Try access token
    }

    try {
      const payload = await this.tokenService.verifyJwt(token, JwtType.ACCESS);
      const workspace = await this.workspaceRepo.findById(payload.workspaceId);
      if (!workspace) throw new UnauthorizedException();

      const user = await this.userRepo.findById(payload.sub, payload.workspaceId);
      if (!user || user.deactivatedAt || user.deletedAt) {
        throw new UnauthorizedException();
      }

      request['user'] = { user, workspace, tokenType: JwtType.ACCESS };
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
