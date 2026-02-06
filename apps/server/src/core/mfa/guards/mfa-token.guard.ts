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

@Injectable()
export class MfaTokenGuard implements CanActivate {
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
      throw new UnauthorizedException('MFA token required');
    }

    const payload = await this.tokenService.verifyJwt(token, JwtType.MFA_TOKEN);

    const workspace = await this.workspaceRepo.findById(payload.workspaceId);
    if (!workspace) {
      throw new UnauthorizedException();
    }

    const req = request as any;
    if (req.raw?.workspaceId && req.raw.workspaceId !== payload.workspaceId) {
      throw new UnauthorizedException('Workspace does not match');
    }

    const user = await this.userRepo.findById(payload.sub, payload.workspaceId);
    if (!user || user.deactivatedAt || user.deletedAt) {
      throw new UnauthorizedException();
    }

    request['user'] = { user, workspace };
    return true;
  }
}
