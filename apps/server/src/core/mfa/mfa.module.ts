import { Module } from '@nestjs/common';
import { MfaController } from './mfa.controller';
import { MfaService } from './mfa.service';
import { MfaTokenGuard } from './guards/mfa-token.guard';
import { MfaOrJwtGuard } from './guards/mfa-or-jwt.guard';
import { TokenModule } from '../auth/token.module';
import { WorkspaceModule } from '../workspace/workspace.module';

@Module({
  imports: [TokenModule, WorkspaceModule],
  controllers: [MfaController],
  providers: [MfaService, MfaTokenGuard, MfaOrJwtGuard],
  exports: [MfaService],
})
export class MfaModule {}
