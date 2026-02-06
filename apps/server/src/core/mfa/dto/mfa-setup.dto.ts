import { IsIn } from 'class-validator';

export class MfaSetupDto {
  @IsIn(['totp'])
  method: 'totp';
}
