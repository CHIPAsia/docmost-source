import { IsOptional, IsString } from 'class-validator';

export class MfaGenerateBackupCodesDto {
  @IsOptional()
  @IsString()
  confirmPassword?: string;
}
