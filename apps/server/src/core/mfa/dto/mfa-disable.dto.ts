import { IsOptional, IsString } from 'class-validator';

export class MfaDisableDto {
  @IsOptional()
  @IsString()
  confirmPassword?: string;
}
