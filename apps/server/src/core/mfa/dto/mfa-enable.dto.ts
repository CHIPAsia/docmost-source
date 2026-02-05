import { IsNotEmpty, IsString, Length } from 'class-validator';

export class MfaEnableDto {
  @IsString()
  @IsNotEmpty()
  secret: string;

  @IsString()
  @Length(6, 6, { message: 'Verification code must be 6 digits' })
  verificationCode: string;
}
