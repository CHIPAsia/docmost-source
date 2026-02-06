import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class MfaVerifyDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d{6}$|^[a-zA-Z0-9]{8}$/, {
    message: 'Code must be 6 digits or 8-character backup code',
  })
  code: string;
}
