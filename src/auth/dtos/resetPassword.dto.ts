import { IsEmail, IsString, MinLength, minLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @MinLength(50)
  token: string;

  @IsString()
  password: string;

  @IsString()
  confirmPassword: string;
}
