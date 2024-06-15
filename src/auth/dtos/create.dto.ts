import {
  IsString,
  MaxLength,
  IsEmail,
  IsOptional,
  MinLength,
  Matches,
} from 'class-validator';

export class CreateUserDto {
  @IsString()
  @MaxLength(100)
  firstName: string;

  @IsEmail()
  email: string;

  @IsString()
  @MaxLength(100)
  lastName: string;

  @IsString()
  @MinLength(5)
  @Matches(/^(?=.*[A-Z])(?=.*\d).+$/, {
    message:
      'Password must contain at least one uppercase letter and one number',
  })
  password: string;

  @IsString()
  @MinLength(5)
  @Matches(/^(?=.*[A-Z])(?=.*\d).+$/, {
    message:
      'Password must contain at least one uppercase letter and one number',
  })
  confirmPassword: string;

  @IsString()
  @IsOptional()
  role: 'USER' | 'ADMIN';
}
