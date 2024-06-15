import { IsString, MinLength, IsNumber } from 'class-validator';

export class RefreshTokenDto {
  @IsNumber()
  userId: number;

  @IsString()
  @MinLength(50)
  refreshToken: string;
}
