import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { JwtService } from '@nestjs/jwt';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';
import { EmailService } from 'src/email/email.service';
import { UserModule } from 'src/user/user.module';

@Module({
  imports: [UserModule],
  providers: [
    AuthService,
    JwtService,
    GoogleStrategy,
    FacebookStrategy,
    UserService,
    EmailService,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
