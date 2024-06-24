import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';
import configuration from './config/configuration';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './auth/constants';
import { UserModule } from './user/user.module';
import { EmailModule } from './email/email.module';
import { PrismaService } from './prisma.service';

@Module({
  imports: [
    AuthModule,
    UserModule,
    EmailModule,
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    JwtModule.register({
      global: true,
      secret: jwtConstants.secret,
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
