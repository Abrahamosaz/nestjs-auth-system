import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from 'src/auth/dtos/create.dto';
import { LoginUserDto } from 'src/auth/dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma.service';
import { MailerService } from '@nestjs-modules/mailer';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { UserService } from 'src/user/user.service';
import { EmailService } from 'src/email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private jwtService: JwtService,
    private readonly emailService: EmailService,
    private readonly userService: UserService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    const user = await this.userService.findUserByEmail(createUserDto.email);

    if (user) {
      throw new HttpException(
        'User with this email already exist',
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      const passwordHash = await this.userService.generateHash(
        createUserDto.password,
      );
      const user = await this.prisma.user.create({
        data: { ...createUserDto, password: passwordHash },
      });

      // send the confirmation email
      await this.emailService.sendTemplateEmail(
        user,
        'confirmEmail.hbs',
        'registration Email',
        'confirm',
      );
      return user;
    } catch (err) {
      console.log('error', err);
      throw new HttpException(
        'Error occurred creating user due to invalid credentials',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async login(loginUserDto: LoginUserDto) {
    const user = await this.userService.findUserByEmail(loginUserDto.email);

    if (!user) {
      throw new HttpException(
        'User with email not found',
        HttpStatus.NOT_FOUND,
      );
    }

    if (user.isLogin) {
      throw new BadRequestException('user already login');
    }

    const password = loginUserDto.password;
    const isMatch = await this.userService.verifyPasswordHash(
      user.password,
      password,
    );

    if (isMatch) {
      await this.userService.updateUserByEmail(user?.email, { isLogin: true });
      return await this.generateAndStoreTokens(user.id);
    }

    throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
  }

  async getNewAccessToken(userId: number, refreshToken: string) {
    const refreshtoken = await this.prisma.refreshToken.findUnique({
      where: {
        userId,
        token: refreshToken,
      },
    });

    if (!refreshtoken) {
      throw new HttpException('Invalid refresh token', HttpStatus.FORBIDDEN);
    }

    if (refreshtoken.blackListed) {
      throw new HttpException(
        'Refresh Token has been blacklisted',
        HttpStatus.FORBIDDEN,
      );
    }

    const newTokens = await this.generateTokens(userId);

    if (newTokens) {
      await this.blackListRefresToken(refreshtoken.token, refreshtoken.userId);

      try {
        await this.storeRefreshToken(newTokens.refreshToken, userId);
      } catch (err) {
        throw new HttpException(
          'Error trying to store refresh token',
          HttpStatus.BAD_REQUEST,
        );
      }
    }

    return newTokens;
  }

  async ConfirmEmail(token: string) {
    let payload: { sub: number };

    try {
      payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('jwt.secret'),
      });
    } catch (err) {
      throw new HttpException('Invalid token', HttpStatus.FORBIDDEN);
    }

    const user: any = await this.userService.findUserbyId(payload.sub);

    if (!user) {
      throw new HttpException('Email does not exist', HttpStatus.FORBIDDEN);
    }

    if (user.confirmEmail) {
      return 'Email already confirmed';
    }

    user.confirmEmail = true;

    await this.userService.updateUserByEmail(user.email, user);
    return 'Email confirm successful';
  }

  async ResetPassword(resetPasswordDto: ResetPasswordDto) {
    let payload: { sub: number };

    try {
      payload = await this.jwtService.verifyAsync(resetPasswordDto.token, {
        secret: this.configService.get<string>('jwt.secret'),
      });
    } catch (err) {
      throw new HttpException('Invalid token', HttpStatus.FORBIDDEN);
    }

    const user = await this.userService.findUserbyId(payload.sub);
    const password = await this.userService.generateHash(
      resetPasswordDto.password,
    );
    user.password = password;

    await this.userService.updateUserByEmail(user.email, user);
    return 'Password reset successful';
  }

  async logout(tokens: { accessToken: string; refreshToken: string }) {
    try {
      const user = await this.userService.verifyJwtToken(tokens.accessToken);
      await this.userService.updateUserByEmail(user?.email, { isLogin: false });
      await this.blackListRefresToken(tokens.refreshToken, user.id);
      return 'logout successful';
    } catch (err) {
      return 'user already logout';
    }
  }
  async generateTokens(userId: number) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
        },
        {
          secret: this.configService.get('jwt.access_secret'),
          expiresIn: '1h',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
        },
        {
          secret: this.configService.get('jwt.refresh_secret'),
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: number) {
    // Create a new date object for the future date
    const expiryDate: Date = new Date();
    expiryDate.setDate(expiryDate.getDate() + 7);

    await this.prisma.refreshToken.create({
      data: { token, userId, expiryDate },
    });
  }

  async blackListRefresToken(token: string, userId: number) {
    await this.prisma.refreshToken.update({
      where: {
        token,
        userId,
      },
      data: {
        blackListed: true,
      },
    });
  }

  async validateOuthUser(userDetails: any, type: 'google' | 'facebook') {
    const user = await this.userService.findUserByEmail(userDetails.email);

    if (user) {
      if (type === 'google' && !user.isGoogle) {
        throw new HttpException(
          'Trying to login with google not accepted, email already exist',
          HttpStatus.FORBIDDEN,
        );
      } else if (type === 'facebook' && !user.isFacebook) {
        throw new HttpException(
          'Trying to login with facebook not accepted, email already exist',
          HttpStatus.FORBIDDEN,
        );
      }

      return user;
    }

    return await this.prisma.user.create({
      data: {
        email: userDetails.email,
        firstName: userDetails.firstName,
        lastName: userDetails.lastName,
        password: '',
        confirmEmail: true,
        isGoogle: type === 'google' ? true : false,
        isFacebook: type === 'facebook' ? true : false,
      },
    });
  }

  async generateAndStoreTokens(userId: number) {
    const { accessToken, refreshToken } = await this.generateTokens(userId);

    try {
      await this.storeRefreshToken(refreshToken, userId);
    } catch (err) {
      throw new HttpException(
        'Error trying to store refresh token',
        HttpStatus.BAD_REQUEST,
      );
    }
    return { userId, accessToken, refreshToken };
  }
}
