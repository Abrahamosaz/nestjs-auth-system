import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from 'src/auth/dtos/create.dto';
import { LoginUserDto } from 'src/auth/dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma.service';
import { MailerService } from '@nestjs-modules/mailer';
import { ResetPasswordDto } from './dtos/resetPassword.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    const user = await this.findUserByEmail(createUserDto.email);

    if (user) {
      throw new HttpException(
        'User with this email already exist',
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      const passwordHash = await this.generateHash(createUserDto.password);
      const user = await this.prisma.user.create({
        data: { ...createUserDto, password: passwordHash },
      });

      // send the confirmation email
      await this.sendTemplateEmail(
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
    const user = await this.findUserByEmail(loginUserDto.email);

    if (!user) {
      throw new HttpException(
        'User with email not found',
        HttpStatus.NOT_FOUND,
      );
    }

    const password = loginUserDto.password;
    const isMatch = await this.verifyPasswordHash(user.password, password);

    if (isMatch) {
      return await this.generateAndStoreTokens(user.id);
    }

    throw new HttpException('Invalid credentials', HttpStatus.FORBIDDEN);
  }

  async getNewAccessToken(userId: number, refreshToken: string) {
    const token = await this.prisma.refreshToken.findUnique({
      where: {
        userId,
        token: refreshToken,
      },
    });

    if (!token) {
      throw new HttpException('Invalid refresh token', HttpStatus.FORBIDDEN);
    }

    if (token.blackListed) {
      throw new HttpException(
        'Refresh Token has been blacklisted',
        HttpStatus.FORBIDDEN,
      );
    }

    const newTokens = await this.generateTokens(userId);

    if (newTokens) {
      token.blackListed = true;

      await this.prisma.refreshToken.update({
        where: {
          token: token.token,
          userId: token.userId,
        },
        data: token,
      });

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

  async resendConfirmEmail(email: string) {
    const user = await this.findUserByEmail(email);

    if (!user) {
      if (user) {
        throw new HttpException('Email does not exist', HttpStatus.NOT_FOUND);
      }
    }

    // send the confirmation email
    await this.sendTemplateEmail(
      user,
      'confirmEmail.hbs',
      'Welcome to nestAuth - Confirm Your Email',
      'confirm',
    );

    return 'Confirmation email link sent successful';
  }

  async sendResetLink(email: string) {
    const user = await this.findUserByEmail(email);

    if (!user) {
      if (user) {
        throw new HttpException('Email does not exist', HttpStatus.NOT_FOUND);
      }
    }

    await this.sendTemplateEmail(
      user,
      'resetPasswordEmail.hbs',
      'Password Reset Instructions',
      'reset',
    );

    return 'Reset password email link sent successful';
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

    const user: any = await this.findUserbyId(payload.sub);

    if (!user) {
      throw new HttpException('Email does not exist', HttpStatus.FORBIDDEN);
    }

    if (user.confirmEmail) {
      return 'Email already confirmed';
    }

    user.confirmEmail = true;

    await this.prisma.user.update({
      where: {
        id: payload.sub,
      },
      data: user,
    });

    return 'Email confirm successful';
  }

  async ResetEmail(resetPasswordDto: ResetPasswordDto) {
    let payload: { sub: number };

    try {
      payload = await this.jwtService.verifyAsync(resetPasswordDto.token, {
        secret: this.configService.get<string>('jwt.secret'),
      });
    } catch (err) {
      throw new HttpException('Invalid token', HttpStatus.FORBIDDEN);
    }

    const user = await this.findUserbyId(payload.sub);
    const password = await this.generateHash(resetPasswordDto.password);
    user.password = password;

    await this.prisma.user.update({
      where: {
        id: user.id,
        email: user.email,
      },
      data: user,
    });

    return 'Password reset successful';
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

  async generateHash(password: string) {
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);

    return hash;
  }

  async verifyPasswordHash(hash: string, password: string) {
    return await bcrypt.compare(password, hash);
  }

  async storeRefreshToken(token: string, userId: number) {
    // Create a new date object for the future date
    const expiryDate: Date = new Date();
    expiryDate.setDate(expiryDate.getDate() + 7);

    await this.prisma.refreshToken.create({
      data: { token, userId, expiryDate },
    });
  }

  async sendEmail(options: EmailOptions) {
    try {
      await this.mailerService.sendMail({
        to: options.to,
        subject: options.subject,
        template: options.template,
        context: options.context || {},
      });
    } catch (err) {
      console.log('error sending mail', err);
    }
  }

  async findUserByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findUserbyId(id: number) {
    return await this.prisma.user.findUnique({
      where: { id },
    });
  }

  async sendTemplateEmail(
    user: any,
    template: string,
    subject: string,
    subpath: string,
  ) {
    const activationToken = await this.jwtService.signAsync(
      { sub: user.id },
      {
        secret: this.configService.get('jwt.secret'),
        expiresIn: '1h',
      },
    );

    const EmailLink = `${this.configService.get<string>('templateUrl')}/api/auth/${subpath}/${activationToken}`;
    const year = new Date();
    await this.sendEmail({
      template,
      subject,
      to: user.email,
      context: {
        EmailLink,
        firstName: user.firstName,
        companyName: 'NestauthCompany',
        year: year.getFullYear(),
      },
    });
  }

  async validateOuthUser(userDetails: any, type: 'google' | 'facebook') {
    const user = await this.findUserByEmail(userDetails.email);

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
