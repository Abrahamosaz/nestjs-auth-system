import { MailerService } from '@nestjs-modules/mailer';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ResetPasswordDto } from 'src/auth/dtos/resetPassword.dto';
import { UserService } from 'src/user/user.service';

@Injectable()
export class EmailService {
  constructor(
    private readonly configService: ConfigService,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly userService: UserService,
  ) {}

  private readonly logger = new Logger(EmailService.name);

  async resendConfirmEmail(email: string) {
    const user = await this.userService.findUserByEmail(email);

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

  async ResetEmail(resetPasswordDto: ResetPasswordDto) {
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

  async sendEmail(options: EmailOptions) {
    try {
      await this.mailerService.sendMail({
        to: options.to,
        subject: options.subject,
        template: options.template,
        context: options.context || {},
      });
    } catch (err) {
      this.logger.error('error sending mail', err);
    }
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

  async sendResetLink(email: string) {
    const user = await this.userService.findUserByEmail(email);

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
}
