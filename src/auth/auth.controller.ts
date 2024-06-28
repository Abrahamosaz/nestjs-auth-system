import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { CheckPasswords } from './pipes/checkPassword.pipe';
import { CreateUserDto } from 'src/auth/dtos/create.dto';
import { LoginUserDto } from 'src/auth/dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh.dto';
import { Request, Response } from 'express';
import { UserEntity } from './serializers/user.serializer';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { AuthGuard } from '@nestjs/passport';
import { LoginAuthGuard } from './guards/AuthGuard';
import { AuthService } from './auth.service';
import { EmailService } from 'src/email/email.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly emailService: EmailService,
  ) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req: Request) {
    return HttpStatus.OK;
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const user: any = req.user;
      const loginData = await this.authService.generateAndStoreTokens(user.id);
      res.cookie('accessToken', loginData.accessToken);
      res.cookie('refreshToken', loginData.refreshToken);
      return loginData;
    } catch (err) {
      if (err instanceof HttpException) {
        throw err;
      }

      // Handle unexpected errors
      throw new HttpException(
        'Internal Server Error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  async facebookLogin(): Promise<any> {
    return HttpStatus.OK;
  }

  @Get('facebook/redirect')
  @UseGuards(AuthGuard('facebook'))
  async facebookLoginRedirect(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<any> {
    try {
      const user: any = req.user;
      const loginData = await this.authService.generateAndStoreTokens(user.id);
      res.cookie('accessToken', loginData.accessToken);
      res.cookie('refreshToken', loginData.refreshToken);
      return loginData;
    } catch (err) {
      if (err instanceof HttpException) {
        throw err;
      }

      // Handle unexpected errors
      throw new HttpException(
        'Internal Server Error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('signup')
  @UseInterceptors(ClassSerializerInterceptor)
  async registerUser(
    @Body(new CheckPasswords())
    createUserDto: CreateUserDto,
  ) {
    const user = await this.authService.register(createUserDto);
    // send the confirmation email
    await this.emailService.sendTemplateEmail(
      user,
      'confirmEmail.hbs',
      'registration Email',
      'confirm',
    );

    return new UserEntity(user);
  }

  @Post('login')
  @UseGuards(LoginAuthGuard)
  async loginUser(
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const loginData = await this.authService.login(loginUserDto);
    res.cookie('accessToken', loginData.accessToken);
    res.cookie('refreshToken', loginData.refreshToken);
    return loginData;
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const accessToken = req.cookies.accessToken ?? req.body.accessToken;
    const refreshToken = req.cookies.refreshToken ?? req.body.refreshToken;
    const resMessage = await this.authService.logout({
      accessToken,
      refreshToken,
    });
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return resMessage;
  }

  @Post('confirm/:token')
  async confirmEmail(@Param('token') token: string, @Res() res: Response) {
    const message = await this.authService.ConfirmEmail(token);
    res.status(201).json({ message });
  }

  @Post('reset')
  async resetPassword(
    @Body(new CheckPasswords()) resetPasswordDto: ResetPasswordDto,
    @Res() res: Response,
  ) {
    const message = await this.authService.ResetPassword(resetPasswordDto);
    res.status(201).json({ message });
  }

  @Post('refresh')
  refreshAccessToken(
    @Body() refreshData: RefreshTokenDto,
    @Req() req: Request,
  ) {
    const BearerToken: string | undefined =
      (req.headers['authorization'] as string) ||
      (req.headers['Authorization'] as string);

    const userId = refreshData.userId;
    const refreshToken = BearerToken?.split(' ')[1] || refreshData.refreshToken;

    return this.authService.getNewAccessToken(userId, refreshToken);
  }
}
