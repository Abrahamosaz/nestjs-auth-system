import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
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
import { ResendEmailDto } from './dtos/resendEmail.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { AuthGuard } from '@nestjs/passport';
import { LoginAuthGuard } from './guards/AuthGuard';
import { ApiKeyGuard } from './guards/apiKeyGuard';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req: Request) {
    // This route initiates the Google OAuth2 login flow.
    // The user is redirected to Google for authentication.
    return HttpStatus.OK;
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req: Request) {
    // This route handles the Google OAuth2 callback.
    // The user is redirected here after successful authentication.
    // 'req.user' will contain the authenticated user's information.
    const user: any = req.user;
    return await this.authService.generateAndStoreTokens(user.id);
  }

  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  async facebookLogin(): Promise<any> {
    return HttpStatus.OK;
  }

  @Get('facebook/redirect')
  @UseGuards(AuthGuard('facebook'))
  async facebookLoginRedirect(@Req() req: Request): Promise<any> {
    const user: any = req.user;
    return await this.authService.generateAndStoreTokens(user.id);
  }

  @Get('current_user')
  @UseInterceptors(ClassSerializerInterceptor)
  @UseGuards(ApiKeyGuard)
  async getCurrentUser(@Req() req: Request) {
    const accessToken = req.cookies.accessToken ?? req.body.accessToken;
    const user = await this.authService.getCurrentUser(accessToken);

    return new UserEntity(user);
  }

  @Post('signup')
  @UseInterceptors(ClassSerializerInterceptor)
  async registerUser(
    @Body(new CheckPasswords())
    createUserDto: CreateUserDto,
  ) {
    const user = await this.authService.register(createUserDto);
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

  @Post('email/resend')
  async resendConfirmLink(
    @Body() resendEmailDto: ResendEmailDto,
    @Res() res: Response,
  ) {
    const message = await this.authService.resendConfirmEmail(
      resendEmailDto.email,
    );
    res.status(201).json({ message });
  }

  @Post('confirm/:token')
  async confirmEmail(@Param('token') token: string, @Res() res: Response) {
    const message = await this.authService.ConfirmEmail(token);
    res.status(201).json({ message });
  }

  @Post('email/reset')
  async sendResetLink(
    @Body() resendEmailDto: ResendEmailDto,
    @Res() res: Response,
  ) {
    const message = await this.authService.sendResetLink(resendEmailDto.email);
    res.status(201).json({ message });
  }

  @Post('reset')
  async resetPassword(
    @Body(new CheckPasswords()) resetPasswordDto: ResetPasswordDto,
    @Res() res: Response,
  ) {
    const message = await this.authService.ResetEmail(resetPasswordDto);
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
