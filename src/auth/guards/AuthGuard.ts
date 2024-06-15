import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LoginAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const email = request.body.email;
    const user = await this.authService.findUserByEmail(email);

    if (user.isGoogle) {
      throw new HttpException(
        'Trying to login with a google user not accepted',
        HttpStatus.FORBIDDEN,
      );
    }

    if (user.isFacebook) {
      throw new HttpException(
        'Trying to login with a facebook user not accepted',
        HttpStatus.FORBIDDEN,
      );
    }

    return true;
  }
}
