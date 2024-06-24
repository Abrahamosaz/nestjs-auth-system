import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';

@Injectable()
export class LoginAuthGuard implements CanActivate {
  constructor(private readonly userService: UserService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const email = request.body.email;
    const user = await this.userService.findUserByEmail(email);

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
