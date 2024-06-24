import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const api_key = request.cookies.accessToken ?? request.body.accessToken;
    return await this.verifyApiKey(api_key);
  }

  async verifyApiKey(api_key: string): Promise<boolean> {
    try {
      const user = await this.authService.verifyJwtToken(api_key);

      if (!user) {
        throw new UnauthorizedException(
          'user with this api key does not exist',
        );
      }

      return true;
    } catch (err) {
      throw new UnauthorizedException('provide a valid api key');
    }
  }
}
