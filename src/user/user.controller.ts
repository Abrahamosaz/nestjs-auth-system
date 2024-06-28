import {
  ClassSerializerInterceptor,
  Controller,
  Get,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { Request } from 'express';
import { ApiKeyGuard } from 'src/auth/guards/apiKeyGuard';
import { UserEntity } from 'src/auth/serializers/user.serializer';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('me')
  @UseInterceptors(ClassSerializerInterceptor)
  @UseGuards(ApiKeyGuard)
  async getCurrentUser(@Req() req: Request) {
    const accessToken = req.cookies.accessToken ?? req.body.accessToken;
    const user = await this.userService.getCurrentUser(accessToken);

    return new UserEntity(user);
  }
}
