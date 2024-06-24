import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private jwtService: JwtService,
  ) {}

  async getCurrentUser(accessToken: string) {
    const user = this.verifyJwtToken(accessToken);

    if (!user) {
      throw new NotFoundException('user with this email not found');
    }

    return user;
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

  async updateUserByEmail(email: string, data: any) {
    await this.prisma.user.update({
      where: {
        email,
      },
      data,
    });
  }

  async verifyJwtToken(jwtAccessToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(jwtAccessToken, {
        secret: this.configService.get<string>('jwt.access_secret'),
      });

      return await this.findUserbyId(payload.sub);
    } catch (err) {
      throw err;
    }
  }

  async generateHash(password: string) {
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);

    return hash;
  }

  async verifyPasswordHash(hash: string, password: string) {
    return await bcrypt.compare(password, hash);
  }
}
