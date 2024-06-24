import { Body, Controller, Post, Res } from '@nestjs/common';
import { EmailService } from './email.service';
import { Response } from 'express';
import { ResendEmailDto } from 'src/auth/dtos/resendEmail.dto';

@Controller('email')
export class EmailController {
  constructor(private readonly emailService: EmailService) {}

  @Post('reset')
  async sendResetLink(
    @Body() resendEmailDto: ResendEmailDto,
    @Res() res: Response,
  ) {
    const message = await this.emailService.sendResetLink(resendEmailDto.email);
    res.status(201).json({ message });
  }

  @Post('resend')
  async resendConfirmLink(
    @Body() resendEmailDto: ResendEmailDto,
    @Res() res: Response,
  ) {
    const message = await this.emailService.resendConfirmEmail(
      resendEmailDto.email,
    );
    res.status(201).json({ message });
  }
}
