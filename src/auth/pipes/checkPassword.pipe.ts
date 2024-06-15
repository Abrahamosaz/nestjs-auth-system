import {
  PipeTransform,
  Injectable,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

@Injectable()
export class CheckPasswords implements PipeTransform<any> {
  async transform(value: any) {
    const password = value.password;
    const confirmpassword = value.confirmPassword;
    const result = this.validatePasswords(password, confirmpassword);

    if (!result) {
      throw new HttpException('passwords does not match', HttpStatus.FORBIDDEN);
    }

    delete value.confirmPassword;
    return value;
  }

  private validatePasswords(
    password: string,
    confirmPassword: string,
  ): boolean {
    return password == confirmPassword;
  }
}
