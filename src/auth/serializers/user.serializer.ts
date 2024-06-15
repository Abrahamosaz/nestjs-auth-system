import { Exclude } from 'class-transformer';

export class UserEntity {
  firstName: string;

  email: string;

  lastName: string;

  @Exclude()
  password: string;

  @Exclude()
  confirmPassword: string;

  constructor(partial: Partial<UserEntity>) {
    Object.assign(this, partial);
  }
}
