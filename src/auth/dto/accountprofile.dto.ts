import { IsNotEmpty } from 'class-validator';

export class AccountProfileDto {
  @IsNotEmpty()
  password: string;
}
