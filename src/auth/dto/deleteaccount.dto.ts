import { IsString } from 'class-validator';

export class deleteAccountDto {
  @IsString()
  password: string;
}
