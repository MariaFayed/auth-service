import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  Matches,
  IsOptional,
  IsIn,
} from 'class-validator';

export class LoginDto {

  @ApiProperty()
  email: string;

  @ApiProperty()
  password: string;

}
