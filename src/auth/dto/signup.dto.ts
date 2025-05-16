import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  MinLength,
  Matches,
  IsOptional,
  IsIn,
} from 'class-validator';

export class SignupDto {

  @ApiProperty()
  @IsEmail({}, { message: 'Email must be valid' })
  email: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'First name is required' })
  @MinLength(3, { message: 'First name must be at least 3 characters' })
  firstName: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Last name is required' })
  lastName: string;

  @ApiProperty()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @Matches(/[A-Za-z]/, {
    message: 'Password must contain at least one letter',
  })
  @Matches(/\d/, {
    message: 'Password must contain at least one number',
  })
  @Matches(/[!@#$%^&*]/, {
    message: 'Password must contain at least one special character',
  })
  password: string;

  @ApiProperty()
  @IsOptional()
  @IsIn(['user', 'admin'], { message: 'Role must be either user or admin' })
  role?: string = 'user';
}
