import { Controller, Post, Body, Req, Res, Get, UnauthorizedException,Headers ,Logger ,Injectable} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { SignupDto } from './dto/signup.dto';
import { ApiOperation } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {

  private jwks: ReturnType<typeof jwksClient>;
  private issuer: string;
  private audience: string | undefined;
   private readonly logger = new Logger(AuthController.name);

  constructor(private authService: AuthService,private config: ConfigService) {

    const realm = this.config.get<string>('KEYCLOAK_REALM');
    const keycloakUrl = this.config.get<string>('KEYCLOAK_URL');

    this.issuer = `${keycloakUrl}/realms/${realm}`;
    this.audience = this.config.get<string>('KEYCLOAK_CLIENT_ID');

    this.jwks = jwksClient({
      jwksUri: `${this.issuer}/protocol/openid-connect/certs`,
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
    });
  }

 @ApiOperation({ summary: 'User login' }) 
 @Post('login')
  async login(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const response = await this.authService.login(loginDto.email, loginDto.password);
    this.logger.log(`Login success for ${loginDto.email}`);
    res.cookie('refresh_token', response.refresh_token, {
      httpOnly: true,
      secure: false, 
     sameSite: 'lax',
       path: '/', 
    });

    return { access_token: response.access_token
            , expires_in: response.expires_in 
            , email: response.email
            , firstName: response.firstName
             , lastName: response.lastName };
  }

  @ApiOperation({ summary: 'Refresh Token' })
  @Post('refresh')
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) throw new Error('Refresh token missing');

    const tokens = await this.authService.refreshToken(refreshToken);

    res.cookie('refresh_token', tokens.refresh_token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/auth/refresh',
    });

    return { access_token: tokens.access_token, expires_in: tokens.expires_in };
  }

  @ApiOperation({ summary: 'User Sign Up' })
  @Post('signup')
  async signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

    private async getPublicKey(kid: string): Promise<string> {
    const key = await this.jwks.getSigningKey(kid);
    return key.getPublicKey();
  }

@ApiOperation({ summary: 'Verify Token' })
 @Get('verify')
  async verify(@Headers('authorization') authHeader: string) {
    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Authorization header is missing or malformed');
    }

    const token = authHeader.replace('Bearer ', '');

    try {
      const decodedHeader = jwt.decode(token, { complete: true }) as jwt.Jwt | null;
      const kid = decodedHeader?.header.kid;

      if (!kid) {
        throw new UnauthorizedException('Invalid token: missing key ID (kid)');
      }

      const publicKey = await this.getPublicKey(kid);

      const payload = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
        issuer: this.issuer,
      });

      return { valid: true, payload };
    } catch (err) {
      console.error('Token verification failed:', err.message);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

    @ApiOperation({ summary: 'Log out' })
    @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {

   const refreshToken = req.cookies['refresh_token'];
  if (!refreshToken) {
    return res.status(400).json({ message: 'No refresh token provided' });
  }

  await this.authService.logout(refreshToken);

  // Clear the refresh_token cookie
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  return res.status(200).json({ message: 'Logged out successfully' });
}


}
   


