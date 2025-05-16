import { Injectable, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';
import { first } from 'rxjs';
import { SignupDto } from './dto/signup.dto';

@Injectable()
export class AuthService {
  constructor(private config: ConfigService) {}

  async login(email: string, password: string) {
    try {
      const response = await axios.post(
        `${this.config.get('KEYCLOAK_URL')}/realms/${this.config.get('KEYCLOAK_REALM')}/protocol/openid-connect/token`,
        new URLSearchParams({
            grant_type: 'password',
            client_id: this.config.get<string>('KEYCLOAK_CLIENT_ID')!,
            client_secret: this.config.get<string>('KEYCLOAK_CLIENT_SECRET')!,
            username:email,
            password,
            scope: 'openid profile'
            }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        },
      );
     //Get user Name
       const accessToken = response.data.access_token;
      console.log(response);
         const userInfo = await axios.get(
      `${this.config.get('KEYCLOAK_URL')}/realms/${this.config.get('KEYCLOAK_REALM')}/protocol/openid-connect/userinfo`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
        const profileData = userInfo.data;

       return {
      access_token: accessToken,
      refresh_token: response.data.refresh_token,
      expires_in: response.data.expires_in,
      email: profileData.email,
      firstName : profileData.given_name,
      lastName : profileData.family_name,
      
    };
    } catch (error) {
        console.log(error);
      throw new UnauthorizedException('Invalid credentials');
    }
  }


   private async getAdminToken(): Promise<string> {
    const form = new URLSearchParams({
      grant_type: 'password',
      client_id: this.config.get('KEYCLOAK_ADMIN_CLIENT')!,
      username: this.config.get('KEYCLOAK_ADMIN_USERNAME')!,
      password: this.config.get('KEYCLOAK_ADMIN_PASSWORD')!,
    });

    const response = await axios.post(
      `${this.config.get('KEYCLOAK_URL')}/realms/${this.config.get('KEYCLOAK_ADMIN_REALM')}/protocol/openid-connect/token`,
      form.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    return response.data.access_token;
  }


async signup({
  email,
  password,
  firstName,
  lastName,
  role = 'user',
}: SignupDto) {
    try{
    const token = await this.getAdminToken();

    // Step 1: Create user
    await axios.post(
      `${this.config.get('KEYCLOAK_URL')}/admin/realms/${this.config.get('KEYCLOAK_REALM')}/users`,
      { username: email,
        email:email,
        firstName: firstName,
        lastName :lastName,
        emailVerified: true,
        enabled: true },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      },
    );

    // Step 2: Get user ID
    const userRes = await axios.get(
      `${this.config.get('KEYCLOAK_URL')}/admin/realms/${this.config.get('KEYCLOAK_REALM')}/users?username=${email}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    const userId = userRes.data[0]?.id;
    if (!userId) throw new Error('User creation failed');

    // Step 3: Set password (non-temporary)
    await axios.put(
      `${this.config.get('KEYCLOAK_URL')}/admin/realms/${this.config.get('KEYCLOAK_REALM')}/users/${userId}/reset-password`,
      {
        type: 'password',
        value: password,
        temporary: false,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      },
    );

    // 4. Get the role object
  const rolesRes = await axios.get(
    `${this.config.get('KEYCLOAK_URL')}/admin/realms/${this.config.get('KEYCLOAK_REALM')}/roles`,
    {
      headers: { Authorization: `Bearer ${token}` },
    },
  );
  const roleObj = rolesRes.data.find((r) => r.name === role);
  if (!roleObj) throw new Error(`Role ${role} not found`);

  // 5. Assign the role to the user
  await axios.post(
    `${this.config.get('KEYCLOAK_URL')}/admin/realms/${this.config.get('KEYCLOAK_REALM')}/users/${userId}/role-mappings/realm`,
    [roleObj],
    {
      headers: { Authorization: `Bearer ${token}` },
    },
  );

  return { message: `User created and assigned role '${role}' successfully.` };
}catch(ex)
{
  throw ex;
}
  }

  async refreshToken(refreshToken: string) {
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: this.config.get<string>('KEYCLOAK_CLIENT_ID')!,
    client_secret: this.config.get<string>('KEYCLOAK_CLIENT_SECRET')!, // optional
    refresh_token: refreshToken,
  });

  const tokenUrl = `${this.config.get<string>('KEYCLOAK_URL')}/realms/${this.config.get<string>('KEYCLOAK_REALM')}/protocol/openid-connect/token`;

  try {
    const { data } = await axios.post(tokenUrl, form.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

      return {
        access_token: data.access_token,
        refresh_token: data.refresh_token, 
        expires_in: data.expires_in,
      };
  } catch (err) {
    console.error(' Failed to refresh token:', err.response?.data || err.message);
    throw new UnauthorizedException('Invalid or expired refresh token');
  }
}

  async logout(refreshToken: string) {
    const keycloakUrl = this.config.get('KEYCLOAK_URL');
    const realm = this.config.get('KEYCLOAK_REALM');
    const clientId = this.config.get('KEYCLOAK_CLIENT_ID');
    const clientSecret = this.config.get('KEYCLOAK_CLIENT_SECRET');

    const logoutUrl = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/logout`;

    await axios.post(
      logoutUrl,
      new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: refreshToken,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );

    return { message: 'User logged out successfully' };
  }
}
