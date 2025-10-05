import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto/register.dto';
import { LoginDto } from './dto/login.dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard/jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';

interface AuthenticatedUser {
  userId: string;
  email: string;
}

interface GoogleUser {
  email: string;
  firstName: string;
  lastName: string;
  picture: string;
  googleId: string;
  accessToken: string;
}

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req: { user: AuthenticatedUser }): AuthenticatedUser {
    return req.user;
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {
    // This will redirect to Google OAuth
  }

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(
    @Request() req: { user: GoogleUser },
    @Res() res: Response,
  ) {
    const result = await this.authService.googleLogin(req.user);

    // Redirect to frontend with token
    res.redirect(
      `http://localhost:3001/auth/success?token=${result.accessToken}`,
    );
  }
}
