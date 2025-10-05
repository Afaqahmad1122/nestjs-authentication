import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../entities/user.entity/user.entity';
import { RegisterDto } from './dto/register.dto/register.dto';
import { LoginDto } from './dto/login.dto/login.dto';

interface GoogleUser {
  email: string;
  firstName: string;
  lastName: string;
  googleId: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(
    registerDto: RegisterDto,
  ): Promise<{ user: Partial<User>; accessToken: string }> {
    const existingUser = await this.userRepository.findOne({
      where: { email: registerDto.email },
    });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const user = this.userRepository.create(registerDto);
    const savedUser = await this.userRepository.save(user);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = savedUser;

    const payload = { email: savedUser.email, sub: savedUser.id };
    const accessToken = this.jwtService.sign(payload);

    return { user: userWithoutPassword, accessToken };
  }

  async login(
    loginDto: LoginDto,
  ): Promise<{ user: Partial<User>; accessToken: string }> {
    const user = await this.userRepository.findOne({
      where: { email: loginDto.email },
    });
    if (!user || !(await user.validatePassword(loginDto.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user;
    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload);

    return { user: userWithoutPassword, accessToken };
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (user && (await user.validatePassword(password))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async googleLogin(
    user: GoogleUser,
  ): Promise<{ user: Partial<User>; accessToken: string }> {
    const existingUser = await this.userRepository.findOne({
      where: { googleId: user.googleId },
    });

    if (existingUser) {
      const payload = { email: existingUser.email, sub: existingUser.id };
      const accessToken = this.jwtService.sign(payload);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...userWithoutPassword } = existingUser;
      return { user: userWithoutPassword, accessToken };
    }

    // Create new user
    const newUser = this.userRepository.create({
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      googleId: user.googleId,
      password: '', // No password for Google users
    });

    const savedUser = await this.userRepository.save(newUser);
    const payload = { email: savedUser.email, sub: savedUser.id };
    const accessToken = this.jwtService.sign(payload);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = savedUser;

    return { user: userWithoutPassword, accessToken };
  }
}
