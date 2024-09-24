import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { PrismaService } from './prisma.service';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { deleteAccountDto } from './dto/deleteaccount.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly JwtService: JwtService,
    private readonly ConfigService: ConfigService,
  ) {}
  async register(registerDto: RegisterDto) {
    const { username, email, password } = registerDto;
    const userExist = await this.prisma.user.findUnique({ where: { email } });
    if (userExist) {
      throw new UnauthorizedException('Un utilisateur existe déja');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.create({
      data: { username, email, password: hashedPassword },
    });
    return user;
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not exist');
    }
    const comparePassword = await bcrypt.compare(password, user.password);
    if (!comparePassword) {
      throw new ConflictException('Password not match');
    }
    const payload = {
      sub: user.id,
      email: user.email,
    };
    const token = this.JwtService.sign(payload, {
      expiresIn: '1d',
      secret: this.ConfigService.get('SECRET_KEY'),
    });
    return {
      token,
      user: {
        username: user.username,
        email: user.username,
      },
    };
  }
  async deleteAccount(userId: number, deleteaccountDto: deleteAccountDto) {
    const { password } = deleteaccountDto;
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not Found');
    const passwordcompare = await bcrypt.compare(password, user.password);
    if (!passwordcompare)
      throw new UnauthorizedException('Password dont match');
    await this.prisma.user.delete({ where: { id: userId } });
    return { data: 'User successfully delete' };
  }
  async profile(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException('User not exist');
    }

    return user;
  }
}
