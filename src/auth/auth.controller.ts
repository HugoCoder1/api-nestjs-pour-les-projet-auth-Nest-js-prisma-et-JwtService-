import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { deleteAccountDto } from './dto/deleteaccount.dto';
// import { AccountProfileDto } from './dto/accountprofile.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authservice: AuthService) {}
  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    return this.authservice.register(registerDto);
  }
  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.authservice.login(loginDto);
  }
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  profile(@Req() req: Request) {
    const userId = req.user['id'];
    return this.authservice.profile(userId);
  }
  @UseGuards(AuthGuard('jwt'))
  @Delete('delete')
  deleteAccount(
    @Req() req: Request,
    @Body() deleteAccountDto: deleteAccountDto,
  ) {
    // const userId = req.user['id'];
    if (!req.user || !req.user['id']) {
      throw new UnauthorizedException('User not authenticated');
    }

    const userId = req.user['id'];
    return this.authservice.deleteAccount(userId, deleteAccountDto);
  }
}
