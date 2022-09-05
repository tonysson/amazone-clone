import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { newUserDto } from './../user/dtos/new-user.dto';
import { UserDetails } from './../user/user-details.interface';
import { ExistingUserDto } from './../user/dtos/existing-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() user: newUserDto): Promise<UserDetails | null> {
    return this.authService.register(user);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() user: ExistingUserDto): Promise<{ token: string } | null> {
    return this.authService.login(user);
  }

  @Post('verify-jwt')
  @HttpCode(HttpStatus.OK)
  verifyJwt(@Body() payload : {jwt : string}){
    return this.authService.verifyJwt(payload.jwt)
  }
}
