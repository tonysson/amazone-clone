import { HttpException, Injectable, HttpStatus } from '@nestjs/common';
import { UserService } from './../user/user.service';
import * as bcrypt from 'bcrypt';
import { newUserDto } from './../user/dtos/new-user.dto';
import { UserDetails } from './../user/user-details.interface';
import { ExistingUserDto } from './../user/dtos/existing-user.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async matchPassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserDetails | null> {
    const user = await this.userService.findByEmail(email);
    const doesUserExist = !!user;
    if (!doesUserExist) return null;
    const matchPassword = await this.matchPassword(password, user.password);
    if (!matchPassword) return null;
    return this.userService._getUserDetails(user);
  }

  async verifyJwt(jwt : string) : Promise<{exp : number}>{
    try {
     const { exp } = await this.jwtService.verifyAsync(jwt)
     return {exp}
    } catch (error) {
      throw new HttpException('Invalid Jwt', HttpStatus.UNAUTHORIZED)
    }
  }

  async register(user: Readonly<newUserDto>): Promise<UserDetails | any> {
    const { name, email, password } = user;
    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) throw new HttpException('Email in use!', HttpStatus.CONFLICT)
    const hashedPassword = await this.hashPassword(password);
    const newUser = await this.userService.create(name, email, hashedPassword);
    return this.userService._getUserDetails(newUser);
  }

  async login(
    existingUser: ExistingUserDto,
  ): Promise<{ token: string } | null> {
    const { email, password } = existingUser;
    const user = await this.validateUser(email, password);

    if (!user)
      throw new HttpException('Credentials invalid!', HttpStatus.UNAUTHORIZED);

    const jwt = await this.jwtService.signAsync({ user });
    return { token: jwt };
  }



}
