import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';

@Injectable({})
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService ) {}
    async signin(dto: AuthDto) {
        // find the user by email
        const user = await this.prisma.users.findUnique({
            where: {
                email: dto.email,
            },
        });
        // if user does not exist throw exception
        if (!user) throw new ForbiddenException('Credentials incorrect');

        // compare password
        const pwMatches = await argon.verify(user.hash, dto.password,);

        // if password incorrect throw exception
        if(!pwMatches) throw new ForbiddenException('Credentials incorrect');

        // send back the user
        delete user.hash;
        return user;
    }
    async signup(dto: AuthDto) {
        // generate the password hash
        const hash = await argon.hash(dto.password);

        try {
            // save the new user in the  db
            const user = await this.prisma.users.create({
                data : {
                    email: dto.email,
                    hash,
                },
            })

            delete user.hash;

            //return the saved user
            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials Taken');
                }
            }
        }



    }
}
