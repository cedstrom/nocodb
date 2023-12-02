import { promisify } from 'util';
import { default as Strategy } from 'passport-ldapauth';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import bcrypt from 'bcryptjs';
import type { Request } from 'express';
import type { VerifyDoneCallback } from 'passport-ldapauth';
import { UsersService } from '~/services/users/users.service';
import { BaseUser, User } from '~/models';
import { sanitiseUserObj } from '~/utils';

export const LdapServerOptions = {
  url: process.env.NC_LDAP_URL || 'ldap://ldap.example.com:389',
  bindDN:
    process.env.NC_LDAP_BIND_DN ||
    'CN=ro_super_user,OU=Users,DC=example,DC=com',
  bindCredentials: process.env.NC_LDAP_BIND_PASSWORD || 'AlrightAlrightAlright',
  searchBase: process.env.NC_LDAP_SEARCH_BASE || 'dc=example,dc=com',
  searchFilter: process.env.NC_LDAP_SEARCH_ATTRIBUTE || '(mail={{username}})',
};

@Injectable()
export class LdapStrategy extends PassportStrategy(Strategy, 'ldap') {
  constructor(private usersService: UsersService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
      server: LdapServerOptions,
      passReqToCallback: true,
    });
    this.usersService = usersService;
  }

  async validate(
    req: Request,
    ldapUser: any,
    done: VerifyDoneCallback,
  ): Promise<any> {
    // mostly copied from older code
    const email = ldapUser.mail;
    try {
      const user = await User.getByEmail(email);
      if (user) {
        // if base id defined extract base level roles
        if (req.ncProjectId) {
          BaseUser.get(req.ncProjectId, user.id)
            .then(async (baseUser) => {
              user.roles = baseUser?.roles || user.roles;
              // + (user.roles ? `,${user.roles}` : '');

              done(null, sanitiseUserObj(user));
            })
            .catch((e) => done(e));
        } else {
          return done(null, sanitiseUserObj(user));
        }
        // if user not found create new user if allowed
        // or return error
      } else {
        const salt = await promisify(bcrypt.genSalt)(10);
        const user = await this.usersService.registerNewUserIfAllowed({
          email_verification_token: null,
          email: email,
          password: '',
          salt,
          req,
        });
        return done(null, sanitiseUserObj(user));
      }
    } catch (err) {
      return done(err);
    }
  }
}
