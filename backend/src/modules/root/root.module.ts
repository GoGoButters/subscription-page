import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { getJWTConfig } from '@common/config/jwt/jwt.config';

import { SubpageConfigService } from './subpage-config.service';
import { WhitelistService } from './whitelist.service';
import { RootController } from './root.controller';
import { RootService } from './root.service';

@Module({
    imports: [JwtModule.registerAsync(getJWTConfig())],
    controllers: [RootController],
    providers: [RootService, SubpageConfigService, WhitelistService],
})
export class RootModule {}

