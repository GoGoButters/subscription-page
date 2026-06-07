import { ConfigModule } from '@nestjs/config';
import { Module } from '@nestjs/common';

import { validateEnvConfig } from '@common/utils/validate-env-config';
import { configSchema, Env } from '@common/config/app-config';
import { AxiosModule } from '@common/axios/axios.module';
import { PgModule } from '@common/pg/pg.module.js';

import { SubscriptionPageBackendModule } from '@modules/subscription-page-backend.modules';

@Module({
    imports: [
        AxiosModule,
        PgModule,
        ConfigModule.forRoot({
            isGlobal: true,
            cache: true,
            envFilePath: '.env',
            validate: (config) => validateEnvConfig<Env>(configSchema, config),
        }),

        SubscriptionPageBackendModule,
    ],
})
export class AppModule {}

