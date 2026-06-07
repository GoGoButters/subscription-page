import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import pg from 'pg';

const { Pool } = pg;
type PoolType = InstanceType<typeof Pool>;

export interface IVpnUserWhitelistInfo {
    unlimitedExpiryDate: Date | null;
    whitelistSubscription: string | null;
}

@Injectable()
export class PgService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(PgService.name);
    private pool: PoolType | null = null;
    private isAvailable = false;

    constructor(private readonly configService: ConfigService) {}

    async onModuleInit(): Promise<void> {
        const pgHost = this.configService.get<string>('PG_HOST');
        const pgPort = this.configService.get<string>('PG_PORT');
        const pgDatabase = this.configService.get<string>('PG_DATABASE');
        const pgUser = this.configService.get<string>('PG_USER');
        const pgPassword = this.configService.get<string>('PG_PASSWORD');

        if (!pgHost || !pgPort || !pgDatabase || !pgUser || !pgPassword) {
            this.logger.warn(
                '[SKIP] PostgreSQL not configured — whitelist routing disabled. Set PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD in .env to enable.',
            );
            return;
        }

        try {
            this.pool = new Pool({
                host: pgHost,
                port: parseInt(pgPort, 10),
                database: pgDatabase,
                user: pgUser,
                password: pgPassword,
                max: 5,
                idleTimeoutMillis: 30_000,
                connectionTimeoutMillis: 5_000,
            });

            // Test connection
            const client = await this.pool.connect();
            client.release();

            this.isAvailable = true;
            this.logger.log('[OK] Connected to PostgreSQL — whitelist routing enabled.');
        } catch (error) {
            this.logger.error(
                `[WARN] Failed to connect to PostgreSQL — whitelist routing disabled. Error: ${error}`,
            );
            this.pool = null;
            this.isAvailable = false;
        }
    }

    async onModuleDestroy(): Promise<void> {
        if (this.pool) {
            await this.pool.end();
            this.logger.log('[OK] PostgreSQL pool closed.');
        }
    }

    public getIsAvailable(): boolean {
        return this.isAvailable;
    }

    public async findUserByRmwUuid(rmwUuid: string): Promise<IVpnUserWhitelistInfo | null> {
        if (!this.pool || !this.isAvailable) {
            return null;
        }

        try {
            const result = await this.pool.query<{
                unlimited_expiry_date: Date | null;
                whitelist_subscription: string | null;
            }>(
                `SELECT unlimited_expiry_date, whitelist_subscription FROM vpn_users
                 WHERE rmw_uuid = $1 OR sub LIKE '%/' || $1
                 LIMIT 1`,
                [rmwUuid],
            );

            if (result.rows.length === 0) {
                return null;
            }

            const row = result.rows[0];

            return {
                unlimitedExpiryDate: row.unlimited_expiry_date,
                whitelistSubscription: row.whitelist_subscription,
            };
        } catch (error) {
            this.logger.error(`Error querying vpn_users for rmw_uuid=${rmwUuid}: ${error}`);
            return null;
        }
    }
}
