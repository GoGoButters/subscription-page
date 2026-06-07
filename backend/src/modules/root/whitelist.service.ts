import { Request, Response } from 'express';

import { Injectable, Logger } from '@nestjs/common';

import axios from 'axios';

import { PgService } from '@common/pg/pg.service.js';
import { IGNORED_HEADERS } from '@common/constants/index.js';

@Injectable()
export class WhitelistService {
    private readonly logger = new Logger(WhitelistService.name);

    constructor(private readonly pgService: PgService) {}

    /**
     * Attempts to serve a whitelist subscription for the given user.
     * Returns `true` if the whitelist response was served, `false` if standard Remnawave should be used.
     */
    public async tryServeWhitelist(
        clientIp: string,
        shortUuid: string,
        req: Request,
        res: Response,
    ): Promise<boolean> {
        if (!this.pgService.getIsAvailable()) {
            return false;
        }

        try {
            const vpnUser = await this.pgService.findUserByRmwUuid(shortUuid);

            if (!vpnUser) {
                this.logger.debug(`No vpn_users record for rmw_uuid=${shortUuid}`);
                return false;
            }

            if (!vpnUser.unlimitedExpiryDate || !vpnUser.whitelistSubscription) {
                this.logger.debug(
                    `vpn_users record for rmw_uuid=${shortUuid} has no expiry date or whitelist subscription URL`,
                );
                return false;
            }

            const now = new Date();
            if (vpnUser.unlimitedExpiryDate <= now) {
                this.logger.debug(
                    `vpn_users rmw_uuid=${shortUuid}: unlimited_expiry_date=${vpnUser.unlimitedExpiryDate.toISOString()} is in the past, using standard Remnawave subscription`,
                );
                return false;
            }

            // unlimited_expiry_date is in the future — proxy to whitelist webhook
            this.logger.log(
                `Whitelist active for rmw_uuid=${shortUuid}, proxying to webhook`,
            );

            return await this.proxyToWebhook(
                clientIp,
                vpnUser.whitelistSubscription,
                req,
                res,
            );
        } catch (error) {
            this.logger.error(`Error in tryServeWhitelist for rmw_uuid=${shortUuid}: ${error}`);
            return false;
        }
    }

    /**
     * Checks if a user has an active whitelist subscription (for browser/webpage title purposes).
     * Returns `true` if whitelist is active, `false` otherwise.
     */
    public async isWhitelistActive(shortUuid: string): Promise<boolean> {
        if (!this.pgService.getIsAvailable()) {
            return false;
        }

        try {
            const vpnUser = await this.pgService.findUserByRmwUuid(shortUuid);

            if (!vpnUser?.unlimitedExpiryDate || !vpnUser?.whitelistSubscription) {
                return false;
            }

            return vpnUser.unlimitedExpiryDate > new Date();
        } catch (error) {
            this.logger.error(`Error checking whitelist status for rmw_uuid=${shortUuid}: ${error}`);
            return false;
        }
    }

    private async proxyToWebhook(
        clientIp: string,
        webhookUrl: string,
        req: Request,
        res: Response,
    ): Promise<boolean> {
        try {
            // Build headers to forward to the webhook
            // Pass through client headers that are relevant for the webhook
            const forwardHeaders: Record<string, string> = {};

            const headersToForward = [
                'user-agent',
                'accept',
                'accept-language',
                'accept-encoding',
                'if-none-match',
                'x-device-os',
                'x-hwid',
                'x-device-locale',
                'x-ver-os',
                'x-app-version',
                'x-device-model',
                'priority',
            ];

            for (const headerName of headersToForward) {
                const value = req.headers[headerName];
                if (value) {
                    forwardHeaders[headerName] = Array.isArray(value) ? value.join(', ') : value;
                }
            }

            // Pass the real client IP so the webhook sees the actual user IP
            forwardHeaders['x-real-ip'] = clientIp;
            forwardHeaders['x-forwarded-for'] = clientIp;
            forwardHeaders['x-forwarded-proto'] = 'https';

            this.logger.debug(
                `Proxying to webhook: ${webhookUrl} with client IP: ${clientIp}`,
            );

            const webhookResponse = await axios.get(webhookUrl, {
                headers: forwardHeaders,
                timeout: 15_000,
                // Return raw response data as string (subscription configs)
                transformResponse: [(data: unknown) => data],
                validateStatus: () => true,
            });

            // Forward response headers from webhook to the client
            if (webhookResponse.headers) {
                Object.entries(webhookResponse.headers)
                    .filter(([key]) => !IGNORED_HEADERS.has(key.toLowerCase()))
                    .forEach(([key, value]) => {
                        if (value !== undefined) {
                            res.setHeader(key, value as string);
                        }
                    });
            }

            res.status(webhookResponse.status).send(webhookResponse.data);
            return true;
        } catch (error) {
            this.logger.error(`Error proxying to webhook ${webhookUrl}: ${error}`);
            return false;
        }
    }
}
