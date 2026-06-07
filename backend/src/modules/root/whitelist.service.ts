import { Request, Response } from 'express';

import { Injectable, Logger } from '@nestjs/common';

import axios from 'axios';

import { PgService } from '@common/pg/pg.service';
import { IGNORED_HEADERS } from '@common/constants/index';

interface ICachedWebhookResponse {
    status: number;
    headers: Record<string, string>;
    data: unknown;
    cachedAt: number;
}

const CACHE_TTL_MS = 60_000; // 60 seconds

@Injectable()
export class WhitelistService {
    private readonly logger = new Logger(WhitelistService.name);
    private readonly webhookCache = new Map<string, ICachedWebhookResponse>();
    // Tracks in-flight webhook requests so concurrent requests wait for the same response
    private readonly pendingRequests = new Map<string, Promise<ICachedWebhookResponse | null>>();

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

            // 1. Check cache — serve instantly if fresh
            const cached = this.webhookCache.get(shortUuid);
            if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
                this.logger.debug(
                    `Serving cached whitelist response for rmw_uuid=${shortUuid} (age: ${Math.round((Date.now() - cached.cachedAt) / 1000)}s)`,
                );
                this.sendCachedResponse(cached, res);
                return true;
            }

            // 2. Check if another request is already fetching from webhook — wait for it
            const pending = this.pendingRequests.get(shortUuid);
            if (pending) {
                this.logger.debug(
                    `Waiting for in-flight webhook request for rmw_uuid=${shortUuid}`,
                );
                const result = await pending;
                if (result) {
                    this.sendCachedResponse(result, res);
                    return true;
                }
                return false;
            }

            // 3. First request — fetch from webhook and let others wait
            this.logger.log(
                `Whitelist active for rmw_uuid=${shortUuid}, proxying to webhook`,
            );

            const webhookPromise = this.fetchFromWebhook(
                clientIp,
                shortUuid,
                vpnUser.whitelistSubscription,
                req,
            );
            this.pendingRequests.set(shortUuid, webhookPromise);

            try {
                const result = await webhookPromise;
                if (result) {
                    this.sendCachedResponse(result, res);
                    return true;
                }
                return false;
            } finally {
                this.pendingRequests.delete(shortUuid);
            }
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

    private sendCachedResponse(cached: ICachedWebhookResponse, res: Response): void {
        Object.entries(cached.headers).forEach(([key, value]) => {
            res.setHeader(key, value);
        });
        res.status(cached.status).send(cached.data);
    }

    /**
     * Fetches the webhook response, caches it, and returns the cached object.
     * Does NOT send the response to `res` — the caller does that.
     */
    private async fetchFromWebhook(
        clientIp: string,
        shortUuid: string,
        webhookUrl: string,
        req: Request,
    ): Promise<ICachedWebhookResponse | null> {
        try {
            const excludedHeaders = new Set([
                'host',
                'connection',
                'authorization',
                'content-length',
                'transfer-encoding',
                'keep-alive',
                'upgrade',
                'trailer',
                'te',
                'proxy-authorization',
                'proxy-authenticate',
            ]);

            const forwardHeaders: Record<string, string> = {};

            for (const [key, value] of Object.entries(req.headers)) {
                if (value && !excludedHeaders.has(key.toLowerCase())) {
                    forwardHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
                }
            }

            forwardHeaders['x-real-ip'] = clientIp;
            forwardHeaders['x-forwarded-for'] = clientIp;
            forwardHeaders['x-forwarded-proto'] = 'https';

            this.logger.debug(
                `Proxying to webhook: ${webhookUrl} with client IP: ${clientIp}`,
            );

            const webhookResponse = await axios.get(webhookUrl, {
                headers: forwardHeaders,
                timeout: 15_000,
                transformResponse: [(data: unknown) => data],
                validateStatus: () => true,
            });

            const responseHeaders: Record<string, string> = {};
            if (webhookResponse.headers) {
                Object.entries(webhookResponse.headers)
                    .filter(([key]) => !IGNORED_HEADERS.has(key.toLowerCase()))
                    .forEach(([key, value]) => {
                        if (value !== undefined) {
                            responseHeaders[key] = value as string;
                        }
                    });
            }

            const cachedResponse: ICachedWebhookResponse = {
                status: webhookResponse.status,
                headers: responseHeaders,
                data: webhookResponse.data,
                cachedAt: Date.now(),
            };

            // Store in cache
            this.webhookCache.set(shortUuid, cachedResponse);

            return cachedResponse;
        } catch (error) {
            this.logger.error(`Error proxying to webhook ${webhookUrl}: ${error}`);
            return null;
        }
    }
}
