import crypto, { KeyPairKeyObjectResult } from 'node:crypto';
import querystring from 'node:querystring';

import axios from 'axios';
import { exportJWK, JWK } from 'jose';
import { SmartBuffer } from 'smart-buffer';

import type { TokenOptions } from '@/structs/MicrosoftAuth';
import { getMatchForIndex } from '@/util/regex';

export type XboxTokenOptions = TokenOptions;

export interface PreAuthResponse {
	cookie: string;
	ppft: string;
	url: string;
}

export interface LogUserCredentials {
	username: string;
	password: string;
}

export interface LogUserResponse {
	access_token: string;
	token_type: string;
	expires_in: number;
	scope: string;
	refresh_token: string;
	user_id: string;
}

export interface ExchangeRpsTicketResponse {
	IssueInstant: string;
	NotAfter: string;
	Token: string;
	DisplayClaims: {
		xui: [{
			uhs: string;
		}];
	};
}

export interface XstsResponse {
	userXuid: string | null;
	userHash: string;
	xstsToken: string;
	expiresOn: Date;
}

export class XboxManager {
	private key: KeyPairKeyObjectResult;
	private jwk!: JWK;
	private ready = false;

	constructor() {
		this.key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
	}

	private async preAuth(options?: XboxTokenOptions): Promise<PreAuthResponse> {
		const response = await axios.get('https://login.live.com/oauth20_authorize.srf', {
			...options?.axiosOptions,
			params: {
				client_id: '000000004C12AE6F',
				redirect_uri: 'https://login.live.com/oauth20_desktop.srf',
				scope: 'service::user.auth.xboxlive.com::MBI_SSL',
				display: 'touch',
				response_type: 'token',
				locale: 'en',
			},
			headers: {
				'Accept-Encoding': 'gzip',
				'Accept-Language': 'en-US',
				'User-Agent': 'Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
			},
		});

		return {
			cookie: (response.headers['set-cookie'] ?? [])
				.map(c => c.split(';')[0])
				.join('; '),
			ppft: getMatchForIndex(response.data, /sFTTag:'.*value="(.*)"\/>'/, 1)!,
			url: getMatchForIndex(response.data, /urlPost:'(.+?(?='))/, 1)!,
		};
	}

	private async logUser(auth: PreAuthResponse, credentials: LogUserCredentials, options?: XboxTokenOptions): Promise<LogUserResponse> {
		const response = await axios.post(auth.url, querystring.stringify({
			login: credentials.username,
			loginfmt: credentials.username,
			passwd: credentials.password,
			PPFT: auth.ppft,
		}), {
			...options?.axiosOptions,
			headers: {
				'Accept-Encoding': 'gzip',
				'Accept-Language': 'en-US',
				'User-Agent': 'Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
				'Content-Type': 'application/x-www-form-urlencoded',
				Cookie: auth.cookie,
			},
		});

		const parsed: LogUserResponse = querystring
			.parse(response.request.res.responseUrl.split('#')[1]) as unknown as LogUserResponse;

		parsed.expires_in = parseInt(parsed.expires_in as unknown as string);

		return parsed;
	}

	private async exchangeRpsTicketForUserToken(ticket: LogUserResponse, options?: XboxTokenOptions): Promise<ExchangeRpsTicketResponse> {
		const response = await axios.post('https://user.auth.xboxlive.com/user/authenticate', {
			RelyingParty: 'http://auth.xboxlive.com',
			TokenType: 'JWT',
			Properties: {
				AuthMethod: 'RPS',
				SiteName: 'user.auth.xboxlive.com',
				RpsTicket: ticket.access_token,
			},
		}, {
			...options?.axiosOptions,
			headers: {
				'Accept-encoding': 'gzip',
				'Accept-Language': 'en-US',
				'User-Agent': 'Mozilla/5.0 (XboxReplay; XboxLiveAuth/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
				Accept: 'application/json',
				'x-xbl-contract-version': 0,
			},
		});

		return response.data;
	}

	// https://github.com/PrismarineJS/prismarine-auth
	private sign(url: string, authorizationToken: string, payload: string) {
		const windowsTimestamp = (BigInt((Date.now() / 1000) | 0) + 11644473600n) * 10000000n;
		const pathAndQuery = new URL(url).pathname;

		const allocSize = /* sig */ 5 + /* ts */ 9 + /* POST */ 5 + pathAndQuery.length + 1 + authorizationToken.length + 1 + payload.length + 1;
		const buf = SmartBuffer.fromSize(allocSize);

		buf.writeInt32BE(1);
		buf.writeUInt8(0);
		buf.writeBigUInt64BE(windowsTimestamp);
		buf.writeUInt8(0);
		buf.writeStringNT('POST');
		buf.writeStringNT(pathAndQuery);
		buf.writeStringNT(authorizationToken);
		buf.writeStringNT(payload);

		const signature = crypto.sign('SHA256', buf.toBuffer(), { key: this.key.privateKey, dsaEncoding: 'ieee-p1363' });
		const header = SmartBuffer.fromSize(signature.length + 12);

		header.writeInt32BE(1);
		header.writeBigUInt64BE(windowsTimestamp);
		header.writeBuffer(signature);

		return header.toBuffer();
	}

	public async init() {
		if (this.ready) return;

		this.jwk = await exportJWK(this.key.publicKey);
		this.jwk.alg = 'ES256';
		this.jwk.use = 'sig';

		this.ready = true;
	}

	public async getXstsToken(credentials: LogUserCredentials, options?: XboxTokenOptions): Promise<XstsResponse> {
		await this.init();

		const preAuth = await this.preAuth(options);
		const logUser = await this.logUser(preAuth, credentials, options);
		const xboxUserToken = await this.exchangeRpsTicketForUserToken(logUser, options);

		const payload = JSON.stringify({
			RelyingParty: 'rp://api.minecraftservices.com/',
			TokenType: 'JWT',
			Properties: {
				UserTokens: [
					xboxUserToken.Token,
				],
				ProofKey: this.jwk,
				SandboxId: 'RETAIL',
			},
		});

		const signature = this.sign('https://xsts.auth.xboxlive.com/xsts/authorize', '', payload).toString('base64');
		const xstsResponse = await axios.post('https://xsts.auth.xboxlive.com/xsts/authorize', payload, {
			...options?.axiosOptions,
			headers: {
				'Cache-Control': 'no-store, must-revalidate, no-cache',
				'x-xbl-contract-version': 1,
				Signature: signature,
			},
		});

		return {
			userXuid: xstsResponse.data.DisplayClaims.xui[0].xid || null,
			userHash: xstsResponse.data.DisplayClaims.xui[0].uhs,
			xstsToken: xstsResponse.data.Token,
			expiresOn: new Date(xstsResponse.data.NotAfter),
		};
	}
}
