import axios, { AxiosRequestConfig } from 'axios';

import { XboxManager, XboxTokenOptions } from '@/managers/XboxManager';

export interface TokenOptions {
	axiosOptions: Pick<AxiosRequestConfig, 'httpsAgent'>;
}

export type JavaTokenOptions = TokenOptions;

export interface JavaToken {
	token: string;
	expiresAt: Date;
}

export class MicrosoftAuth {
	private username: string;
	private password: string;
	private xbox: XboxManager;

	constructor(username: string, password: string) {
		this.username = username;
		this.password = password;

		this.xbox = new XboxManager();
	}

	private async getXboxToken(options?: XboxTokenOptions) {
		return this.xbox.getXstsToken({
			username: this.username,
			password: this.password,
		}, options);
	}

	public async getJavaToken(options?: JavaTokenOptions): Promise<JavaToken> {
		const xsts = await this.getXboxToken(options);
		const response = await axios.post('https://api.minecraftservices.com/authentication/login_with_xbox', {
			identityToken: `XBL3.0 x=${xsts.userHash};${xsts.xstsToken}`,
		}, {
			...options?.axiosOptions,
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': 'MinecraftLauncher/2.2.10675',
			},
		});

		console.log(response.data);

		return {
			token: response.data.access_token,
			expiresAt: new Date(Date.now() + response.data.expires_in * 1_000),
		};
	}
}
