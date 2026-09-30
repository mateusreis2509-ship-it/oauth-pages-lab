export function getProviderConfig(provider, env) {
    if (provider === "google") {
        return {
            clientId: env.GOOGLE_CLIENT_ID,
            clientSecret: env.GOOGLE_CLIENT_SECRET,
            redirectUri: `${env.PUBLIC_BASE_URL}/oauth/callback/google`,
            tokenUrl: "https://oauth2.googleapis.com/token",
        };
    }

    if (provider === "github") {
        return {
            clientId: env.GITHUB_CLIENT_ID,
            clientSecret: env.GITHUB_CLIENT_SECRET,
            redirectUri: `${env.PUBLIC_BASE_URL}/oauth/callback/github`,
            tokenUrl: "https://github.com/login/oauth/access_token",
        };
    }

    return null;
}
