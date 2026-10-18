import * as openid from "openid-client";

const transactionKey = "aether.example.login-attempt";
const transactionLifetime = 10 * 60 * 1000;
const callbackPath = "/auth/callback";

export function createAuthClient({
    issuer,
    clientId,
    origin = window.location.origin,
    storage = {
        getItem: (key) => window.sessionStorage.getItem(key),
        setItem: (key, value) => window.sessionStorage.setItem(key, value),
        removeItem: (key) => window.sessionStorage.removeItem(key),
    },
    currentUrl = () => new URL(window.location.href),
    navigate = (url) => window.location.assign(url),
    clearCallback = () => window.history.replaceState(null, "", "/"),
    clock = () => Date.now(),
    protocol = openid,
} = {}) {
    // Tokens and validation context stay in this closure, never Vue state or Web Storage.
    let credentials = null;
    let profile = null;
    let identity = null;
    let configuration;
    let pendingOperation = false;
    let message = "";

    function snapshot() {
        return { profile: profile ? { ...profile } : null, message };
    }

    function forgetIdentity() {
        credentials = null;
        profile = null;
        identity = null;
    }

    async function configured() {
        if (!configuration) {
            const issuerUrl = new URL(issuer);
            if (
                issuerUrl.protocol !== "https:" ||
                issuerUrl.search ||
                issuerUrl.hash ||
                issuerUrl.username ||
                issuerUrl.password ||
                !clientId
            ) {
                throw new Error("Invalid public configuration");
            }
            configuration = await protocol.discovery(
                issuerUrl,
                clientId,
                { id_token_signed_response_alg: "RS256" },
                protocol.None(),
                {
                    execute: [protocol.enableNonRepudiationChecks],
                    timeout: 8,
                    [protocol.customFetch]: (input, options) =>
                        fetch(input, {
                            ...options,
                            credentials: "omit",
                            redirect: "error",
                            referrerPolicy: "no-referrer",
                        }),
                },
            );
        }
        return configuration;
    }

    async function revoke(tokens) {
        if (!tokens) return true;
        let completed = true;
        // Revoke both independently: a failed refresh revocation must not skip access cleanup.
        for (const [token, hint] of [
            [tokens.refresh_token, "refresh_token"],
            [tokens.access_token, "access_token"],
        ]) {
            if (!token) continue;
            try {
                await protocol.tokenRevocation(await configured(), token, {
                    token_type_hint: hint,
                });
            } catch {
                completed = false;
            }
        }
        return completed;
    }

    async function accept(tokens, expectedIdentity = null) {
        const claims = tokens.claims();
        if (
            !claims ||
            typeof claims.sub !== "string" ||
            !claims.sub ||
            !tokens.id_token ||
            !tokens.access_token ||
            !tokens.refresh_token
        ) {
            throw new Error("Incomplete identity");
        }
        if (
            expectedIdentity &&
            (claims.sub !== expectedIdentity.sub ||
                claims.nonce !== expectedIdentity.nonce ||
                claims.auth_time !== expectedIdentity.authTime)
        ) {
            throw new Error("Changed identity");
        }
        const user = await protocol.fetchUserInfo(
            await configured(),
            tokens.access_token,
            claims.sub,
        );
        if (
            user.sub !== claims.sub ||
            typeof user.name !== "string" ||
            typeof user.email !== "string" ||
            typeof user.email_verified !== "boolean"
        ) {
            throw new Error("Incomplete profile");
        }
        const nextProfile = {
            issuer,
            subject: claims.sub,
            name: user.name,
            email: user.email,
            emailVerified: user.email_verified,
            refreshedAt: clock(),
        };
        identity = {
            sub: claims.sub,
            nonce: claims.nonce,
            authTime: claims.auth_time,
        };
        credentials = tokens;
        profile = nextProfile;
    }

    async function exclusive(action) {
        if (pendingOperation) return;
        pendingOperation = true;
        try {
            await action();
        } finally {
            pendingOperation = false;
        }
    }

    async function initialize() {
        const callback = currentUrl();
        if (callback.pathname !== callbackPath) return;
        // Scrub code/state before discovery, error rendering, or any other network activity.
        clearCallback();
        return exclusive(async () => {
            let received;
            try {
                const saved = storage.getItem(transactionKey);
                storage.removeItem(transactionKey);
                const attempt = JSON.parse(saved);
                if (
                    !attempt ||
                    typeof attempt.state !== "string" ||
                    typeof attempt.nonce !== "string" ||
                    typeof attempt.verifier !== "string" ||
                    !Number.isFinite(attempt.createdAt) ||
                    clock() - attempt.createdAt > transactionLifetime ||
                    clock() < attempt.createdAt ||
                    attempt.origin !== origin
                ) {
                    throw new Error("Invalid login attempt");
                }
                // Validate state even on denial, before accepting any callback outcome.
                if (
                    callback.origin !== origin ||
                    callback.searchParams.getAll("state").length !== 1 ||
                    callback.searchParams.get("state") !== attempt.state
                ) {
                    throw new Error("Invalid callback");
                }
                if (callback.searchParams.get("error") === "access_denied") {
                    message =
                        "Sign-in was cancelled. You can try again whenever you are ready.";
                    return;
                }
                received = await protocol.authorizationCodeGrant(
                    await configured(),
                    callback,
                    {
                        pkceCodeVerifier: attempt.verifier,
                        expectedState: attempt.state,
                        expectedNonce: attempt.nonce,
                        idTokenExpected: true,
                    },
                );
                await accept(received);
                message = "You are signed in to this app.";
            } catch {
                forgetIdentity();
                await revoke(received);
                message = "We could not complete sign-in. Please start again.";
            }
        });
    }

    async function signIn() {
        return exclusive(async () => {
            message = "";
            try {
                storage.removeItem(transactionKey);
                const config = await configured();
                const verifier = protocol.randomPKCECodeVerifier();
                const state = protocol.randomState();
                const nonce = protocol.randomNonce();
                const url = protocol.buildAuthorizationUrl(config, {
                    redirect_uri: new URL(callbackPath, origin).href,
                    scope: "openid profile email",
                    response_type: "code",
                    state,
                    nonce,
                    code_challenge:
                        await protocol.calculatePKCECodeChallenge(verifier),
                    code_challenge_method: "S256",
                });
                storage.setItem(
                    transactionKey,
                    JSON.stringify({
                        verifier,
                        state,
                        nonce,
                        createdAt: clock(),
                        origin,
                    }),
                );
                navigate(url.href);
            } catch {
                message =
                    "Aether is unavailable right now. Please try signing in again.";
            }
        });
    }

    async function refreshSession() {
        return exclusive(async () => {
            if (!credentials) return;
            const previous = credentials;
            let replacement;
            try {
                replacement = await protocol.refreshTokenGrant(
                    await configured(),
                    previous.refresh_token,
                );
                await accept(replacement, identity);
                message = "Your profile and session are up to date.";
            } catch {
                forgetIdentity();
                await revoke(replacement ?? previous);
                message =
                    "Your session could not be refreshed. Please sign in again.";
            }
        });
    }

    async function signOut() {
        return exclusive(async () => {
            const previous = credentials;
            forgetIdentity();
            try {
                storage.removeItem(transactionKey);
            } catch {
                /* Memory cleanup still succeeds if browser storage is unavailable. */
            }
            const completed = await revoke(previous);
            message = completed
                ? "You are signed out of this app. Your Aether session stays signed in."
                : "You are signed out of this app. Token cleanup could not be confirmed; your Aether session stays signed in.";
        });
    }

    return { snapshot, initialize, signIn, refreshSession, signOut };
}
