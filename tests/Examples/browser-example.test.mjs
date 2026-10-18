import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

// The provider does not depend on a browser SDK. Substitute that import only;
// every test executes the actual module shown in the portal with an injected protocol.
const source = await readFile(
    new URL("../../resources/examples/browser/auth.js", import.meta.url),
    "utf8",
);
const sdkImport = /^import \* as openid from ["']openid-client["'];/;
assert.match(source, sdkImport);
const { createAuthClient } = await import(
    "data:text/javascript," +
        encodeURIComponent(source.replace(sdkImport, "const openid = {};"))
);

function fixture() {
    const saved = new Map();
    const calls = { grants: [], refreshes: [], revocations: [], events: [] };
    let callback = new URL("http://localhost:5173/");
    let destination;
    let sequence = 0;
    let configurationOptions;
    const claims = { sub: "example-subject", nonce: "nonce", auth_time: 100 };
    const token = (suffix = "") => ({
        access_token: "fixture-access" + suffix,
        refresh_token: "fixture-refresh" + suffix,
        id_token: "fixture-id" + suffix,
        claims: () => ({ ...claims }),
    });
    const protocol = {
        customFetch: Symbol("customFetch"),
        None: () => "none",
        enableNonRepudiationChecks: () => {},
        discovery: async (issuer, clientId, metadata, method, options) => {
            assert.equal(issuer.href, "https://identity.example/");
            assert.equal(clientId, "public-example");
            assert.equal(method, "none");
            assert.equal(metadata.id_token_signed_response_alg, "RS256");
            configurationOptions = options;
            return {};
        },
        randomPKCECodeVerifier: () => "fixture-verifier-" + ++sequence,
        randomState: () => "fixture-state-" + sequence,
        randomNonce: () => "nonce",
        calculatePKCECodeChallenge: async () => "fixture-library-challenge",
        buildAuthorizationUrl: (config, parameters) =>
            new URL(
                "https://identity.example/authorize?" +
                    new URLSearchParams(parameters),
            ),
        authorizationCodeGrant: async (config, url, checks) => {
            calls.events.push("grant");
            calls.grants.push(checks);
            assert.equal(saved.size, 0);
            assert.equal(callback.search, "");
            return token();
        },
        refreshTokenGrant: async (config, refreshToken) => {
            calls.refreshes.push(refreshToken);
            return token("-next");
        },
        fetchUserInfo: async () => ({
            sub: claims.sub,
            name: "Example User",
            email: "example@example.test",
            email_verified: true,
        }),
        tokenRevocation: async (config, credential) => {
            calls.revocations.push(credential);
        },
    };
    const storage = {
        getItem: (key) => saved.get(key) ?? null,
        setItem: (key, value) => saved.set(key, value),
        removeItem: (key) => saved.delete(key),
    };
    const options = {
        issuer: "https://identity.example",
        clientId: "public-example",
        origin: "http://localhost:5173",
        storage,
        protocol,
        clock: () => 1_000_000,
        currentUrl: () => callback,
        navigate: (url) => {
            destination = new URL(url);
        },
        clearCallback: () => {
            calls.events.push("clear");
            callback = new URL("http://localhost:5173/");
        },
    };
    const auth = createAuthClient(options);
    const setCallback = (query) => {
        callback = new URL(
            "http://localhost:5173/auth/callback?" +
                (query ??
                    "code=fixture-code&state=" +
                        destination.searchParams.get("state")),
        );
    };
    return {
        auth,
        saved,
        calls,
        protocol,
        storage,
        options,
        token,
        claims,
        setCallback,
        get destination() {
            return destination;
        },
        get configurationOptions() {
            return configurationOptions;
        },
    };
}

async function signedIn() {
    const fixtureData = fixture();
    await fixtureData.auth.signIn();
    fixtureData.setCallback();
    await fixtureData.auth.initialize();
    assert.ok(fixtureData.auth.snapshot().profile);
    return fixtureData;
}

test("uses public S256 state and nonce transactions with fresh verifiers and no persisted tokens", async () => {
    const fixtureData = fixture();
    await fixtureData.auth.signIn();
    const first = [...fixtureData.saved.values()][0];
    assert.equal(
        fixtureData.destination.searchParams.get("code_challenge_method"),
        "S256",
    );
    assert.equal(
        fixtureData.destination.searchParams.get("scope"),
        "openid profile email",
    );
    assert.equal(
        fixtureData.destination.searchParams.get("redirect_uri"),
        "http://localhost:5173/auth/callback",
    );
    assert.equal(
        fixtureData.destination.searchParams.has("client_secret"),
        false,
    );
    assert.equal(
        fixtureData.destination.searchParams.has("code_verifier"),
        false,
    );
    await fixtureData.auth.signIn();
    assert.notEqual([...fixtureData.saved.values()][0], first);
    assert.doesNotMatch(
        [...fixtureData.saved.values()].join(""),
        /fixture-access|fixture-refresh|fixture-id/,
    );
});

test("clears callback before exchanging, consumes transactions and exposes only safe profile fields", async () => {
    const fixtureData = await signedIn();
    assert.deepEqual(fixtureData.calls.events, ["clear", "grant"]);
    assert.equal(fixtureData.calls.grants[0].idTokenExpected, true);
    assert.equal(fixtureData.calls.grants[0].expectedNonce, "nonce");
    assert.equal(
        fixtureData.auth.snapshot().profile.issuer,
        "https://identity.example",
    );
    assert.equal(
        fixtureData.auth.snapshot().profile.subject,
        "example-subject",
    );
    assert.doesNotMatch(
        JSON.stringify(fixtureData.auth.snapshot()),
        /fixture-access|fixture-refresh|fixture-id/,
    );
    fixtureData.setCallback();
    await fixtureData.auth.initialize();
    assert.equal(fixtureData.calls.grants.length, 1);
    assert.equal(fixtureData.auth.snapshot().profile, null);
});

for (const query of [
    "code=fixture-code",
    "code=fixture-code&state=wrong",
    "code=fixture-code&state=fixture-state-1&state=fixture-state-1",
]) {
    test(
        "rejects missing mismatched or duplicated state: " + query,
        async () => {
            const fixtureData = fixture();
            await fixtureData.auth.signIn();
            fixtureData.setCallback(query);
            await fixtureData.auth.initialize();
            assert.equal(fixtureData.calls.grants.length, 0);
            assert.equal(fixtureData.saved.size, 0);
        },
    );
}

for (const kind of ["expired", "future", "malformed", "other-origin"]) {
    test("rejects unusable login attempt: " + kind, async () => {
        const fixtureData = fixture();
        await fixtureData.auth.signIn();
        const key = [...fixtureData.saved.keys()][0];
        const attempt = JSON.parse(fixtureData.saved.get(key));
        if (kind === "expired") attempt.createdAt = 0;
        if (kind === "future") attempt.createdAt = 1_000_001;
        if (kind === "other-origin")
            attempt.origin = "https://unexpected.example";
        fixtureData.saved.set(
            key,
            kind === "malformed" ? "not-json" : JSON.stringify(attempt),
        );
        fixtureData.setCallback();
        await fixtureData.auth.initialize();
        assert.equal(fixtureData.calls.grants.length, 0);
        assert.equal(fixtureData.auth.snapshot().profile, null);
    });
}

test("recognizes consent denial only after checking its state", async () => {
    const fixtureData = fixture();
    await fixtureData.auth.signIn();
    fixtureData.setCallback("error=access_denied&state=fixture-state-1");
    await fixtureData.auth.initialize();
    assert.match(fixtureData.auth.snapshot().message, /cancelled/);
    await fixtureData.auth.signIn();
    fixtureData.setCallback("error=access_denied&state=wrong");
    await fixtureData.auth.initialize();
    assert.doesNotMatch(fixtureData.auth.snapshot().message, /cancelled/);
    assert.equal(fixtureData.calls.grants.length, 0);
});

test("serializes refresh and replaces the refresh token for the next request", async () => {
    const fixtureData = await signedIn();
    let finish;
    fixtureData.protocol.refreshTokenGrant = async (config, refreshToken) => {
        fixtureData.calls.refreshes.push(refreshToken);
        return new Promise((resolve) => {
            finish = resolve;
        });
    };
    const first = fixtureData.auth.refreshSession();
    const second = fixtureData.auth.refreshSession();
    await new Promise(setImmediate);
    assert.equal(fixtureData.calls.refreshes.length, 1);
    finish(fixtureData.token("-replacement"));
    await Promise.all([first, second]);
    fixtureData.protocol.refreshTokenGrant = async (config, refreshToken) => {
        assert.equal(refreshToken, "fixture-refresh-replacement");
        return fixtureData.token("-next");
    };
    await fixtureData.auth.refreshSession();
});

test("rejects changed refresh identity and cleans replacement credentials", async () => {
    const fixtureData = await signedIn();
    fixtureData.protocol.refreshTokenGrant = async () => ({
        ...fixtureData.token("-bad"),
        claims: () => ({ ...fixtureData.claims, sub: "other-person" }),
    });
    await fixtureData.auth.refreshSession();
    assert.equal(fixtureData.auth.snapshot().profile, null);
    assert.deepEqual(fixtureData.calls.revocations, [
        "fixture-refresh-bad",
        "fixture-access-bad",
    ]);
});

test("rejects a different UserInfo subject and revokes issued credentials", async () => {
    const fixtureData = fixture();
    fixtureData.protocol.fetchUserInfo = async () => ({
        sub: "unexpected-person",
    });
    await fixtureData.auth.signIn();
    fixtureData.setCallback();
    await fixtureData.auth.initialize();
    assert.equal(fixtureData.auth.snapshot().profile, null);
    assert.equal(fixtureData.calls.revocations.length, 2);
});

test("clears local identity even if both logout revocations fail, without echoing exceptions", async () => {
    const fixtureData = await signedIn();
    let attempts = 0;
    fixtureData.protocol.tokenRevocation = async () => {
        attempts++;
        throw new Error("private transport context");
    };
    await fixtureData.auth.signOut();
    assert.equal(attempts, 2);
    assert.equal(fixtureData.auth.snapshot().profile, null);
    assert.match(fixtureData.auth.snapshot().message, /could not be confirmed/);
    assert.doesNotMatch(
        fixtureData.auth.snapshot().message,
        /private transport/,
    );
});

test("reload starts with no identity and unavailable storage does not navigate", async () => {
    const fixtureData = await signedIn();
    assert.equal(
        createAuthClient(fixtureData.options).snapshot().profile,
        null,
    );
    fixtureData.storage.removeItem = () => {
        throw new Error("private storage context");
    };
    await fixtureData.auth.signIn();
    assert.doesNotMatch(fixtureData.auth.snapshot().message, /private storage/);
});

test("uses credential-free nonredirecting fetch for library requests", async () => {
    const fixtureData = fixture();
    await fixtureData.auth.signIn();
    const previousFetch = globalThis.fetch;
    globalThis.fetch = async (input, options) => {
        assert.equal(options.credentials, "omit");
        assert.equal(options.redirect, "error");
        assert.equal(options.referrerPolicy, "no-referrer");
        return new Response("{}");
    };
    try {
        await fixtureData.configurationOptions[
            fixtureData.protocol.customFetch
        ]("https://identity.example/token", {});
    } finally {
        globalThis.fetch = previousFetch;
    }
});
