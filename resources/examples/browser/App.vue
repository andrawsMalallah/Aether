<script setup>
import { onMounted, ref } from "vue";
import { createAuthClient } from "./auth.js";
import "./example.css";

const auth = createAuthClient({
    issuer: import.meta.env.VITE_AETHER_ISSUER,
    clientId: import.meta.env.VITE_AETHER_CLIENT_ID,
});
const session = ref(auth.snapshot());
const busy = ref(true);

async function run(action) {
    if (busy.value) return;
    busy.value = true;
    try {
        await action();
    } finally {
        session.value = auth.snapshot();
        busy.value = false;
    }
}

onMounted(async () => {
    try {
        await auth.initialize();
    } finally {
        session.value = auth.snapshot();
        busy.value = false;
    }
});
</script>

<template>
    <main class="aether-example" :aria-busy="busy">
        <h1>Sign in with Aether</h1>
        <p v-if="session.message" role="status">{{ session.message }}</p>
        <p v-if="busy" role="status">Please wait…</p>
        <template v-if="session.profile">
            <h2>{{ session.profile.name }}</h2>
            <dl>
                <dt>Email</dt>
                <dd>{{ session.profile.email }}</dd>
                <dt>Email verified</dt>
                <dd>{{ session.profile.emailVerified ? "Yes" : "No" }}</dd>
                <dt>Issuer</dt>
                <dd>{{ session.profile.issuer }}</dd>
                <dt>Subject</dt>
                <dd>{{ session.profile.subject }}</dd>
            </dl>
            <div class="aether-example-actions">
                <button :disabled="busy" @click="run(auth.refreshSession)">
                    Refresh session
                </button>
                <button :disabled="busy" @click="run(auth.signOut)">
                    Sign out of this app
                </button>
            </div>
        </template>
        <button v-else :disabled="busy" @click="run(auth.signIn)">
            Sign in with Aether
        </button>
    </main>
</template>
