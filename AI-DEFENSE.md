# Optional AI defensive triage

SiteSentinel can send a minimal security-event summary to an OpenAI-compatible chat-completions API. This feature is an advisory helper for the application instance where you install it. It does not crawl or probe domains, expand your authorized scope, or control allow/block decisions.

## Configure a provider

Set credentials on the protected server, never in browser JavaScript or a public dashboard:

```sh
SENTINEL_AI_API_KEY=your-provider-key
SENTINEL_AI_MODEL=your-provider-model
SENTINEL_AI_BASE_URL=https://api.openai.com/v1
SENTINEL_AI_SCOPE=storefront-production
```

The base URL must be HTTPS in production and must implement the OpenAI-compatible /chat/completions API. Other API formats need a reviewed adapter. Keep secrets in your deployment secret manager or environment; do not commit them to config.json, source control, logs, or client bundles.

## Attach the advisor

```js
const { createSentinel } = require("./server.js");
const { createAIAdvisor } = require("./ai-defense.js");

const sentinel = createSentinel();
const advise = createAIAdvisor(); // reads server-side environment variables

sentinel.onAlert(async alert => {
  try {
    const advice = await advise(alert);
    // Store/display as untrusted advisory text after HTML escaping.
    await saveSecurityAdvice({ eventId: alert.id, advice });
  } catch (err) {
    // Provider errors must not affect request handling or blocking.
    logProviderFailure(err.message);
  }
});
```

## Data and safety

The adapter sends only an application scope label, a small event kind/verdict, and bounded signature identifiers. It excludes raw request bodies, URLs, query strings, headers, cookies, credentials, and client IP addresses. The configured provider still receives event metadata; review its retention and data-processing terms before enabling it. Calls are asynchronous in the alert listener and do not gate requests.

AI output is untrusted advice. Escape it before rendering, review actions before applying them, and keep deterministic SiteSentinel rules in charge of enforcement. This adapter does not automatically run commands, scan targets, or alter blocks. API keys are server-side only; the current dashboard has no authentication and must not be used to collect/store user keys.
