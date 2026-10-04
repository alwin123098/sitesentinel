# Optional AI defensive triage

SiteSentinel can send a minimal security-event summary to one selected provider: OpenAI/ChatGPT, Gemini, Sarvam, xAI/Grok, or Groq. The advisor is scoped to the application instance where you install it. It does not crawl/probe targets or control allow/block decisions.

## Configure one provider

Set these only on the protected server, preferably through your hosting provider's secret manager:

```sh
SENTINEL_AI_PROVIDER=gemini
GEMINI_API_KEY=your-key
SENTINEL_AI_SCOPE=storefront-production
# Optional: SENTINEL_AI_MODEL=gemini-3.8-flash
```

Provider names and server-side key variables:

| Provider selector | API key environment variable | Default model |
|---|---|---|
| openai or chatgpt | OPENAI_API_KEY or CHATGPT_API_KEY | gpt-5.2 |
| gemini | GEMINI_API_KEY or GOOGLE_GEMINI_API_KEY | gemini-3.8-flash |
| sarvam | SARVAM_API_KEY or SARVAM_API_SUBSCRIPTION_KEY | sarvam-105b |
| grok | XAI_API_KEY or GROK_API_KEY | grok-4.7 |
| groq | GROQ_API_KEY | openai/gpt-oss-120b |

For backward compatibility, SENTINEL_AI_API_KEY works with whichever provider is selected. SENTINEL_AI_MODEL overrides that provider's default. You can also pass { provider, apiKey, model, scope } directly to createAIAdvisor(options), but do so only in server-side code. Never put keys in browser JavaScript, public config files, source control, or logs. This module currently supports these providers' text chat APIs; it does not accept arbitrary API formats.

## Attach the advisor

```js
const { createSentinel } = require("./server.js");
const { createAIAdvisor } = require("./ai-defense.js");

const sentinel = createSentinel();
const advise = createAIAdvisor(); // reads provider and secret from server environment

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

The advisor sends only an application scope label, a bounded event kind/verdict, and signature identifiers. It excludes raw request bodies, URLs, query strings, headers, cookies, credentials, and client IP addresses. The selected AI provider receives this event metadata; review its retention and data-processing terms before enabling it. Calls run in the asynchronous alert listener and do not gate requests.

AI output is untrusted advice. Escape it before rendering, review recommendations before applying them, and keep deterministic SiteSentinel rules in charge of enforcement. The advisor does not run commands, scan targets, or alter blocks. Keep API keys server-side: the current dashboard has no authentication and must not collect/store user keys.
