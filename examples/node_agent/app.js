// A tiny "agent" that calls an LLM gateway. The gateway rejects the key and echoes it in its error,
// and the app records that error on its span, so the key ships to the telemetry backend.
// OpenTelemetry is configured only from the standard OTEL_* env vars, like most real apps.
//
// `node app.js --proof` also leaks the key through every other channel a redactor must cover:
// a span attribute, a URL query parameter, a log record (body and attribute) and a metric attribute.
const { NodeSDK } = require("@opentelemetry/sdk-node");
const { trace, metrics, logs, SpanStatusCode } = require("@opentelemetry/api");

const proof = process.argv.includes("--proof");
const sdk = new NodeSDK({ serviceName: "node-agent" });
sdk.start();
const tracer = trace.getTracer("node-agent");

async function callLlm(prompt) {
  const key = process.env.OPENAI_API_KEY;
  throw new Error(`401 from gateway: invalid api key ${key}`);
}

function leakEverywhere(span, key) {
  span.setAttribute("llm.prompt", `use this key: ${key}`);
  span.setAttribute("http.url", `https://gateway.example/v1/chat?key=${key}&model=gpt`);
  logs.getLogger("node-agent").emit({
    body: `calling gateway with ${key}`,
    attributes: { "request.auth": `Bearer ${key}` },
  });
  metrics.getMeter("node-agent").createCounter("llm.calls").add(1, { "llm.key": key });
}

async function main() {
  await tracer.startActiveSpan("llm.call", async (span) => {
    try {
      if (proof) leakEverywhere(span, process.env.OPENAI_API_KEY);
      await callLlm("summarize this");
    } catch (err) {
      span.recordException(err);
      span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
    } finally {
      span.end();
    }
  });
  // Without this, Node exits before the batch is exported and nothing reaches the backend.
  await sdk.shutdown();
}

main();
