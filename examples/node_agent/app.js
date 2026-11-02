// A tiny "agent" that calls an LLM gateway. The gateway rejects the key and echoes it in its error,
// and the app records that error on its span, so the key ships to the telemetry backend.
// OpenTelemetry is configured only from the standard OTEL_* env vars, like most real apps.
const { NodeSDK } = require("@opentelemetry/sdk-node");
const { trace, SpanStatusCode } = require("@opentelemetry/api");

const sdk = new NodeSDK({ serviceName: "node-agent" });
sdk.start();
const tracer = trace.getTracer("node-agent");

async function callLlm(prompt) {
  const key = process.env.OPENAI_API_KEY;
  throw new Error(`401 from gateway: invalid api key ${key}`);
}

async function main() {
  await tracer.startActiveSpan("llm.call", async (span) => {
    try {
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
