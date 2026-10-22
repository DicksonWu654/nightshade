import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

export interface ExecutionLimits {
  timeoutMs?: number;
  heapMiB?: number;
  maxOutputBytes?: number;
}

export const DEFAULT_EXECUTION_LIMITS: Required<ExecutionLimits> = { timeoutMs: 60000, heapMiB: 512, maxOutputBytes: 16 * 1024 * 1024 };

export function executionLimits(options: ExecutionLimits = {}): Required<ExecutionLimits> {
  if (!options || typeof options !== "object" || Array.isArray(options) || Object.keys(options).some(key => !(key in DEFAULT_EXECUTION_LIMITS))) throw new Error("Unknown execution limit");
  const limits = { ...DEFAULT_EXECUTION_LIMITS, ...options };
  for (const [key, minimum, maximum] of [["timeoutMs", 1, 600000], ["heapMiB", 32, 4096], ["maxOutputBytes", 1024, 64 * 1024 * 1024]] as const) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < minimum || limits[key] > maximum) throw new Error(`${key} must be an integer between ${minimum} and ${maximum}`);
  }
  return limits;
}

export class WorkerFailure extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

export async function runNodeModule(module: string, request: unknown, options: ExecutionLimits = {}, abortSignal?: AbortSignal): Promise<{ stdout: string; stderr: string }> {
  const limits = executionLimits(options);
  if (abortSignal !== undefined && !(abortSignal instanceof AbortSignal)) throw new Error("Invalid worker AbortSignal");
  const checkInterrupted = (): void => { if (abortSignal?.aborted) throw new WorkerFailure("worker-interrupted", "Analysis worker was interrupted; no complete report is available"); };
  checkInterrupted();
  const input = JSON.stringify(request);
  if (Buffer.byteLength(input) > 1024 * 1024) throw new WorkerFailure("worker-input-budget", "Worker request exceeds 1 MiB");
  checkInterrupted();
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-worker-"));
  try {
    return await new Promise((resolveResult, reject) => {
      const child = spawn(process.execPath, [`--max-old-space-size=${limits.heapMiB}`, module], { stdio: ["pipe", "pipe", "pipe"], detached: process.platform !== "win32", windowsHide: true, env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary } });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let bytes = 0;
      let failure: WorkerFailure | undefined;
      let finished = false;
      const stop = (error: WorkerFailure): void => {
        if (finished) return;
        failure ??= error;
        if (child.pid && process.platform !== "win32") {
          try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
        } else child.kill("SIGKILL");
      };
      const interrupted = (): void => stop(new WorkerFailure("worker-interrupted", "Analysis worker was interrupted; no complete report is available"));
      process.once("SIGINT", interrupted);
      process.once("SIGTERM", interrupted);
      abortSignal?.addEventListener("abort", interrupted, { once: true });
      const timer = setTimeout(() => stop(new WorkerFailure("worker-timeout", `Analysis worker exceeded ${limits.timeoutMs} ms; results are incomplete`)), limits.timeoutMs);
      const finish = (error?: Error): void => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        process.removeListener("SIGINT", interrupted);
        process.removeListener("SIGTERM", interrupted);
        abortSignal?.removeEventListener("abort", interrupted);
        if (failure ?? error) reject(failure ?? error);
        else resolveResult({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") });
      };
      const collect = (chunks: Buffer[], chunk: Buffer): void => {
        if (failure) return;
        bytes += chunk.length;
        if (bytes > limits.maxOutputBytes) stop(new WorkerFailure("worker-output-budget", `Analysis worker output exceeded ${limits.maxOutputBytes} bytes; results are incomplete`));
        else chunks.push(chunk);
      };
      child.stdout.on("data", chunk => collect(stdout, chunk));
      child.stderr.on("data", chunk => collect(stderr, chunk));
      child.on("error", error => finish(new WorkerFailure("worker-launch", `Cannot launch analysis worker: ${error.message}`)));
      child.on("close", (code, signal) => finish(code === 0 ? undefined : new WorkerFailure("worker-failed", `Analysis worker exited with ${signal ?? code}: ${Buffer.concat(stderr).toString("utf8").slice(-2000)}`)));
      child.stdin.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "EPIPE") stop(new WorkerFailure("worker-input", error.message)); });
      if (abortSignal?.aborted) interrupted();
      child.stdin.end(input);
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
