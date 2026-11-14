// Requirement coverage: VHS-REQ-707 (Mirror-Mode dual real-runtime validation) and
// VHS-REQ-710 (vendored TDMS transport). Pins the deterministic rolling-block ring
// (VHS-REQ-707.18) and the vendored tools/tdms copies to the shared contract that
// mprr publishes at a tagged release: the vendored contract must match its pinned
// SHA-256, the ring constants and the C# copies must agree with it, and the copies
// must still match the recorded upstream snapshot (tools/tdms/provenance.json).
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  BLOCK_BOUNDARY_AUTHORITATIVE_MAX_PERCENT,
  BLOCK_BOUNDARY_NORMAL_LOAD_TARGET_PERCENT,
  DEFAULT_BLOCK_DURATION_MS,
  MIN_RING_CAPACITY_BYTES,
  MPRR_TICKS_PER_MILLISECOND,
  THREE_BLOCK_CAPACITY_HEADROOM,
  THREE_BLOCK_HORIZON,
  computeRequiredThreeBlockCapacityBytes
} from '../../src/reporting/mirror/deterministicRollingBlockRing';

const repoRoot = path.resolve(__dirname, '..', '..');
const contractDir = path.join(repoRoot, 'tools', 'tdms', 'contract');

interface Pin { source: string; tag: string; sha256: string }
interface Constant { value: number }
interface Contract { schemaVersion: string; constants: Record<string, Constant> }
interface Provenance { source: string; tag: string; files: Array<{ path: string; sha256: string }> }

const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const readJson = <T>(file: string): T => JSON.parse(fs.readFileSync(file, 'utf8')) as T;

function loadContract(contractPath = path.join(contractDir, 'mprr-shared-contract.v1.json')): { pin: Pin; contract: Contract } {
  const pin = readJson<Pin>(path.join(contractDir, 'pin.json'));
  const bytes = fs.readFileSync(contractPath);
  expect(sha256(bytes), `vendored contract must match the ${pin.tag} pin`).toBe(pin.sha256);
  return { pin, contract: JSON.parse(bytes.toString('utf8')) as Contract };
}

// The one number a C# declaration carries, read from a closed pattern so an edit
// that extends the literal (45_000 * 2, 10_0000) no longer matches.
function csharpLiteral(relativePath: string, pattern: RegExp): number {
  const source = fs.readFileSync(path.resolve(repoRoot, relativePath), 'utf8');
  const matches = [...source.matchAll(pattern)];
  expect(matches, `${relativePath} must declare ${pattern} exactly once`).toHaveLength(1);
  return Number(matches[0][1].replace(/_/g, ''));
}

describe('mprr shared contract pin (VHS-REQ-707.18, VHS-REQ-710)', () => {
  it('vendors the contract from a tagged mprr release, byte-exact', () => {
    const { pin, contract } = loadContract();
    expect(pin.source).toBe('gitlab.com/svelderrainruiz/mprr');
    expect(pin.tag).toMatch(/^v\d+\.\d+\.\d+$/);
    expect(contract.schemaVersion).toBe('mprr-shared-contract-v1');
  });

  it('keeps the rolling-block ring constants equal to the contract', () => {
    const c = loadContract().contract.constants;
    expect(MPRR_TICKS_PER_MILLISECOND).toBe(c.timingTicksPerMillisecond.value);
    expect(DEFAULT_BLOCK_DURATION_MS).toBe(c.defaultBlockDurationMilliseconds.value);
    expect(THREE_BLOCK_HORIZON).toBe(c.blocksPerHorizon.value);
    expect(THREE_BLOCK_CAPACITY_HEADROOM).toBe(c.admissionCapacitySafetyFactor.value);
    expect(MIN_RING_CAPACITY_BYTES).toBe(c.minimumRingCapacityBytes.value);
    expect(BLOCK_BOUNDARY_AUTHORITATIVE_MAX_PERCENT).toBe(c.nonAuthoritativeBoundaryVariationPercent.value);
    expect(BLOCK_BOUNDARY_NORMAL_LOAD_TARGET_PERCENT).toBe(c.normalLoadBoundaryVariationPercent.value);
    // Behaviour, not just constants: equal blocks above the minimum capacity need
    // ceil(safetyFactor * (blocksPerHorizon * blockBytes)).
    const blockBytes = 100_000;
    const blocks = { 0: blockBytes, 1: blockBytes, 2: blockBytes, 3: blockBytes, 4: blockBytes };
    expect(computeRequiredThreeBlockCapacityBytes(blocks)).toBe(
      Math.ceil(c.admissionCapacitySafetyFactor.value * (c.blocksPerHorizon.value * blockBytes))
    );
  });

  it('keeps the vendored tools/tdms C# constants equal to the contract', () => {
    const c = loadContract().contract.constants;
    const generator = 'tools/tdms/review-capture-windows-zero-copy-packet-harness-generator/Program.cs';
    expect(csharpLiteral(generator, /private const ulong TicksPerMillisecond = ([\d_]+);/g))
      .toBe(c.timingTicksPerMillisecond.value);
    expect(csharpLiteral(generator, /public int BlockDurationMilliseconds \{ get; init; \} = ([\d_]+);/g))
      .toBe(c.defaultBlockDurationMilliseconds.value);
  });

  it('records which upstream snapshot the tools/tdms copies came from', () => {
    const { pin } = loadContract();
    const provenance = readJson<Provenance>(path.join(repoRoot, 'tools', 'tdms', 'provenance.json'));
    expect(provenance.source).toBe(pin.source);
    expect(provenance.tag).toBe(pin.tag);
    const recorded = provenance.files.map((file) => file.path).sort();
    const copied = fs.readdirSync(path.join(repoRoot, 'tools', 'tdms'), { recursive: true, encoding: 'utf8' })
      .map((entry) => `tools/tdms/${entry.split(path.sep).join('/')}`)
      .filter((entry) => /\.(cs|csproj)$/.test(entry) && !/\/(bin|obj)\//.test(entry))
      .sort();
    expect(recorded, 'every copied C# file must be recorded in provenance.json').toEqual(copied);
    for (const file of provenance.files) {
      const text = fs.readFileSync(path.join(repoRoot, file.path)).toString('utf8').replace(/\r\n/g, '\n');
      expect(sha256(Buffer.from(text, 'utf8')), `${file.path} diverged from ${provenance.tag}; record the change in provenance.json`)
        .toBe(file.sha256);
    }
  });

  it('rejects a tampered contract and a literal extended past its declaration', () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'vihs-mprr-contract-'));
    try {
      const tampered = path.join(scratch, 'contract.json');
      const original = fs.readFileSync(path.join(contractDir, 'mprr-shared-contract.v1.json'), 'utf8');
      expect(original).toContain('"value": 45000');
      fs.writeFileSync(tampered, original.replace('"value": 45000', '"value": 46000'));
      expect(() => loadContract(tampered)).toThrow(/must match the v\d+\.\d+\.\d+ pin/);

      const drifted = path.join(scratch, 'Program.cs');
      fs.writeFileSync(drifted, '    private const ulong TicksPerMillisecond = 10_000 * 2;\n');
      expect(() => csharpLiteral(drifted, /private const ulong TicksPerMillisecond = ([\d_]+);/g)).toThrow(/exactly once/);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});
