// CI-only bridge for actions/attest's pinned ~/.docker/config.json lookup.
// Never changes HOME, DOCKER_CONFIG, the Buildx plugin or credential scopes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const limit = 64 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function directory(dir, create = false) {
  if (!fs.existsSync(dir) && create) fs.mkdirSync(dir, {mode: 0o700});
  const info = fs.lstatSync(dir);
  assert.ok(info.isDirectory() && !info.isSymbolicLink());
  assert.equal(fs.realpathSync(dir), path.resolve(dir));
}

function read(file, maxBytes = limit) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(descriptor);
    assert.ok(info.isFile() && info.size <= maxBytes);
    const bytes = fs.readFileSync(descriptor);
    assert.ok(bytes.length <= maxBytes);
    const value = JSON.parse(bytes.toString('utf8'));
    assert.ok(object(value));
    return {bytes, value, mode: info.mode & 0o777};
  } finally {
    fs.closeSync(descriptor);
  }
}

function config(file) {
  const result = read(file);
  assert.ok(result.value.auths === undefined || object(result.value.auths));
  // Never consult or alter an external credential helper/store.
  assert.ok(result.value.credsStore === undefined);
  assert.ok(result.value.credHelpers === undefined);
  assert.ok(result.value.HttpHeaders === undefined);
  return result;
}

function assertNoGHCR(value) {
  assert.ok(value.auths === undefined || object(value.auths));
  for (const key of Object.keys(value.auths ?? {})) {
    // Docker accepts bare registry names and URL-style keys. Never take over
    // existing GHCR authority, including scheme, case, port or path aliases.
    const registry = new URL(key.includes('://') ? key : 'https://' + key);
    assert.notEqual(registry.hostname.toLowerCase(), 'ghcr.io');
  }
}

function replace(file, bytes, mode) {
  const temporary = path.join(path.dirname(file), '.n2u-attestation-auth-new');
  const descriptor = fs.openSync(temporary, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fchmodSync(descriptor, mode);
    fs.fsyncSync(descriptor);
  } catch (error) {
    fs.closeSync(descriptor);
    fs.unlinkSync(temporary);
    throw error;
  }
  fs.closeSync(descriptor);
  try {
    fs.renameSync(temporary, file);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

export function prepare({attestDir, isolatedDir, stateDir}) {
  directory(path.dirname(attestDir));
  directory(isolatedDir);
  directory(path.dirname(stateDir));
  assert.notEqual(path.resolve(attestDir), path.resolve(isolatedDir));
  const source = config(path.join(isolatedDir, 'config.json')).value;
  assert.deepEqual(Object.keys(source.auths ?? {}), ['ghcr.io']);
  const credential = source.auths['ghcr.io'];
  assert.ok(object(credential));
  assert.deepEqual(Object.keys(credential), ['auth']);
  assert.ok(typeof credential.auth === 'string' && credential.auth.length > 0 && credential.auth.length <= 16384);
  assert.match(credential.auth, /^[A-Za-z0-9+/]+={0,2}$/);
  const decoded = Buffer.from(credential.auth, 'base64').toString('utf8');
  assert.ok(decoded.indexOf(':') > 0 && !decoded.endsWith(':'));
  directory(attestDir, true);
  const target = path.join(attestDir, 'config.json');
  let previous = null;
  try { previous = config(target); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  // Preserve unrelated runner state, but fail before taking over existing auth.
  assertNoGHCR(previous?.value ?? {});
  const bridge = Buffer.from(JSON.stringify({auths: {'ghcr.io': credential}}) + '\n');
  // Exclusive journal creation precedes the only change to the default config.
  fs.mkdirSync(stateDir, {mode: 0o700});
  fs.writeFileSync(path.join(stateDir, 'original.json'), JSON.stringify({
    existed: previous !== null,
    bytes: previous?.bytes.toString('base64') ?? '',
    mode: previous?.mode ?? 0o600
  }), {flag: 'wx', mode: 0o600});
  replace(target, bridge, 0o600);
  assert.deepEqual(config(target).bytes, bridge);
}

export function cleanup({attestDir, isolatedDir, stateDir}) {
  const errors = [];
  // Both stores are handled independently: a restoration failure must not
  // prevent scrubbing the isolated publication credential (and vice versa).
  try {
    if (fs.existsSync(stateDir)) {
      directory(stateDir);
      const journalPath = path.join(stateDir, 'original.json');
      if (fs.existsSync(journalPath)) {
        directory(attestDir);
        const saved = read(journalPath, 2 * limit).value;
        assert.deepEqual(Object.keys(saved).sort(), ['bytes', 'existed', 'mode']);
        assert.equal(typeof saved.existed, 'boolean');
        assert.equal(typeof saved.bytes, 'string');
        assert.ok(Number.isInteger(saved.mode) && saved.mode >= 0 && saved.mode <= 0o777);
        const target = path.join(attestDir, 'config.json');
        if (saved.existed) {
          const original = Buffer.from(saved.bytes, 'base64');
          const parsed = JSON.parse(original.toString('utf8'));
          assert.ok(object(parsed));
          assertNoGHCR(parsed);
          assert.ok(parsed.credsStore === undefined && parsed.credHelpers === undefined && parsed.HttpHeaders === undefined);
          replace(target, original, saved.mode);
          const restored = config(target);
          assert.deepEqual(restored.bytes, original);
          assert.equal(restored.mode, saved.mode);
        } else {
          assert.equal(saved.bytes, '');
          try {
            assert.ok(fs.lstatSync(target).isFile());
            fs.unlinkSync(target);
          } catch (error) { if (error.code !== 'ENOENT') throw error; }
          assert.ok(!fs.existsSync(target));
        }
        fs.unlinkSync(journalPath);
      }
    }
  } catch (error) { errors.push(error); }
  try {
    if (fs.existsSync(isolatedDir)) {
      directory(isolatedDir);
      const file = path.join(isolatedDir, 'config.json');
      if (fs.existsSync(file)) {
        const current = config(file);
        delete current.value.auths?.['ghcr.io'];
        replace(file, Buffer.from(JSON.stringify(current.value) + '\n'), 0o600);
        assert.ok(!Object.hasOwn(config(file).value.auths ?? {}, 'ghcr.io'));
      }
      fs.accessSync(path.join(isolatedDir, 'cli-plugins', 'docker-buildx'), fs.constants.X_OK);
    }
  } catch (error) { errors.push(error); }
  if (errors.length) throw new Error('credential cleanup failed');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.ok(process.env.RUNNER_TEMP && process.env.DOCKER_CONFIG);
    const paths = {
      attestDir: path.join(os.homedir(), '.docker'),
      isolatedDir: process.env.DOCKER_CONFIG,
      stateDir: path.join(process.env.RUNNER_TEMP, 'n2u-attestation-auth')
    };
    assert.equal(path.resolve(paths.isolatedDir), path.join(process.env.RUNNER_TEMP, 'n2u-docker-config'));
    assert.ok(process.argv.length === 3);
    if (process.argv[2] === 'prepare') prepare(paths);
    else if (process.argv[2] === 'cleanup') cleanup(paths);
    else throw new Error('unknown operation');
  } catch {
    // Never render exceptions/assertion values that might contain credentials.
    console.error('Attestation credential bridge failed; publication is blocked.');
    process.exitCode = 1;
  }
}
