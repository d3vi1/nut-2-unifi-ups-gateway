import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {test} from 'node:test';
import {cleanup, prepare} from './attestation-auth.mjs';

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'n2u-auth-test-')));
  t.after(() => fs.rmSync(root, {recursive: true}));
  const paths = {attestDir: path.join(root, '.docker'), isolatedDir: path.join(root, 'isolated'), stateDir: path.join(root, 'journal')};
  fs.mkdirSync(paths.isolatedDir);
  fs.mkdirSync(path.join(paths.isolatedDir, 'cli-plugins'));
  fs.writeFileSync(path.join(paths.isolatedDir, 'cli-plugins', 'docker-buildx'), 'synthetic plugin', {mode: 0o700});
  fs.writeFileSync(path.join(paths.isolatedDir, 'config.json'), JSON.stringify({auths: {'ghcr.io': {auth: Buffer.from('synthetic:never-a-secret').toString('base64')}}}), {mode: 0o600});
  return paths;
}

function original(paths, content) {
  fs.mkdirSync(paths.attestDir);
  fs.writeFileSync(path.join(paths.attestDir, 'config.json'), content, {mode: 0o640});
}

function assertScrubbed(paths) {
  const source = JSON.parse(fs.readFileSync(path.join(paths.isolatedDir, 'config.json')));
  assert.equal(source.auths['ghcr.io'], undefined);
  assert.equal(fs.readFileSync(path.join(paths.isolatedDir, 'cli-plugins', 'docker-buildx'), 'utf8'), 'synthetic plugin');
}

for (const existing of [null, '{\n "auths": {}, "experimental": "enabled"\n}\n', '{"auths":{"https://index.docker.io/v1/":{"auth":"c3ludGhldGljOnRlc3Q="}}}\n', '{"auths":{}}' + ' '.repeat(60000)]) {
  test(`pinned action lookup and exact restore (${existing === null ? 'absent' : existing.length + ' bytes'})`, t => {
    const paths = fixture(t);
    if (existing !== null) original(paths, existing);
    prepare(paths);
    // Same fixed path/read as the pinned @sigstore/oci getRegistryCredentials.
    const configPath = path.join(path.dirname(paths.attestDir), '.docker', 'config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.equal(Buffer.from(config.auths['ghcr.io'].auth, 'base64').toString('utf8'), 'synthetic:never-a-secret');
    assert.equal(fs.statSync(configPath).mode & 0o777, 0o600);
    cleanup(paths);
    if (existing !== null) {
      assert.equal(fs.readFileSync(configPath, 'utf8'), existing);
      assert.equal(fs.statSync(configPath).mode & 0o777, 0o640);
    } else assert.ok(!fs.existsSync(configPath));
    assertScrubbed(paths);
    cleanup(paths); // Cleanup is safe if called again after successful restoration.
  });
}

for (const invalid of ['not-json', '[]', '{"credsStore":"helper"}', '{"credHelpers":{}}', '{"HttpHeaders":{}}', '{"auths":{"ghcr.io":{}}}', '{"auths":{"https://GHCR.io/v1/":{}}}', '{"auths":{"ghcr.io:443":{}}}', ' '.repeat(65537)]) {
  test('reject default config without overwriting it: ' + invalid.slice(0, 48), t => {
    const paths = fixture(t);
    original(paths, invalid);
    assert.throws(() => prepare(paths));
    assert.equal(fs.readFileSync(path.join(paths.attestDir, 'config.json'), 'utf8'), invalid);
    cleanup(paths);
    assertScrubbed(paths);
  });
}

for (const invalid of ['not-json', '{}', '{"auths":{}}', '{"auths":{"ghcr.io":{"auth":"broken"}}}', '{"auths":{"ghcr.io":{"auth":"aDp5","identitytoken":"x"}}}', '{"auths":{"ghcr.io":{"auth":"aDp5"},"other":{}}}']) {
  test('reject unusable isolated credential: ' + invalid.slice(0, 48), t => {
    const paths = fixture(t);
    fs.writeFileSync(path.join(paths.isolatedDir, 'config.json'), invalid);
    assert.throws(() => prepare(paths));
    assert.ok(!fs.existsSync(paths.attestDir));
  });
}

test('reject symlinked default config and directory', t => {
  const paths = fixture(t);
  fs.mkdirSync(paths.attestDir);
  const source = path.join(paths.isolatedDir, 'config.json');
  const bytes = fs.readFileSync(source);
  fs.symlinkSync(source, path.join(paths.attestDir, 'config.json'));
  assert.throws(() => prepare(paths));
  assert.deepEqual(fs.readFileSync(source), bytes);
  fs.unlinkSync(path.join(paths.attestDir, 'config.json'));
  fs.rmdirSync(paths.attestDir);
  fs.symlinkSync(paths.isolatedDir, paths.attestDir);
  assert.throws(() => prepare(paths));
});

test('a preparation failure after journaling restores the exact original', t => {
  const paths = fixture(t);
  original(paths, '{"auths":{}}\n');
  // Exclusive staging-file creation fails before replacing the target.
  const collision = path.join(paths.attestDir, '.n2u-attestation-auth-new');
  fs.writeFileSync(collision, 'unrelated');
  assert.throws(() => prepare(paths));
  assert.equal(fs.readFileSync(collision, 'utf8'), 'unrelated');
  fs.unlinkSync(collision);
  cleanup(paths);
  assert.equal(fs.readFileSync(path.join(paths.attestDir, 'config.json'), 'utf8'), '{"auths":{}}\n');
  assertScrubbed(paths);
});

test('restore failure blocks publication but still scrubs isolated credentials', t => {
  const paths = fixture(t);
  prepare(paths);
  fs.writeFileSync(path.join(paths.stateDir, 'original.json'), 'broken');
  assert.throws(() => cleanup(paths), /credential cleanup failed/);
  assertScrubbed(paths);
});

test('isolated cleanup failure still restores default config', t => {
  const paths = fixture(t);
  original(paths, '{"auths":{}}\n');
  prepare(paths);
  fs.writeFileSync(path.join(paths.isolatedDir, 'config.json'), 'broken');
  assert.throws(() => cleanup(paths), /credential cleanup failed/);
  assert.equal(fs.readFileSync(path.join(paths.attestDir, 'config.json'), 'utf8'), '{"auths":{}}\n');
});

test('reject journal reuse before another default-config mutation', t => {
  const paths = fixture(t);
  fs.mkdirSync(paths.stateDir);
  assert.throws(() => prepare(paths));
  assert.ok(!fs.existsSync(path.join(paths.attestDir, 'config.json')));
});
