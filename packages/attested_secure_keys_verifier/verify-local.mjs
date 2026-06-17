#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Local Android Key Attestation verifier — no backend required.
//
//   node verify-local.mjs <bundle.json>
//
// Takes the { keyId, publicJwk, attestation:{ x5c, nonce } } bundle exported by
// the demo app's "Copy JSON" button and checks it against the properties a
// wallet / WSCD (Wallet Secure Cryptographic Device) key must have:
//   - the cert chain is real and anchors to the pinned Google attestation root
//   - the attested certificate IS your public JWK
//   - the key was GENERATED in hardware (TEE/StrongBox), non-exportable
//   - verified boot + locked device
//   - user authentication is bound to the key
//   - the challenge is bound to a fresh server nonce (freshness / anti-replay)
//
// Uses only Node built-ins + the system `openssl` (no npm dependencies), so it
// runs anywhere openssl is on PATH. This is a developer self-check, NOT a
// production verifier (see the notes it prints at the end).
// ---------------------------------------------------------------------------

import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// --- Pinned trust anchor -----------------------------------------------------
// SHA-256 fingerprint of the legacy Google Hardware Attestation Root
// (subject DN attribute serialNumber=f92009e853b6b045). Before trusting this in
// production, confirm it equals Google's published root at
// https://android.googleapis.com/attestation/root — and ALSO pin the newer
// ECDSA P-384 root, which is mandatory for Remote-Key-Provisioning devices.
const GOOGLE_ROOT_SHA256 =
  '1EF1A04B8BA58AB94589AC498C8982A783F24EA7307E0159A0C3A73B377D87CC'

const SEC_LEVEL = { 0: 'Software', 1: 'TrustedEnvironment', 2: 'StrongBox' }
const BOOT_STATE = { 0: 'Verified', 1: 'SelfSigned', 2: 'Unverified', 3: 'Failed' }
const AUTH_BIT = { 1: 'PASSWORD/credential', 2: 'FINGERPRINT/biometric' }
const ATT_EXT_OID = '1.3.6.1.4.1.11129.2.1.17'

const c = (n, s) => `\x1b[${n}m${s}\x1b[0m`
let nPass = 0, nFail = 0, nWarn = 0
const ok = (m) => { nPass++; console.log(`  ${c(32, '✓')} ${m}`) }
const bad = (m) => { nFail++; console.log(`  ${c(31, '✗')} ${m}`) }
const warn = (m) => { nWarn++; console.log(`  ${c(33, '⚠')} ${m}`) }
const head = (t) => console.log('\n' + c(1, t))

const ossl = (args, input) =>
  execFileSync('openssl', args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
    .replace(/\r\n/g, '\n') // openssl on Windows emits CRLF; JS `.` won't match \r

// openssl verify exits non-zero on failure but still prints the verdict.
const osslSafe = (args) => {
  try { return ossl(args) }
  catch (e) { return ((e.stdout || '') + (e.stderr || '')).replace(/\r\n/g, '\n') }
}

const b64urlToHex = (s) =>
  Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex')

function main() {
  const file = process.argv[2]
  if (!file) {
    console.error('Usage: node verify-local.mjs <bundle.json>')
    process.exit(2)
  }
  try { ossl(['version']) } catch {
    console.error('openssl not found on PATH. Install OpenSSL or run from a shell that has it.')
    process.exit(2)
  }

  const bundle = JSON.parse(readFileSync(file, 'utf8'))
  const jwk = bundle.publicJwk || {}
  const att = bundle.attestation || {}
  const x5c = att.x5c || []
  const nonceHex = att.nonce ? b64urlToHex(att.nonce) : ''

  console.log(c(1, '=== attested_secure_keys — local attestation verifier ==='))
  console.log(`bundle : ${file}`)
  console.log(`keyId  : ${bundle.keyId || '(none)'}`)
  console.log(`type   : ${att.type || '(none)'}  encoding: ${att.encoding || '(none)'}`)

  const dir = mkdtempSync(join(tmpdir(), 'ask-verify-'))
  try {
    if (att.type !== 'android-key') {
      warn(`attestation type is "${att.type}", not "android-key" — this script only checks Android key attestation.`)
    }

    // --- 1. Build PEMs from the chain ---------------------------------------
    head('[1] Certificate chain')
    const pems = []
    x5c.forEach((b64, i) => {
      const der = join(dir, `c${i}.der`)
      const pem = join(dir, `c${i}.pem`)
      writeFileSync(der, Buffer.from(b64, 'base64')) // Buffer base64 is lenient about padding
      ossl(['x509', '-inform', 'DER', '-in', der, '-out', pem])
      pems.push(pem)
    })
    if (pems.length >= 2) ok(`${pems.length} certificates parsed (leaf → root)`)
    else { bad(`expected a chain of ≥ 2 certs, got ${pems.length}`); return finish(dir) }

    const leaf = pems[0]
    const root = pems[pems.length - 1]
    const intermediates = pems.slice(1, -1)

    // --- 2. Pin the root, then verify the chain anchors to it ----------------
    const rootFp = ossl(['x509', '-in', root, '-noout', '-fingerprint', '-sha256'])
      .split('=')[1].replace(/[:\s]/g, '').toUpperCase()
    if (rootFp === GOOGLE_ROOT_SHA256) {
      ok('root certificate matches the pinned Google Hardware Attestation root (SHA-256)')
    } else {
      bad(`root does NOT match the pinned Google root.\n      got      ${rootFp}\n      expected ${GOOGLE_ROOT_SHA256}`)
    }

    const interFile = join(dir, 'inter.pem')
    writeFileSync(interFile, intermediates.map((p) => readFileSync(p)).join('\n'))
    const verifyArgs = ['verify', '-CAfile', root]
    if (intermediates.length) verifyArgs.push('-untrusted', interFile)
    verifyArgs.push(leaf)
    const vout = osslSafe(verifyArgs).trim()
    if (/:\s*OK\s*$/m.test(vout)) ok(`chain verifies cryptographically (openssl: "${vout.split('\n').pop().trim()}")`)
    else bad(`chain did NOT verify: ${vout}`)

    // --- 3. Leaf key == publicJwk -------------------------------------------
    head('[2] Key identity')
    const leafText = ossl(['x509', '-in', leaf, '-noout', '-text'])
    const pointHex = (leafText.match(/pub:\s*([\s\S]*?)ASN1 OID/) || [, ''])[1]
      .replace(/[^0-9a-fA-F]/g, '').toLowerCase()
    const curve = (leafText.match(/ASN1 OID:\s*(\S+)/) || [, '?'])[1]
    if (/^04[0-9a-f]{128}$/.test(pointHex)) {
      const certX = pointHex.slice(2, 66)
      const certY = pointHex.slice(66, 130)
      const jx = jwk.x ? b64urlToHex(jwk.x) : ''
      const jy = jwk.y ? b64urlToHex(jwk.y) : ''
      if (certX === jx && certY === jy) ok('leaf certificate public key == publicJwk (x and y match byte-for-byte)')
      else bad('leaf public key does NOT match publicJwk')
    } else warn('could not extract the leaf EC point to compare with the JWK')
    if (curve === 'prime256v1') ok(`key is EC P-256 / ES256 (${curve}) — the curve EUDI uses`)
    else warn(`unexpected curve: ${curve} (expected prime256v1 / P-256)`)

    // --- 4. Parse the KeyDescription (the attestation extension) -------------
    head('[3] Hardware & key properties (from the signed attestation extension)')
    const kd = parseKeyDescription(leaf)
    if (!kd) { bad(`could not locate/parse the attestation extension (OID ${ATT_EXT_OID})`); return finish(dir) }

    const named = (m, v) => `${m[v] ?? '?'}(${v})`
    const attLvlOk = kd.attestationSecurityLevel >= 1
    const kmLvlOk = kd.keymasterSecurityLevel >= 1
    ;(attLvlOk ? ok : bad)(`attestationSecurityLevel = ${named(SEC_LEVEL, kd.attestationSecurityLevel)} ${attLvlOk ? '(hardware)' : '(SOFTWARE — not hardware!)'}`)
    ;(kmLvlOk ? ok : bad)(`keymasterSecurityLevel   = ${named(SEC_LEVEL, kd.keymasterSecurityLevel)}`)
    if (kd.attestationSecurityLevel === 1) warn('this is TEE, not StrongBox(2) — strong vs a rooted OS, but not a discrete secure element')
    if (kd.origin === 0) ok('origin = GENERATED(0) — key minted inside hardware, never imported (non-exportable)')
    else bad(`origin = ${kd.origin} (expected GENERATED(0))`)
    if (kd.verifiedBootState === 0) ok('rootOfTrust.verifiedBootState = Verified(0)')
    else warn(`verifiedBootState = ${named(BOOT_STATE, kd.verifiedBootState)} (not Verified)`)
    ;(kd.deviceLocked ? ok : warn)(`rootOfTrust.deviceLocked = ${kd.deviceLocked}`)

    // --- 5. User-authentication binding -------------------------------------
    head('[4] User-authentication binding')
    if (kd.noAuthRequired) {
      bad('noAuthRequired is PRESENT — the key can be used with NO authentication (gating not enforced)')
    } else if (kd.userAuthType != null) {
      const bits = Object.entries(AUTH_BIT).filter(([b]) => kd.userAuthType & b).map(([, n]) => n)
      ok(`key requires user auth (noAuthRequired absent); userAuthType=${kd.userAuthType} → ${bits.join(' + ') || 'unknown'}`)
      warn('the attestation cannot distinguish strong (Class-3) from weak biometrics — only "a fingerprint/biometric is required"')
    } else {
      warn('no noAuthRequired and no userAuthType found — gating state unclear')
    }

    // --- 6. Freshness / anti-replay -----------------------------------------
    head('[5] Freshness (anti-replay) — bind to a server nonce')
    const chalHex = kd.challengeHex
    const chalAscii = isPrintable(kd.challengeHex) ? Buffer.from(kd.challengeHex, 'hex').toString('latin1') : null
    console.log(`      attestationChallenge = ${chalAscii ? `"${chalAscii}"` : ''} (hex ${chalHex})`)
    console.log(`      server nonce         = (hex ${nonceHex || '(none in bundle)'})`)
    if (nonceHex && chalHex === nonceHex) {
      ok('challenge == server nonce — this attestation is bound to your request (fresh)')
    } else {
      bad('challenge != server nonce — the attestation is NOT bound to a fresh challenge, so it is REPLAYABLE')
      console.log(c(2, '        → fix: bind serverNonce as the attestation challenge at key generation (the M1 task)'))
    }

    finish(dir)
  } catch (e) {
    console.error('\n' + c(31, 'verifier error: ') + (e.message || e))
    finish(dir)
    process.exit(1)
  }
}

// Extract & parse the Android KeyDescription via `openssl asn1parse`.
function parseKeyDescription(leafPem) {
  const top = ossl(['asn1parse', '-in', leafPem]).split('\n')
  const oidIdx = top.findIndex((l) => l.includes(ATT_EXT_OID))
  if (oidIdx < 0 || oidIdx + 1 >= top.length) return null
  const off = (top[oidIdx + 1].match(/^\s*(\d+):/) || [])[1]
  if (off == null) return null

  const recs = ossl(['asn1parse', '-in', leafPem, '-strparse', off])
    .split('\n')
    .map((l) => {
      const m = l.match(/^\s*(\d+):d=(\d+)\s+hl=\s*\d+\s+l=\s*(\d+)\s+(?:prim|cons):\s*(.*)$/)
      if (!m) return null
      return { depth: +m[2], rest: m[4].trim() }
    })
    .filter(Boolean)
  const d1 = recs.filter((r) => r.depth === 1)
  const enums = d1.filter((r) => r.rest.startsWith('ENUMERATED'))
  const octets = d1.filter((r) => r.rest.startsWith('OCTET STRING'))
  const hexOf = (rest) => {
    const h = rest.match(/\[HEX DUMP\]:\s*([0-9A-Fa-f]*)/)
    if (h) return h[1].toLowerCase()
    const v = rest.split(':').slice(1).join(':') // printable OCTET like ":demo.holderKey"
    return Buffer.from(v, 'latin1').toString('hex')
  }
  const enumVal = (rest) => parseInt((rest.split(':')[1] || '0').trim(), 16)

  // Find a context-tagged value: returns the INTEGER/ENUM after `cont [ tag ]`.
  const afterTag = (tag, kind) => {
    const i = recs.findIndex((r) => r.rest.replace(/\s+/g, ' ') === `cont [ ${tag} ]`)
    if (i < 0) return null
    for (let j = i + 1; j < recs.length; j++) {
      if (kind === 'int' && /^INTEGER/.test(recs[j].rest)) return enumVal(recs[j].rest)
      if (kind === 'bool' && /^BOOLEAN/.test(recs[j].rest)) {
        const v = (recs[j].rest.split(':')[1] || '0').trim()
        return v !== '0' && v !== '00'
      }
      if (kind === 'enum' && /^ENUMERATED/.test(recs[j].rest)) return enumVal(recs[j].rest)
    }
    return null
  }

  // rootOfTrust [704]: deviceLocked (BOOLEAN) then verifiedBootState (ENUMERATED).
  return {
    attestationSecurityLevel: enums[0] ? enumVal(enums[0].rest) : null,
    keymasterSecurityLevel: enums[1] ? enumVal(enums[1].rest) : null,
    challengeHex: octets[0] ? hexOf(octets[0].rest) : '',
    origin: afterTag(702, 'int'),
    userAuthType: afterTag(504, 'int'),
    noAuthRequired: recs.some((r) => r.rest.replace(/\s+/g, ' ') === 'cont [ 503 ]'),
    deviceLocked: afterTag(704, 'bool'),
    verifiedBootState: afterTag(704, 'enum'),
  }
}

const isPrintable = (hex) =>
  hex.length > 0 && Buffer.from(hex, 'hex').every((b) => b >= 0x20 && b < 0x7f)

function finish(dir) {
  try { rmSync(dir, { recursive: true, force: true }) } catch {}
  head('=== Summary ===')
  console.log(`  ${c(32, nPass + ' passed')}   ${c(31, nFail + ' failed')}   ${c(33, nWarn + ' warnings')}`)
  const wscdReady = nFail === 0
  console.log('\n' + c(1, 'Wallet/WSCD readiness:'))
  console.log(`  ${wscdReady ? c(32, '✓') : c(31, '✗')} Key is hardware-bound, non-exportable, attestable to Google's root, and (if [4] passed) user-auth gated.`)
  console.log(`  ${c(33, '⚠')} For a LIVE proof-of-possession you still need: challenge==fresh-nonce ([5]), a signature over that nonce, revocation check, and the OID4VCI keyattestation+jwt wrapper (M2).`)
  console.log(c(2, '\n  Note: a real verifier must also check cert validity windows, the Google revocation status list,\n  and pin BOTH the legacy RSA root and the ECDSA P-384 (RKP) root. This script is a developer self-check.'))
  process.exitCode = nFail === 0 ? 0 : 1
}

main()
