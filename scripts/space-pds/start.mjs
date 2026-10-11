// Starts the upstream atproto dev network (PLC + one PDS, no AppView) from a
// built checkout of bluesky-social/atproto branch `permissioned-data`,
// creates test accounts with a personal Labyrinth mailbox Space each, and
// writes their sessions to a JSON file for `tests/live_space_pds.rs`.
//
//   node scripts/space-pds/start.mjs <atproto checkout> <out.json>
//
// Runs until interrupted. No Postgres is needed: the PDS and PLC use SQLite.

import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const [atproto, out] = process.argv.slice(2)
if (!atproto || !out) {
  console.error('usage: start.mjs <atproto checkout> <out.json>')
  process.exit(2)
}
const devEnv = pathToFileURL(
  resolve(atproto, 'packages/dev-env/dist/index.js'),
).href
const { TestNetworkNoAppView } = await import(devEnv)

const SPACE_TYPE = 'blue.catbird.labyrinth.mailbox'
const SKEY = 'self'
const NAMES = ['alice', 'bob', 'carol', 'dave']

const network = await TestNetworkNoAppView.create({})
const pdsUrl = network.pds.url

async function xrpc(nsid, body, jwt) {
  const res = await fetch(`${pdsUrl}/xrpc/${nsid}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(jwt ? { authorization: `Bearer ${jwt}` } : {}),
    },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`${nsid} ${res.status}: ${text}`)
  return text ? JSON.parse(text) : {}
}

const accounts = {}
for (const name of NAMES) {
  const s = await xrpc('com.atproto.server.createAccount', {
    handle: `${name}.test`,
    email: `${name}@test.com`,
    password: `${name}-pass`,
  })
  // The owner-only mailbox: nobody else is on the member list.
  const space = await xrpc(
    'com.atproto.simplespace.createSpace',
    {
      spaceType: SPACE_TYPE,
      skey: SKEY,
      readPolicy: { $type: 'com.atproto.simplespace.defs#memberListPolicy' },
      writePolicy: { $type: 'com.atproto.simplespace.defs#memberListPolicy' },
      appAccess: { $type: 'com.atproto.simplespace.defs#open' },
    },
    s.accessJwt,
  )
  accounts[name] = { did: s.did, accessJwt: s.accessJwt, space: space.uri }
}

writeFileSync(out, JSON.stringify({ pds: pdsUrl, accounts }, null, 2))
console.log(`space PDS at ${pdsUrl}; sessions in ${out}`)

const stop = async () => {
  await network.close()
  process.exit(0)
}
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
setInterval(() => {}, 1 << 30)
