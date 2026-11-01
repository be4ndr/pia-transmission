const assert = require('node:assert/strict')
const { before, after, beforeEach, afterEach, test } = require('node:test')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const { chromium } = require('../node_modules/playwright')

const fixture = JSON.parse(fs.readFileSync(process.env.WEBUI_TEST_CONFIG, 'utf8'))
const evidence = process.env.WEBUI_TEST_EVIDENCE
const auth = `Basic ${Buffer.from('fixture:fixture-password').toString('base64')}`
let browser
let sessionId = ''
let clients = []
let testNumber = 0

async function rpc(method, args = {}) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await fetch(fixture.rpc, {
      method: 'POST',
      headers: { Authorization: auth, 'Content-Type': 'application/json', 'X-Transmission-Session-Id': sessionId },
      body: JSON.stringify({ method, arguments: args })
    })
    if (response.status === 409) {
      sessionId = response.headers.get('X-Transmission-Session-Id')
      continue
    }
    assert.equal(response.status, 200)
    const body = await response.json()
    assert.equal(body.result, 'success', JSON.stringify(body))
    return body.arguments
  }
  throw new Error('RPC session negotiation failed')
}

async function torrents() {
  return (await rpc('torrent-get', {
    fields: ['id', 'name', 'isPrivate', 'metadataPercentComplete', 'trackers', 'trackerStats', 'downloadDir', 'percentDone', 'hashString']
  })).torrents
}

async function eventually(read, predicate) {
  const deadline = Date.now() + 30000
  while (Date.now() < deadline) {
    const result = await read()
    if (predicate(result)) return result
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error('Timed out waiting for daemon readback')
}

async function client(settings = {}, route = '', viewport = { width: 1440, height: 1000 }) {
  const context = await browser.newContext({
    viewport, locale: 'en-US', serviceWorkers: 'block',
    httpCredentials: { username: 'fixture', password: 'fixture-password' }
  })
  await context.addInitScript(settings => {
    if (!localStorage.getItem('setting')) {
      localStorage.setItem('setting', JSON.stringify({
        language: 'en-US', polling: { sessionInterval: 1, torrentInterval: 1, torrentDetailInterval: 1 }, ...settings
      }))
    }
  }, settings)
  await context.route('**/*', route => {
    const url = new URL(route.request().url())
    return url.hostname === '127.0.0.1' || url.protocol === 'data:' ? route.continue() : route.abort()
  })
  const page = await context.newPage()
  page.setDefaultTimeout(8000)
  const traffic = []
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', async response => {
    if (response.url() !== fixture.rpc) return
    try {
      const request = JSON.parse(response.request().postData())
      // Fixture bytes and session tokens add no diagnostic value to the log.
      if (request.arguments?.metainfo) request.arguments.metainfo = '[fixture]'
      const body = response.status() === 200 ? await response.json() : null
      if (body?.arguments?.['session-id']) body.arguments['session-id'] = '[fixture]'
      traffic.push({ request, status: response.status(), response: body })
    } catch { /* 401 authentication challenges have no JSON request body. */ }
  })
  const entry = { context, page, traffic, errors, response: null }
  clients.push(entry)
  entry.response = await page.goto(fixture.base + route)
  if (!route) await page.getByPlaceholder('Search torrents...').waitFor()
  return entry
}

async function upload(page, files) {
  await page.locator('button').nth(2).click()
  await page.locator('input[type=file]').setInputFiles(files)
  await page.locator('.n-dialog .n-switch').first().click() // add paused; file operations use seeded local data
  await page.getByRole('button', { name: 'Add', exact: true }).click()
}

async function settingsDialog(page) {
  await page.locator('button').nth(13).click()
  await page.locator('.n-dialog .n-tabs-tab').filter({ hasText: /^Other$/ }).click()
  return page.getByPlaceholder('Default tracker list', { exact: true })
}

async function message(page, text) {
  await page.locator('.n-message__content').filter({ hasText: text }).waitFor()
}

before(async () => {
  assert.equal((await rpc('session-get')).version, '4.1.3 (838877323f)')
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] })
})

beforeEach(async () => {
  clients = []
  testNumber++
  const current = await torrents()
  if (current.length) await rpc('torrent-remove', { ids: current.map(t => t.id), 'delete-local-data': false })
  await rpc('session-set', { 'default-trackers': '' })
})

afterEach(async () => {
  for (const [index, entry] of clients.entries()) {
    const stem = path.join(evidence, `${testNumber}-${index}`)
    try {
      await entry.page.screenshot({ path: stem + '.png' })
      fs.writeFileSync(stem + '.html', await entry.page.content())
      fs.writeFileSync(stem + '.json', JSON.stringify({ url: entry.page.url(), traffic: entry.traffic, errors: entry.errors }, null, 2))
      assert.deepEqual(entry.errors, [], 'unexpected browser exception')
    } finally {
      await entry.context.close()
    }
  }
})

after(async () => {
  await browser?.close()
})

test('clearing the existing tracker setting disables injection and survives refresh', async () => {
  const { page } = await client()
  assert.equal((await rpc('session-get'))['default-trackers'], '')
  const input = await settingsDialog(page)
  await input.fill('')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await message(page, 'Saved successfully')
  assert.equal((await rpc('session-get'))['default-trackers'], '')
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('setting')).defaultTrackers), [])
  await page.reload()
  await page.getByPlaceholder('Search torrents...').waitFor()
  await upload(page, fixture.records.public.path)
  await message(page, 'Added successfully')
  assert.deepEqual((await torrents())[0].trackers.map(t => t.announce), [fixture.announce])
})

test('configured browser defaults never add public trackers to a private torrent or its duplicate', async () => {
  const { page, traffic } = await client({ defaultTrackers: [fixture.extra] })
  await upload(page, fixture.records.private.path)
  await message(page, 'Added successfully')
  const torrent = (await torrents())[0]
  assert.equal(torrent.isPrivate, true)
  assert.deepEqual(torrent.trackers.map(t => t.announce), [fixture.announce])
  await upload(page, fixture.records.private.path)
  await message(page, 'Torrent already exists')
  assert.equal((await torrents()).length, 1)
  assert(!traffic.some(t => t.request.arguments?.trackerAdd), 'private torrent was mutated with trackerAdd')
})

test('fresh browser public tracker injection is disabled by default', async () => {
  const { page, traffic } = await client()
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('setting')).defaultTrackers), [])
  await upload(page, fixture.records.public.path)
  await message(page, 'Added successfully')
  assert.deepEqual((await torrents())[0].trackers.map(t => t.announce), [fixture.announce])
  assert(!traffic.some(t => t.request.arguments?.trackerAdd))
})

test('existing low-level empty browser defaults disable injection without a patch', async () => {
  const { page, traffic } = await client({ defaultTrackers: [] })
  await upload(page, fixture.records.private.path)
  await message(page, 'Added successfully')
  const torrent = (await torrents())[0]
  assert.equal(torrent.isPrivate, true)
  assert.deepEqual(torrent.trackers.map(t => t.announce), [fixture.announce])
  assert(!traffic.some(t => t.request.arguments?.trackerAdd))
})

test('private magnet receives no extra trackers while its metadata is unresolved', async () => {
  const { page, traffic } = await client({ defaultTrackers: [fixture.extra] })
  await page.locator('button').nth(1).click()
  await page.locator('.n-dialog textarea').fill(fixture.records.private.magnet)
  // The upstream Start Directly switch defaults to enabled, regardless of the session default.
  await page.getByRole('button', { name: 'Add', exact: true }).click()
  await message(page, 'Added successfully')
  assert(!traffic.some(t => t.request.arguments?.trackerAdd), 'unresolved magnet was given extra trackers')
  // Transmission 4.1.3 deliberately does not share private-torrent metadata.
  // A successful local announce still gives us a real unresolved private magnet.
  const current = await eventually(torrents, ts => ts[0]?.trackerStats[0]?.lastAnnounceSucceeded)
  assert.equal(current[0].metadataPercentComplete, 0)
  assert.deepEqual(current[0].trackers.map(t => t.announce), [fixture.announce])
  assert(!traffic.some(t => t.request.arguments?.trackerAdd))
})

test('public magnet retrieves real metadata without injecting trackers while unresolved', async () => {
  const { page, traffic } = await client({ defaultTrackers: [fixture.extra] })
  await page.locator('button').nth(1).click()
  await page.locator('.n-dialog textarea').fill(fixture.records.public.magnet)
  await page.getByRole('button', { name: 'Add', exact: true }).click()
  await message(page, 'Added successfully')
  assert(!traffic.some(t => t.request.arguments?.trackerAdd), 'unresolved magnet was given extra trackers')
  const current = await eventually(torrents, ts => ts[0]?.metadataPercentComplete === 1)
  assert.equal(current[0].isPrivate, false)
  assert.deepEqual(current[0].trackers.map(t => t.announce), [fixture.announce])
  assert(!traffic.some(t => t.request.arguments?.trackerAdd))
})

test('configured browser defaults still apply to a known public torrent', async () => {
  const { page, traffic } = await client({ defaultTrackers: [fixture.extra] })
  await upload(page, fixture.records.public.path)
  await message(page, 'Added successfully')
  const torrent = (await torrents())[0]
  assert.equal(torrent.isPrivate, false)
  assert.deepEqual(torrent.trackers.map(t => t.announce).sort(), [fixture.announce, fixture.extra].sort())
  assert(traffic.some(t => t.request.arguments?.trackerAdd?.includes(fixture.extra)))
  assert(traffic.some(t => t.status === 409), 'browser session negotiation was not exercised')
})

test('failed privacy lookup does not inject trackers or misreport a successful add as failed', async () => {
  const entry = await client({ defaultTrackers: [fixture.extra] })
  await entry.page.route(fixture.rpc, async route => {
    const body = JSON.parse(route.request().postData())
    if (body.method === 'torrent-get' && body.arguments.fields.length === 2 && body.arguments.fields.includes('isPrivate')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ arguments: {}, result: 'fixture lookup failure' }) })
    }
    return route.fallback()
  })
  await upload(entry.page, fixture.records.public.path)
  await message(entry.page, 'Added successfully')
  assert.deepEqual((await torrents())[0].trackers.map(t => t.announce), [fixture.announce])
  assert(!entry.traffic.some(t => t.request.arguments?.trackerAdd))
})

test('malformed upload shows failure and leaves the torrent count unchanged', async () => {
  const { page, traffic } = await client()
  await upload(page, fixture.invalid)
  await message(page, 'Failed to add')
  assert.equal((await torrents()).length, 0)
  assert.equal(await page.getByText('Added successfully', { exact: true }).count(), 0)
  assert(traffic.some(t => t.request.method === 'torrent-add' && t.response?.result === 'unrecognized info'))
})

test('batch upload distinguishes one valid torrent from one rejected file', async () => {
  const { page } = await client({ defaultTrackers: [] })
  await upload(page, [fixture.records.public.path, fixture.invalid])
  await message(page, 'Added 1, 0 already existed, 1 failed')
  assert.equal((await torrents()).length, 1)
  assert.equal(await page.locator('.n-dialog input[type=file]').count(), 1)
})

test('relative move rejection shows failure; correcting the path moves actual data', async () => {
  const { page, traffic } = await client({ defaultTrackers: [] })
  await upload(page, fixture.records.public.path)
  await message(page, 'Added successfully')
  // Wait for the canvas row to be painted before selecting its checkbox.
  const moveButton = page.locator('button').nth(8)
  for (let attempt = 0; attempt < 30 && await moveButton.isDisabled(); attempt++) {
    await page.waitForTimeout(100)
    await page.mouse.click(236, 103)
  }
  await page.locator('button').nth(8).click()
  const input = page.getByPlaceholder('Enter new directory', { exact: true })
  await input.fill('relative-test')
  await page.getByRole('button', { name: 'Confirm', exact: true }).click()
  await message(page, 'Failed to change directory')
  assert.equal((await torrents())[0].downloadDir, '/data/downloads')
  assert(traffic.some(t => t.request.method === 'torrent-set-location' && t.response?.result === 'new location path is not absolute'))
  await input.fill('/data/moved/nested')
  await page.getByRole('button', { name: 'Confirm', exact: true }).click()
  await message(page, 'Directory changed successfully')
  await eventually(torrents, ts => ts[0]?.downloadDir === '/data/moved/nested')
  const hash = execFileSync(fixture.docker, ['exec', fixture.container, 'sha256sum', `/data/moved/nested/${fixture.records.public.name}`], { encoding: 'utf8' }).trim().split(/\s+/)[0]
  assert.equal(hash, fixture.digest)
  execFileSync(fixture.docker, ['exec', fixture.container, 'test', '!', '-e', `/data/downloads/${fixture.records.public.name}`])
})

test('rejected settings save does not update the browser tracker defaults', async () => {
  const { page } = await client({ defaultTrackers: [fixture.extra] })
  const input = await settingsDialog(page)
  await input.fill(fixture.announce)
  await page.route(fixture.rpc, route => {
    const body = JSON.parse(route.request().postData())
    return body.method === 'session-set'
      ? route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ arguments: {}, result: 'fixture settings rejection' }) })
      : route.fallback()
  })
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await message(page, 'Failed to save')
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('setting')).defaultTrackers), [fixture.extra])
  assert.equal((await rpc('session-get'))['default-trackers'], '')
})

for (const route of ['settings', 'login']) {
  test(`cold ${route} hash route and refresh work without a service worker`, async () => {
    const entry = await client({}, `#/${route}`)
    assert.equal(entry.response.status(), 200)
    assert.equal(entry.response.fromServiceWorker(), false)
    // An authenticated visit to Login intentionally redirects to the dashboard.
    const content = route === 'settings'
      ? entry.page.getByRole('heading', { name: 'Settings', exact: true })
      : entry.page.getByPlaceholder('Search torrents...')
    await content.waitFor()
    assert(new URL(entry.page.url()).hash.startsWith(route === 'settings' ? '#/settings' : '#/'))
    const response = await entry.page.reload()
    assert.equal(response.status(), 200)
    assert.equal(response.fromServiceWorker(), false)
    await content.waitFor()
  })
}

test('cold login route and refresh show the form when RPC credentials are invalid', async () => {
  const entry = await client({ savePassword: true, savedAuth: Buffer.from('fixture:wrong-password').toString('base64') }, '#/login')
  assert.equal(entry.response.status(), 200)
  await entry.page.getByRole('heading', { name: 'Transmission Login', exact: true }).waitFor()
  const response = await entry.page.reload()
  assert.equal(response.status(), 200)
  assert.equal(response.fromServiceWorker(), false)
  await entry.page.getByRole('heading', { name: 'Transmission Login', exact: true }).waitFor()
  assert(new URL(entry.page.url()).hash.startsWith('#/login'))
})
