const assert = require('node:assert/strict')
const { before, after, test } = require('node:test')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const { chromium } = require('../node_modules/playwright')
const fixture = JSON.parse(fs.readFileSync(process.env.WEBUI_TEST_CONFIG, 'utf8'))
const evidence = process.env.WEBUI_TEST_EVIDENCE
const modern = fixture.ui === 'transmission-web'
const legacy = fixture.ui === 'transmission-web-legacy'
const auth = 'Basic ' + Buffer.from('fixture:fixture-password').toString('base64')
let browser, context, page, sessionId = ''
const traffic = [], errors = [], results = {}
function docker(...args) { return execFileSync(fixture.docker, args, { encoding: 'utf8' }).trim() }
async function rpc(method, args = {}) {
  for (let i = 0; i < 2; i++) {
    const response = await fetch(fixture.rpc, { method: 'POST', headers: { Authorization: auth,
      'Content-Type': 'application/json', 'X-Transmission-Session-Id': sessionId },
      body: JSON.stringify({ method, arguments: args }) })
    if (response.status === 409) { sessionId = response.headers.get('X-Transmission-Session-Id'); continue }
    assert.equal(response.status, 200)
    const data = await response.json(); assert.equal(data.result, 'success', JSON.stringify(data)); return data.arguments
  }
  throw new Error('RPC session negotiation failed')
}
async function torrents() { return (await rpc('torrent-get', { fields: ['id', 'name', 'hashString', 'downloadDir', 'percentDone', 'status', 'isPrivate', 'trackers', 'files', 'peers', 'metadataPercentComplete'] })).torrents }
async function until(read, check) {
  const deadline = Date.now() + 30000
  while (Date.now() < deadline) { const value = await read(); if (check(value)) return value; await new Promise(r => setTimeout(r, 100)) }
  throw new Error('Daemon readback timed out')
}
async function snapshot(label) {
  fs.writeFileSync(path.join(evidence, label + '.html'), await page.content())
  await page.screenshot({ path: path.join(evidence, label + '.png') })
}
async function load() {
  const response = await page.goto(fixture.base)
  assert.equal(response.status(), 200)
  await page.locator(modern ? 'input[placeholder="Search torrents..."]' : legacy ? '#toolbar_add_torrents' : '#toolbar-open').waitFor()
  await until(async () => traffic, ts => ts.some(t => ['session-get', 'session_get'].includes(t.request.method) && (t.response?.result === 'success' || t.response?.result?.version)))
}
before(async () => {
  assert.equal((await rpc('session-get')).version, '4.1.3 (838877323f)')
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] })
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'en-US', serviceWorkers: 'block',
    httpCredentials: { username: 'fixture', password: 'fixture-password' } })
  await context.addInitScript(() => {
    if (location.protocol !== 'http:') return
    if (!localStorage.getItem('setting')) localStorage.setItem('setting', JSON.stringify({ language: 'en-US', polling: { sessionInterval: 1, torrentInterval: 1, torrentDetailInterval: 1 } }))
  })
  await context.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort())
  page = await context.newPage(); page.setDefaultTimeout(10000)
  page.on('dialog', dialog => dialog.accept())
  page.on('pageerror', error => errors.push(error.message))
  page.on('response', async response => {
    if (!response.url().startsWith(fixture.rpc)) return
    try {
      const request = response.request().postData() ? JSON.parse(response.request().postData()) : { method: response.request().method() }; if (request.arguments?.metainfo) request.arguments.metainfo = '[fixture]'
      const body = response.status() === 200 ? await response.json() : null
      if (body?.arguments?.['session-id']) body.arguments['session-id'] = '[fixture]'
      traffic.push({ request, status: response.status(), response: body })
    } catch { }
  })
  await load()
})
after(async () => {
  try { await snapshot('final'); fs.writeFileSync(path.join(evidence, 'browser.json'), JSON.stringify({ ui: fixture.ui, results, traffic, errors }, null, 2)) }
  finally { await browser?.close() }
})
function check(name, fn) {
  test(name, async () => {
    results[name] = 'FAIL'
    try {
      await fn()
      assert.deepEqual(errors, [])
      results[name] = 'PASS'
    } catch (error) { console.error(name, error.message); throw error }
    finally { await snapshot(name.replace(/[^a-z0-9]+/gi, '-').slice(0, 70)) }
  })
}
async function add(magnet = false, directory = '/data/downloads') {
  if (modern) {
    await page.locator('button').nth(magnet ? 1 : 2).click()
    if (magnet) await page.locator('.n-dialog textarea').fill(fixture.records.public.magnet)
    else await page.locator('input[type=file]').setInputFiles(fixture.records.public.path)
    await page.getByPlaceholder('Select or enter download directory', { exact: true }).fill(directory)
    if (!magnet) await page.locator('.n-dialog .n-switch').first().click()
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await page.locator('.n-message__content').filter({ hasText: 'Added successfully' }).waitFor()
  } else if (legacy) {
    await page.locator('#toolbar_add_torrents').click()
    const dialog = page.locator('#dialog-torrent-add')
    if (magnet) await dialog.locator('#torrent_url').fill(fixture.records.public.magnet)
    else await dialog.locator('input[type=file]').setInputFiles(fixture.records.public.path)
    const input = dialog.locator('#download-dir + .textbox input.textbox-text')
    await input.fill('')
    await input.pressSequentially(directory)
    await until(() => dialog.locator('#download-dir + .textbox input.textbox-value').inputValue(), value => value === directory)
    await input.press('Tab')
    await dialog.locator('#chkautostart').setChecked(magnet)
    await dialog.locator('#torrent-button-ok').click()
    await dialog.waitFor({ state: 'hidden' })
  } else {
    await page.locator('#toolbar-open').click()
    if (magnet) await page.locator('input[type=url]').fill(fixture.records.public.magnet)
    else await page.locator('input[type=file]').setInputFiles(fixture.records.public.path)
    await page.locator('#add-dialog-folder-input').fill(directory)
    await page.locator('#auto-start-check').setChecked(magnet)
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await page.locator('#add-dialog-folder-input').waitFor({ state: 'hidden' })
  }
  const current = await until(torrents, ts => ts.length === 1 && ts[0].name === fixture.records.public.name && ts[0].downloadDir === directory)
  assert.deepEqual(current[0].trackers.map(t => t.announce), [fixture.announce])
}
async function select() {
  if (modern) {
    const button = page.locator('button').nth(8)
    for (let i = 0; i < 40 && await button.isDisabled(); i++) { await page.waitForTimeout(100); await page.mouse.click(236, 103) }
    assert.equal(await button.isEnabled(), true)
  } else if (legacy) {
    await page.locator('#m_left .tree-title').filter({ hasText: /^All\b/ }).first().click()
    const row = page.locator('#m_list .datagrid-body .datagrid-row').filter({ hasText: fixture.records.public.name }).first()
    await row.click()
    await row.locator('input[type=checkbox]').setChecked(true)
  } else {
    await page.locator('#torrent-list li').filter({ hasText: fixture.records.public.name }).click()
    await page.locator('#toolbar-delete:enabled').waitFor()
  }
}
async function menu(action) {
  if (modern) { await page.mouse.click(450, 103, { button: 'right' }); await page.getByText(action, { exact: true }).last().click() }
  else { await page.locator('#torrent-list li').first().click({ button: 'right' }); await page.locator(`[data-action="${action}"]:visible`).click() }
}
check('torrent file addition and download directory selection', async () => { await add(); await select() })
check('verification checks actual seeded data', async () => {
  if (modern) await menu('Verify')
  else if (legacy) await page.locator('#toolbar_recheck').click()
  else await menu('verify-selected-torrents')
  await until(async () => traffic, ts => ts.some(t => ['torrent-verify', 'torrent_verify'].includes(t.request.method)))
  await until(torrents, ts => ts[0]?.percentDone === 1 && ![1, 2].includes(ts[0]?.status))
})
check('torrent details render files peers and trackers', async () => {
  if (modern) {
    if (!(await page.locator('.torrent-detail').isVisible())) await page.locator('button').nth(14).click()
    await page.locator('.torrent-detail .n-tabs-tab').filter({ hasText: /^Files$/ }).click()
    await page.locator('.torrent-detail').getByText(fixture.records.public.name, { exact: true }).last().waitFor()
    await page.locator('.torrent-detail .n-tabs-tab').filter({ hasText: /^Peers$/ }).click()
    await page.locator('.torrent-detail').getByText('IP', { exact: true }).waitFor()
    await page.locator('.torrent-detail .n-tabs-tab').filter({ hasText: /^Trackers$/ }).click()
    await page.locator('.torrent-detail').getByText(fixture.announce, { exact: true }).waitFor()
  } else if (legacy) {
    if (!(await page.locator('#torrent-attribute-tabs').isVisible())) await page.locator('#layout_body > .layout-expand-south .layout-button-up').click()
    const tabs = page.locator('#torrent-attribute-tabs .tabs-header .tabs-title')
    await tabs.filter({ hasText: /^Files$/ }).click()
    await page.locator('#torrent-attribute-files').getByText(fixture.records.public.name, { exact: true }).waitFor()
    await tabs.filter({ hasText: /^Peers$/ }).click()
    await page.locator('#torrent-attribute-peers').getByText('IP address', { exact: true }).waitFor()
    await tabs.filter({ hasText: /^Trackers$/ }).click()
    await page.locator('#torrent-attribute-servers').getByText(fixture.announce, { exact: true }).waitFor()
  } else {
    await page.locator('#toolbar-inspector').click()
    await page.locator('#inspector-tab-files').click()
    await page.getByText(fixture.records.public.name, { exact: true }).last().waitFor()
    await page.locator('#inspector-tab-peers').click()
    await page.getByText('Address', { exact: true }).waitFor()
    await page.locator('#inspector-tab-tiers').click()
    await page.locator(`.tier-list-tracker[title="${fixture.announce}"]`).waitFor()
  }
  assert.equal((await torrents())[0].files.length, 1)
})
check('moving data creates a nested destination and preserves bytes', async () => {
  await select()
  if (modern) {
    await page.locator('button').nth(8).click()
    await page.getByPlaceholder('Enter new directory', { exact: true }).fill('/data/moved/nested')
    await page.getByRole('button', { name: 'Confirm', exact: true }).click()
    await page.locator('.n-message__content').filter({ hasText: 'Directory changed successfully' }).waitFor()
  } else if (legacy) {
    await page.locator('#toolbar_changeDownloadDir').click()
    const dialog = page.locator('#dialog-torrent-changeDownloadDir')
    const input = dialog.locator('#download-dir + .textbox input.textbox-text')
    await input.fill('')
    await input.pressSequentially('/data/moved/nested')
    await until(() => dialog.locator('#download-dir + .textbox input.textbox-value').inputValue(), value => value === '/data/moved/nested')
    await input.press('Tab')
    await dialog.locator('#move-data').check()
    await dialog.locator('#torrent-button-ok').click()
    await dialog.waitFor({ state: 'hidden' })
  } else {
    await menu('show-move-dialog')
    await page.locator('#torrent-path').fill('/data/moved/nested')
    await page.locator('.move-dialog').getByRole('button', { name: 'OK', exact: true }).click()
    await page.locator('#torrent-path').waitFor({ state: 'hidden' })
  }
  await until(torrents, ts => ts[0]?.downloadDir === '/data/moved/nested')
  assert.equal(docker('exec', fixture.container, 'sha256sum', '/data/moved/nested/' + fixture.records.public.name).split(/\s/)[0], fixture.digest)
  docker('exec', fixture.container, 'test', '!', '-e', '/data/downloads/' + fixture.records.public.name)
})
check('Transmission settings save through the browser', async () => {
  if (modern) {
    await page.locator('button').nth(13).click()
    await page.locator('.n-dialog .n-tabs-tab').filter({ hasText: /^Other$/ }).click()
    await page.getByPlaceholder('Default tracker list', { exact: true }).fill(fixture.extra)
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await page.locator('.n-message__content').filter({ hasText: 'Saved successfully' }).waitFor()
    assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('setting')).defaultTrackers), [fixture.extra])
  } else if (legacy) {
    await page.locator('#toolbar_config').click()
    await page.locator('#dialog-system-config #start-added-torrents').check()
    await page.locator('#system-config-button-save').click()
    await until(async () => rpc('session-get'), s => s['start-added-torrents'] === true)
    await page.locator('#dialog-system-config').waitFor({ state: 'hidden' })
  } else {
    const previous = (await rpc('session-get'))['alt-speed-enabled']
    await page.locator('#turtle').click()
    await until(async () => rpc('session-get'), s => s['alt-speed-enabled'] !== previous)
  }
})
check('restart preserves selected UI torrents settings and moved data', async () => {
  const saved = await rpc('session-get')
  const initial = (await torrents())[0]
  // Reopen after restart with the same browser storage, without polling a deliberately stopped daemon.
  await page.goto('about:blank')
  docker('stop', '-t', '30', fixture.container); docker('start', fixture.container)
  await until(async () => { try { return await rpc('session-get') } catch { return null } }, s => s?.version?.startsWith('4.1.3'))
  const restored = await rpc('session-get')
  for (const field of ['default-trackers', 'alt-speed-enabled', 'start-added-torrents', 'download-dir']) assert.deepEqual(restored[field], saved[field], field)
  assert.equal((await torrents())[0].hashString, initial.hashString)
  assert.equal((await torrents())[0].downloadDir, '/data/moved/nested')
  assert.equal(docker('exec', fixture.container, 'sha256sum', '/data/moved/nested/' + fixture.records.public.name).split(/\s/)[0], fixture.digest)
  await load()
  if (modern) assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('setting')).defaultTrackers), [fixture.extra])
  await select()
})
check('removing a torrent preserves data when deletion is not requested', async () => {
  if (modern) {
    await page.locator('button').nth(5).click()
    await page.getByRole('button', { name: 'Delete Torrent', exact: true }).click()
  } else if (legacy) {
    await page.locator('#toolbar_remove').click()
    await page.locator('#remove-data').uncheck()
    await page.locator('#torrent-remove-confirm-button-ok').click()
  } else {
    await page.locator('#toolbar-delete').click()
    await page.getByRole('button', { name: 'Remove', exact: true }).click()
  }
  await until(torrents, ts => ts.length === 0)
  assert.equal(docker('exec', fixture.container, 'sha256sum', '/data/moved/nested/' + fixture.records.public.name).split(/\s/)[0], fixture.digest)
  await rpc('session-set', { 'default-trackers': '' })
  if (modern) await page.evaluate(() => { const s = JSON.parse(localStorage.getItem('setting')); s.defaultTrackers = []; localStorage.setItem('setting', JSON.stringify(s)) })
  await load()
})
check('magnet metadata and payload download into a new nested directory', async () => {
  await add(true, '/data/new-download/nested')
  const current = await until(torrents, ts => ts[0]?.metadataPercentComplete === 1 && ts[0]?.percentDone === 1)
  assert.equal(current[0].isPrivate, false)
  assert.equal(docker('exec', fixture.container, 'sha256sum', '/data/new-download/nested/' + fixture.records.public.name).split(/\s/)[0], fixture.digest)
  assert(traffic.some(t => ['torrent-add', 'torrent_add'].includes(t.request.method)))
  assert(traffic.some(t => t.status === 409))
})
