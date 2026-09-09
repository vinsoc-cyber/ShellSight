import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ComponentsDoc, RuleSet } from '../api/types'
import { Generate, blockedBecause, ruleSetNeed, viewReason } from './Generate'

// The declaration is the SCANNER's, read out of the release -- this form carries no copy of it
// (G5). windows-amd64 is the interesting target: three views this console will not offer, and
// exactly one of them states a host requirement of its own.
const windowsDoc: ComponentsDoc = {
  schema_version: '1',
  target: 'windows-amd64',
  release: 'v1.0.0-231',
  always: ['shellsight.exe'],
  views: {
    disk: { binaries: ['diskprobe.exe'], data: ['kb/rules/own'], rules: true },
    'java-mem': {
      binaries: ['javamem.jar'],
      rules: false,
      host_requires: 'a Java runtime on the target host',
    },
    'dotnet-mem': { binaries: ['dotnetmem.exe'], rules: false },
  },
}

const SETS: RuleSet[] = [
  { id: 9, name: 'sweep-acme', version: 3, created_by: 'x', frozen_at: '2026-09-01T00:00:00Z',
    frozen_by: 'x', yarc_sha256: 'a'.repeat(64) },
  // A draft. The server refuses one -- "this rule set is not frozen and has no compiled blob" --
  // so the form must not offer it.
  { id: 10, name: 'draft-set', version: null, created_by: 'x', frozen_at: null },
]

type ServerOpts = {
  doc?: ComponentsDoc
  count?: number
  releases?: unknown[]
  sets?: RuleSet[]
  createStatus?: number
  createError?: string
}

// Stubs fetch rather than mocking ../api, which is what every other route test here does. It also
// tests more: the real api/index.ts builds the URLs, and the download link comes from the real
// api.builds.downloadURL rather than from a stand-in the test wrote itself.
function server(opts: ServerOpts = {}) {
  const sent: { url: string; body: unknown }[] = []
  const ok = (body: unknown) =>
    Promise.resolve({
      ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve(body),
    } as Response)

  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST' && url === '/api/builds') {
        sent.push({ url, body: JSON.parse(String(init?.body)) })
        const status = opts.createStatus ?? 201
        if (status >= 400) {
          return Promise.resolve({
            ok: false, status, statusText: 'ERR',
            json: () => Promise.resolve({ error: opts.createError ?? 'refused' }),
          } as Response)
        }
        return Promise.resolve({
          ok: true, status: 201, statusText: 'Created',
          json: () => Promise.resolve({
            id: 7, build_id: 'b-7f3a91c02d55', release_id: 1, rule_set_id: 9, views: ['disk'],
            sha256: 'b'.repeat(64), size_bytes: 4096,
            generated_at: '2026-09-04T10:00:00Z', generated_by: 'x',
          }),
        } as Response)
      }
      if (url === '/api/releases') {
        return ok(opts.releases ?? [{
          id: 1, version: 'v1.0.0-231', target: 'windows-amd64',
          published_at: '2026-09-01T00:00:00Z', published_by: 'v.quannh67',
        }])
      }
      if (url.endsWith('/components')) return ok(opts.doc ?? windowsDoc)
      if (url.endsWith('/resolved-count')) return ok({ count: opts.count ?? 5872 })
      if (url === '/api/rulesets') return ok(opts.sets ?? SETS)
      throw new Error('unstubbed ' + method + ' ' + url)
    }),
  )
  return { sent }
}

function show() {
  return render(
    <MemoryRouter>
      <Generate />
    </MemoryRouter>,
  )
}

// Spec 7: only disk is selectable, and every other view is shown DISABLED WITH ITS REASON. Hiding
// would imply the capability does not exist.
test('offers disk and shows every other view disabled, with a reason', async () => {
  server()
  show()
  const disk = (await screen.findByLabelText(/^disk$/i)) as HTMLInputElement
  expect(disk.disabled).toBe(false)
  expect(disk.checked).toBe(true)

  for (const name of ['java-mem', 'dotnet-mem']) {
    const box = screen.getByLabelText(name) as HTMLInputElement
    expect(box.disabled).toBe(true)
    expect(box.checked).toBe(false)
  }
  // The reason must be ON THE PAGE, not merely implied by the disabled state.
  expect(screen.getByText(/not a v1 claim/i)).toBeTruthy()
})

// Spec 7 names this one concretely: Windows java-mem's reason is its host requirement, which comes
// from components.json rather than from a string this form carries.
test("java-mem's reason is the host requirement the declaration states", async () => {
  server()
  show()
  await screen.findByLabelText(/^disk$/i)
  expect(screen.getByText(/a Java runtime on the target host/i)).toBeTruthy()
})

test('shows the resolved rule count before the button', async () => {
  server({ count: 5872 })
  show()
  expect(await screen.findByText(/resolves to 5,872 rules/i)).toBeTruthy()
})

// G7, and the promise SelectionEditor.tsx has been making to analysts since before the server
// could keep it.
test('a rule set resolving to zero rules blocks generation and says so', async () => {
  server({ count: 0 })
  show()
  const button = (await screen.findByRole('button', { name: /generate/i })) as HTMLButtonElement
  await waitFor(() => expect(screen.getByText(/no rules/i)).toBeTruthy())
  expect(button.disabled).toBe(true)
})

// Every set appears; a draft appears DISABLED. This previously asserted the picker offered only
// frozen sets -- i.e. that a draft was hidden -- which made the console silently answer a different
// question than the analyst asked. Retargeted rather than deleted, so the behaviour change is
// visible in the history.
test('the rule-set picker lists every set, with drafts disabled', async () => {
  server()
  show()
  const picker = (await screen.findByRole('combobox', { name: /rule set/i })) as HTMLSelectElement
  const options = Array.from(picker.options)
  expect(options.map((o) => o.textContent)).toEqual([
    'sweep-acme v3',
    'draft-set — not frozen, so it has no compiled blob to carry',
  ])
  expect(options.map((o) => o.disabled)).toEqual([false, true])
})

test('generating posts the selection and then offers the download', async () => {
  const { sent } = server()
  show()
  await screen.findByText(/resolves to 5,872 rules/i)
  fireEvent.click(await screen.findByRole('button', { name: /generate/i }))

  await waitFor(() => expect(sent).toHaveLength(1))
  // The exact body, not a subset: an extra field here is one the server would have to interpret.
  expect(sent[0]?.body).toEqual({
    release_id: 1,
    rule_set_id: 9,
    views: ['disk'],
    // No scope typed, so the build bakes none and the agent auto-discovers on the host.
    scan_scope: [],
    // Unchosen, so "": the server writes JSON null and the scanner's built-in default wins.
    output_format: '',
    process_priority: '',
  })

  // The id, size and SHA-256 after, per spec 7.
  expect(await screen.findByText('b-7f3a91c02d55')).toBeTruthy()
  expect(screen.getByText(/4,096 bytes/)).toBeTruthy()
  expect(screen.getByText('b'.repeat(64))).toBeTruthy()

  // An <a href>, not a fetch: api/http.ts always calls res.json(), so a zip cannot come back
  // through the wrapper.
  const link = screen.getByRole('link', { name: /download/i })
  expect(link.getAttribute('href')).toBe('/api/builds/7/download')
})

test('a refused generation shows the server reason and offers no download', async () => {
  server({
    createStatus: 422,
    createError: 'this release declares "diskprobe.exe" but does not hold it',
  })
  show()
  await screen.findByText(/resolves to 5,872 rules/i)
  fireEvent.click(await screen.findByRole('button', { name: /generate/i }))
  expect(await screen.findByText(/does not hold it/i)).toBeTruthy()
  expect(screen.queryByRole('link', { name: /download/i })).toBeNull()
})

// Deselecting every view is NOT the same thing as a selection that carries no YARA, and the
// difference is not cosmetic. Array.prototype.every over an empty list returns TRUE, so the
// obvious formulation of "no selected view scans with YARA" reports "not applicable" about a
// build that carries nothing at all -- and would let the analyst generate it.
test('deselecting every view blocks generation and does not read as not applicable', async () => {
  server()
  show()
  const disk = (await screen.findByLabelText(/^disk$/i)) as HTMLInputElement
  fireEvent.click(disk)
  await waitFor(() => expect(screen.getByText(/at least one view/i)).toBeTruthy())
  expect(screen.queryByText(/not applicable/i)).toBeNull()
  const button = screen.getByRole('button', { name: /generate/i }) as HTMLButtonElement
  expect(button.disabled).toBe(true)
})

// "not applicable" is derived from the declaration's rules flag, never from a view's NAME. A
// release whose disk view declares rules:false must read not-applicable through the same code path
// that will carry a memory view the day one is offered -- which is what makes enabling one a
// config change rather than a form change.
test('a selection the declaration says carries no YARA reads not applicable', async () => {
  const noYara: ComponentsDoc = {
    ...windowsDoc,
    views: { ...windowsDoc.views, disk: { binaries: ['diskprobe.exe'], rules: false } },
  }
  server({ doc: noYara })
  show()
  await screen.findByLabelText(/^disk$/i)
  expect(await screen.findByText(/not applicable/i)).toBeTruthy()
  // And no rule-set control at all: there is nothing for a compiled set to be part of.
  expect(screen.queryByRole('combobox', { name: /rule set/i })).toBeNull()
  const button = screen.getByRole('button', { name: /generate/i }) as HTMLButtonElement
  expect(button.disabled).toBe(false)
})

test('ruleSetNeed separates an empty selection from one that carries no YARA', () => {
  expect(ruleSetNeed(windowsDoc, ['disk'])).toBe('required')
  expect(ruleSetNeed(windowsDoc, ['java-mem'])).toBe('not-applicable')
  // One rules view in the selection is enough to need a set.
  expect(ruleSetNeed(windowsDoc, ['disk', 'java-mem'])).toBe('required')
  expect(ruleSetNeed(windowsDoc, [])).toBe('no-views')
})

test('blockedBecause names every refusal the server would make, and only those', () => {
  const base = { doc: windowsDoc, views: ['disk'], ruleSetID: 9, resolvedCount: 5872 }
  expect(blockedBecause(base)).toBeNull()
  expect(String(blockedBecause({ ...base, doc: null }))).toMatch(/declaration/i)
  expect(String(blockedBecause({ ...base, views: [] }))).toMatch(/at least one view/i)
  expect(String(blockedBecause({ ...base, ruleSetID: null }))).toMatch(/frozen rule set/i)
  expect(String(blockedBecause({ ...base, resolvedCount: null }))).toMatch(/resolve/i)
  expect(String(blockedBecause({ ...base, resolvedCount: 0 }))).toMatch(/no rules/i)
  // A selection carrying no YARA needs no rule set, so a missing one is not a refusal.
  expect(
    blockedBecause({ doc: windowsDoc, views: ['java-mem'], ruleSetID: null, resolvedCount: null }),
  ).toBeNull()
})

test('viewReason prefers the declaration host requirement over the generic reason', () => {
  expect(viewReason(windowsDoc, 'disk')).toBeNull()
  expect(viewReason(windowsDoc, 'java-mem')).toBe('a Java runtime on the target host')
  expect(viewReason(windowsDoc, 'dotnet-mem')).toBe('not a v1 claim')
})

// A draft rule set must be SHOWN, disabled, with its reason -- not filtered out of existence.
//
// The spec states this for views: "never hidden. Hiding implies the capability does not exist,
// while showing it disabled says it exists and is deliberately not offered." A hidden draft made
// the console silently answer a different question than the analyst asked: three sets exist, two
// appear, and nothing says why the third is gone.
test('an unfrozen rule set is offered disabled, with the reason it cannot be used', async () => {
  server()
  show()
  await screen.findByLabelText(/^disk$/i)

  const draft = (await screen.findByRole('option', { name: /draft-set/i })) as HTMLOptionElement
  expect(draft.disabled).toBe(true)
  // The reason has to be legible where the analyst is looking, not inferred from the grey.
  expect(draft.textContent).toMatch(/not frozen/i)
})

test('a frozen set is still selectable alongside it', async () => {
  server()
  show()
  await screen.findByLabelText(/^disk$/i)
  const frozen = (await screen.findByRole('option', { name: /sweep-acme/i })) as HTMLOptionElement
  expect(frozen.disabled).toBe(false)
})

// spec 6.6 bakes these two as the build's DEFAULT, and the API already accepts them -- agent.json
// carries "output_format" and "process_priority". The form not offering them meant the only way to
// set them was curl.
test('the baked output format and process priority are offered and posted', async () => {
  const s = server()
  show()
  // The count, not the checkbox: the button stays disabled until it arrives, so clicking on the
  // checkbox alone races the fetch and lands on a disabled control.
  await screen.findByText(/resolves to 5,872 rules/i)

  fireEvent.change(screen.getByLabelText(/output format/i), { target: { value: 'json' } })
  fireEvent.change(screen.getByLabelText(/process priority/i), { target: { value: 'low' } })
  fireEvent.click(screen.getByRole('button', { name: /generate/i }))

  await waitFor(() => expect(s.sent.length).toBe(1))
  const body = s.sent[0]?.body as Record<string, unknown>
  expect(body.output_format).toBe('json')
  expect(body.process_priority).toBe('low')
})

// "" means the analyst chose nothing, and the server renders that as JSON null so the scanner's
// built-in default wins. Sending "" as a value would be a value the scanner rejects.
test('leaving a baked setting unchosen posts nothing for it', async () => {
  const s = server()
  show()
  // See above: await the count, or the click lands on a still-disabled button.
  await screen.findByText(/resolves to 5,872 rules/i)
  fireEvent.click(screen.getByRole('button', { name: /generate/i }))

  await waitFor(() => expect(s.sent.length).toBe(1))
  const body = s.sent[0]?.body as Record<string, unknown>
  expect(body.output_format ?? '').toBe('')
  expect(body.process_priority ?? '').toBe('')
})

// The baked scan scope: one path per line, posted as a list. A comma-separated box would be
// ambiguous, because a webroot can contain a space but not a newline.
test('the baked scan scope is offered and posted as a list', async () => {
  const s = server()
  show()
  // The count, not the checkbox: the button stays disabled until it arrives, so clicking on the
  // checkbox alone races the fetch and lands on a disabled control.
  await screen.findByText(/resolves to 5,872 rules/i)

  fireEvent.change(screen.getByLabelText(/scan scope/i), {
    target: { value: '/var/www\n  /srv/http  \n\n' },
  })
  fireEvent.click(screen.getByRole('button', { name: /generate/i }))

  await waitFor(() => expect(s.sent.length).toBe(1))
  const body = s.sent[0]?.body as Record<string, unknown>
  // Trimmed, and the blank line dropped -- a blank entry is one the scanner rejects.
  expect(body.scan_scope).toEqual(['/var/www', '/srv/http'])
})

test('an empty scan scope bakes none, so the agent auto-discovers', async () => {
  const s = server()
  show()
  // See above: await the count, or the click lands on a still-disabled button.
  await screen.findByText(/resolves to 5,872 rules/i)
  fireEvent.click(screen.getByRole('button', { name: /generate/i }))

  await waitFor(() => expect(s.sent.length).toBe(1))
  const body = s.sent[0]?.body as Record<string, unknown>
  expect(body.scan_scope).toEqual([])
})

// The text has to say that naming a path turns discovery OFF, not merely what an empty box does.
// The analyst read the previous wording as additive -- "auto-discover AND these paths" -- which is
// the opposite of what discover.Discover does: an explicit list returns before any mechanism runs.
test('the scan-scope help says naming a path replaces discovery', async () => {
  server()
  show()
  await screen.findByLabelText(/^disk$/i)
  expect(screen.getByText(/turns auto-discovery off/i)).toBeTruthy()
  expect(screen.getByText(/discovers webroots from the host/i)).toBeTruthy()
})
