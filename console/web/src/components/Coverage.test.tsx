import { render, screen } from '@testing-library/react'
import type { Coverage as C } from '../api/types'
import { CoveragePanel } from './Coverage'

const ran = (over: Partial<C> = {}): C => ({
  view: 'disk',
  status: 'ran',
  targets_scanned: 1200,
  non_regular: 0,
  unreadable: 0,
  oversize_skipped: 0,
  no_language_detector: 0,
  ...over,
})

test('shows what was actually scanned', () => {
  render(<CoveragePanel coverage={[ran()]} />)
  expect(screen.getByText(/1,200|1200/)).toBeTruthy()
  expect(screen.getByText('disk')).toBeTruthy()
})

test('an incomplete view is called out, with the counts that make it incomplete', () => {
  // A "clean" verdict over a webroot where 398 files were unreadable is not clean; it usually
  // means the scan ran without the permissions it needed. That is worth more to an analyst than
  // the word clean, so the panel surfaces it rather than burying it in a tooltip.
  render(<CoveragePanel coverage={[ran({ unreadable: 398 })]} />)
  // The count appears twice by design: once as the summary, once in the breakdown that says WHY.
  // A bare /398/ therefore matches two elements and getByText throws. Assert both precisely --
  // which is stronger anyway, since it pins the reason and not just the number.
  expect(screen.getByText(/398.*not complete/)).toBeTruthy()
  expect(screen.getByText(/398 unreadable/)).toBeTruthy()
})

test('a view that was never shipped reads as absent, not as failed', () => {
  // Coverage.Status "n/a" means "not included in this build". Rendering that as a failure would
  // make every disk-only agent look broken.
  render(
    <CoveragePanel
      coverage={[{ ...ran(), view: 'java-mem', status: 'n/a', targets_scanned: 0 }]}
    />,
  )
  expect(screen.getByText(/not included in this build/i)).toBeTruthy()
  expect(screen.queryByText(/failed/i)).toBeNull()
})

test('a failed view is distinguished from an absent one and shows its reason', () => {
  render(
    <CoveragePanel
      coverage={[{ ...ran(), status: 'failed', reason: 'attach denied', targets_scanned: 0 }]}
    />,
  )
  expect(screen.getByText(/failed/i)).toBeTruthy()
  expect(screen.getByText(/attach denied/)).toBeTruthy()
})

test('no coverage at all says so, and does not render an empty reassuring panel', () => {
  // Silence about coverage is the failure mode this whole panel exists to prevent.
  render(<CoveragePanel coverage={[]} />)
  expect(screen.getByText(/reported no coverage/i)).toBeTruthy()
})
