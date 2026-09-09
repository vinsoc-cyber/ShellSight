import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Layout } from './Layout'

function show() {
  return render(
    <MemoryRouter>
      <Layout />
    </MemoryRouter>,
  )
}

test('offers the three sections an analyst works in', () => {
  show()
  expect(screen.getByRole('link', { name: /cases/i })).toBeTruthy()
  expect(screen.getByRole('link', { name: /rules/i })).toBeTruthy()
  expect(screen.getByRole('link', { name: /rule sets/i })).toBeTruthy()
})

test('says the name is attribution and not authentication', () => {
  // The API takes this header at its word. A console that presents an unverified name as an
  // identity misrepresents its own guarantees, so the screen states the limit in words.
  show()
  expect(screen.getByText(/not authentication/i)).toBeTruthy()
})

test('the actor field is editable and persists what is typed', () => {
  show()
  const field = screen.getByLabelText(/your name/i) as HTMLInputElement
  expect(field).toBeTruthy()
  expect(field.tagName).toBe('INPUT')
})
