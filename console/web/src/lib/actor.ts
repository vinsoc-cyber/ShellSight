// The analyst's self-declared name, sent as X-Console-Actor for attribution.
//
// This is ATTRIBUTION, NOT AUTHENTICATION. The API accepts whatever this header says and falls
// back to the string "unknown". Anyone who can reach the port can claim any name. The console
// binds loopback by default for exactly that reason, and the UI says so where the name is set --
// displaying an unverified name as though it were an identity would misrepresent the console's
// own guarantees.

const KEY = 'shellsight.actor'

export function actor(): string {
  try {
    return localStorage.getItem(KEY) ?? ''
  } catch {
    // Private windows and blocked site data both throw here. An empty name is correct: the API
    // records "unknown", which is honest.
    return ''
  }
}

export function setActor(name: string): void {
  try {
    localStorage.setItem(KEY, name.trim())
  } catch {
    // Nothing to do -- the name simply will not persist across reloads.
  }
}
