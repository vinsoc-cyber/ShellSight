import { actor } from '../lib/actor'

// ApiError carries the HTTP status, because callers branch on it: 422 means the console rejected
// the CONTENT (a rule that will not compile) and belongs inline next to the editor, while 4xx/5xx
// otherwise means the request or the server failed and belongs in a banner.
export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }

  // A well-formed request whose content the console refused.
  get rejectedContent(): boolean {
    return this.status === 422
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers = new Headers({ Accept: 'application/json' })
  const name = actor()
  if (name) headers.set('X-Console-Actor', name)
  if (body !== undefined) headers.set('Content-Type', 'application/json')

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (!res.ok) {
    throw new ApiError(await errorMessage(res), res.status)
  }
  // 204 carries no body; parsing it would turn a successful delete into a thrown error.
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string }
    if (body?.error) return body.error
  } catch {
    // A non-JSON error body tells us nothing useful; the status is the honest answer.
  }
  return `${res.status} ${res.statusText}`.trim()
}

// postForm sends multipart/form-data, which request() cannot: it JSON.stringifies the body and
// sets Content-Type itself. Here the browser MUST set Content-Type, because only it knows the
// multipart boundary -- setting it by hand produces a body the server cannot parse.
export async function postForm<T>(path: string, form: FormData): Promise<T> {
  const headers = new Headers({ Accept: 'application/json' })
  const name = actor()
  if (name) headers.set('X-Console-Actor', name)

  const res = await fetch(path, { method: 'POST', headers, body: form })
  if (!res.ok) {
    throw new ApiError(await errorMessage(res), res.status)
  }
  return (await res.json()) as T
}

export const get = <T>(path: string) => request<T>('GET', path)
export const post = <T>(path: string, body: unknown) => request<T>('POST', path, body)
export const put = <T>(path: string, body: unknown) => request<T>('PUT', path, body)
export const del = (path: string) => request<void>('DELETE', path)
