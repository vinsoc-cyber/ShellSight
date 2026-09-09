// The three states every screen has. Sharing them keeps an empty console from looking like a
// broken one, which is the most common way an internal tool loses its users' trust.

export function Loading({ what }: { what: string }) {
  return (
    <p className="muted" role="status">
      Loading {what}…
    </p>
  )
}

export function ErrorBox({ error, retry }: { error: Error; retry?: () => void }) {
  return (
    <div className="errbox" role="alert">
      <strong>Could not load this.</strong> <span>{error.message}</span>
      {retry && (
        <button type="button" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="muted empty">{children}</p>
}
