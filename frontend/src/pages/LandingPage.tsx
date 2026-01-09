import { useMemo, useState } from 'react'

type SportKey = 'box-cricket' | 'futsal' | 'basketball' | 'volleyball' | 'table-tennis'

type UpcomingMatch = {
  label: string
  timeLabel: string
}

type LiveMatch = {
  label: string
  left: { score: string; detail: string }
  right: { score: string; detail: string }
}

type SportViewModel = {
  key: SportKey
  name: string
  icon: string
  live: LiveMatch
  upcoming: UpcomingMatch[]
}

export default function LiveScoresPage() {
  const sports: SportViewModel[] = useMemo(
    () => [
      {
        key: 'box-cricket',
        name: 'Box Cricket',
        icon: '🏏',
        live: {
          label: 'B2 v/s B4',
          left: { score: '127/9', detail: '60 balls' },
          right: { score: '24/2', detail: '17 balls' }
        },
        upcoming: [
          { label: 'B4 v/s B10', timeLabel: '6 pm, 28 Feb' },
          { label: 'B8 v/s B5', timeLabel: '6 pm, 28 Feb' }
        ]
      },
      {
        key: 'futsal',
        name: 'Futsal',
        icon: '⚽',
        live: {
          label: 'B1 v/s B3',
          left: { score: '2', detail: 'FT' },
          right: { score: '1', detail: 'FT' }
        },
        upcoming: [
          { label: 'B2 v/s B4', timeLabel: '5 pm, 28 Feb' },
          { label: 'B6 v/s B9', timeLabel: '7 pm, 28 Feb' }
        ]
      },
      {
        key: 'basketball',
        name: 'Basketball',
        icon: '🏀',
        live: {
          label: 'B2 v/s B7',
          left: { score: '48', detail: 'Q3' },
          right: { score: '41', detail: 'Q3' }
        },
        upcoming: [
          { label: 'B4 v/s B8', timeLabel: '6 pm, 28 Feb' },
          { label: 'B1 v/s B5', timeLabel: '7 pm, 28 Feb' }
        ]
      },
      {
        key: 'volleyball',
        name: 'Volleyball',
        icon: '🏐',
        live: {
          label: 'B3 v/s B6',
          left: { score: '1', detail: 'Sets' },
          right: { score: '0', detail: 'Sets' }
        },
        upcoming: [
          { label: 'B2 v/s B5', timeLabel: '6 pm, 28 Feb' },
          { label: 'B7 v/s B10', timeLabel: '7 pm, 28 Feb' }
        ]
      },
      {
        key: 'table-tennis',
        name: 'Table Tennis',
        icon: '🏓',
        live: {
          label: 'B8 v/s B9',
          left: { score: '10', detail: 'Game 2' },
          right: { score: '7', detail: 'Game 2' }
        },
        upcoming: [
          { label: 'B1 v/s B4', timeLabel: '6 pm, 28 Feb' },
          { label: 'B2 v/s B6', timeLabel: '7 pm, 28 Feb' }
        ]
      }
    ],
    []
  )

  const [activeSportKey, setActiveSportKey] = useState<SportKey>('box-cricket')
  const activeSport = sports.find((s) => s.key === activeSportKey) ?? sports[0]

  return (
    <div data-page="live-scores" className="min-h-[100svh] overflow-x-hidden bg-amber-50">
      <header className="sticky top-0 z-10 bg-amber-50/90 pt-[env(safe-area-inset-top)] backdrop-blur">
        <div className="mx-auto max-w-md px-4 pt-4">
          <h1 className="text-center text-2xl font-semibold tracking-wide text-stone-800">
            GHS CARNIVAL
          </h1>
        </div>

        <div className="mx-auto max-w-md px-0 pb-2 pt-3">
          <div className="bg-gradient-to-b from-amber-50 to-amber-100/60">
            <div className="flex gap-2.5 overflow-x-auto overscroll-x-contain px-4 py-2.5 snap-x snap-mandatory">
            {sports.map((sport) => {
              const isActive = sport.key === activeSportKey
              return (
                <button
                  key={sport.key}
                  type="button"
                  onClick={() => setActiveSportKey(sport.key)}
                  className={
                    'shrink-0 snap-start rounded-xl px-1 py-1 transition outline-none focus:outline-none focus-visible:outline-none ' +
                    (isActive
                      ? 'bg-white/70'
                      : 'bg-transparent hover:bg-white/50')
                  }
                  aria-pressed={isActive}
                >
                  <div className="flex w-16 flex-col items-center">
                    <div
                      className={
                        'flex h-11 w-11 items-center justify-center rounded-full ' +
                        (isActive
                          ? 'bg-white'
                          : 'bg-amber-50')
                      }
                      aria-hidden="true"
                    >
                      <span className="text-xl leading-none">{sport.icon}</span>
                    </div>
                    <div className="mt-1.5 text-center text-[11px] font-semibold leading-tight text-stone-900">
                      {sport.name}
                    </div>
                    <div className="mt-1.5 h-1 w-8 rounded-full bg-transparent">
                      <div
                        className={
                          'h-full w-full rounded-full ' +
                          (isActive ? 'bg-stone-900/70' : 'bg-transparent')
                        }
                      />
                    </div>
                  </div>
                </button>
              )
            })}
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-md px-4 pb-[calc(2.5rem+env(safe-area-inset-bottom))]">
        <section className="rounded-2xl border border-amber-200 bg-white p-3 shadow-sm">
          <h2 className="text-center text-2xl font-bold text-stone-900">{activeSport.name}</h2>

          <div className="mt-3 rounded-2xl border border-amber-300 bg-gradient-to-b from-amber-100 to-orange-200 p-3 shadow">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold text-stone-900">
                Now Playing : <span className="font-bold">{activeSport.live.label}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-red-500" aria-hidden="true" />
                <span className="sr-only">Live</span>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-[1fr_auto_1fr] items-center">
              <div className="text-center">
                <div className="text-3xl font-extrabold leading-none tracking-tight text-stone-950">
                  {activeSport.live.left.score}
                </div>
                <div className="mt-1.5 text-xs font-semibold text-stone-800">
                  {activeSport.live.left.detail}
                </div>
              </div>

              <div className="flex justify-center" aria-hidden="true">
                <div className="h-14 w-px bg-stone-700/40" />
              </div>

              <div className="text-center">
                <div className="text-3xl font-extrabold leading-none tracking-tight text-stone-950">
                  {activeSport.live.right.score}
                </div>
                <div className="mt-1.5 text-xs font-semibold text-stone-800">
                  {activeSport.live.right.detail}
                </div>
              </div>
            </div>
          </div>

          <h3 className="mt-4 text-xl font-extrabold text-stone-900">Up Next</h3>
          <div className="mt-2.5 grid grid-cols-2 gap-2.5">
            {activeSport.upcoming.slice(0, 2).map((m) => (
              <div
                key={m.label}
                className="rounded-2xl border border-amber-300 bg-amber-50 p-2.5 text-center shadow"
              >
                <div className="text-base font-extrabold leading-tight text-stone-950">{m.label}</div>
                <div className="mt-1 text-xs font-semibold text-stone-700">{m.timeLabel}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-4 rounded-2xl border border-amber-200 bg-white p-3 shadow-sm">
          <h3 className="text-xl font-extrabold text-stone-900">Quick Links</h3>

          <div className="mt-3 space-y-1">
            <a
              href="#"
              className="-mx-2 flex min-h-10 items-center gap-2.5 px-2 py-1.5 text-stone-900"
              aria-label="GHS Carnival's Official Page"
            >
              <span className="text-xl" aria-hidden="true">
                📷
              </span>
              <span className="text-base font-bold underline underline-offset-4">
                GHS CARNIVAL&apos;S Official Page
              </span>
            </a>

            <a href="/guidelines" className="-mx-2 flex min-h-10 items-center gap-2.5 px-2 py-1.5 text-stone-900">
              <span className="text-xl" aria-hidden="true">
                🌐
              </span>
              <span className="text-base font-bold underline underline-offset-4">
                Guidelines / Rulebook
              </span>
            </a>

            <a
              href="#"
              className="-mx-2 flex min-h-10 items-center gap-2.5 px-2 py-1.5 text-stone-900"
              aria-label="Cultural Events Updates"
            >
              <span className="text-xl" aria-hidden="true">
                🕒
              </span>
              <span className="text-base font-bold underline underline-offset-4">
                Cultural Events Updates
              </span>
            </a>
          </div>
        </section>
      </main>
    </div>
  )
}

