import { useState, useEffect } from "react";
import { ScoreDisplay } from "../components/ScoreDisplay";
import { api, Sport, Match } from "../api/client";

const SPORT_ICONS: Record<string, string> = {
  'box-cricket': '🏏',
  'boxcricket': '🏏',
  'futsal': '⚽',
  'basketball': '🏀',
  'volleyball': '🏐',
  'table-tennis': '🏓',
  'tabletennis': '🏓',
  'power-lifting': '🏋️',
  'powerlifting': '🏋️',
  'pool': '🎱',
  'badminton': '🏸',
  'squash': '🎾',
  'tug-of-war': '🪢',
  'tugofwar': '🪢',
  'chess': '♟️'
};

export default function LiveScoresPage() {
  const [sports, setSports] = useState<Sport[]>([]);
  const [selectedSport, setSelectedSport] = useState<string | null>(null);
  const [liveMatch, setLiveMatch] = useState<Match | null>(null);
  const [upcomingMatches, setUpcomingMatches] = useState<Match[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadSports();
  }, []);

  useEffect(() => {
    if (selectedSport) {
      loadMatches(selectedSport);
      
      // Connect to SSE stream for live updates
      const apiBase = import.meta.env.VITE_API_URL || '/api';
      const eventSource = new EventSource(`${apiBase}/public/live-stream?sport_slug=${selectedSport}&interval=5`);
      
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.live) {
            setLiveMatch(data.live);
          } else {
            setLiveMatch(null);
          }
          
          if (data.upcoming) {
            setUpcomingMatches(data.upcoming.slice(0, 6));
          }
        } catch (err) {
          console.error('Failed to parse SSE data:', err);
        }
      };
      
      eventSource.onerror = (err) => {
        console.error('SSE connection error:', err);
        eventSource.close();
      };
      
      // Cleanup: close connection when sport changes or component unmounts
      return () => {
        eventSource.close();
      };
    }
  }, [selectedSport]);

  async function loadSports() {
    try {
      const { items } = await api.getSports();
      setSports(items);
      if (items.length > 0 && !selectedSport) {
        setSelectedSport(items[0].slug);
      }
      setLoading(false);
    } catch (err) {
      console.error('Failed to load sports:', err);
      setError('Failed to load sports');
      setLoading(false);
    }
  }

  async function loadMatches(sportSlug: string) {
    try {
      const { items: allMatches } = await api.getMatches({ 
        sport_slug: sportSlug,
        limit: 50
      });

      const live = allMatches.find(m => m.status === 'LIVE');
      const upcoming = allMatches.filter(m => m.status === 'UPCOMING').slice(0, 6);

      setLiveMatch(live || null);
      setUpcomingMatches(upcoming);
    } catch (err) {
      console.error('Failed to load matches:', err);
      setError('Failed to load matches');
    }
  }

  const currentSport = sports.find(s => s.slug === selectedSport);

  if (loading) {
    return (
      <div className="min-h-screen bg-[url('/Background.png')] bg-center bg-cover bg-no-repeat bg-fixed bg-white font-[system-ui,sans-serif]">
        <header className="py-2 flex justify-center">
            <img src="/ghs_carnival_logo.png" alt="GHS Carnival" className="h-12 md:h-14 w-auto object-contain" />
          </header>
        <div className="max-w-[920px] mx-auto">          
          <div className="p-4 text-center text-gray-500">Loading sports data...</div>
        </div>
      </div>
    );
  }

  if (error || sports.length === 0) {
    return (
      <div className="min-h-screen bg-[url('/Background.png')] bg-center bg-cover bg-no-repeat bg-fixed bg-white font-[system-ui,sans-serif]">
        <header className="py-2 flex justify-center">
            <img src="/ghs_carnival_logo.png" alt="GHS Carnival" className="h-12 md:h-14 w-auto object-contain" />
        </header>
        <div className="max-w-[920px] mx-auto">         
          <div className="p-4 text-center">
            <p className="text-red-500 mb-4">{error || 'No sports available yet'}</p>
            <p className="text-sm text-gray-500">Please check back later or contact the admin.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[url('/Background.png')] bg-center bg-cover bg-no-repeat bg-fixed bg-white font-[system-ui,sans-serif]">
      <header className="py-2 flex justify-center">
            <img src="/ghs_carnival_logo.png" alt="GHS Carnival" className="h-12 md:h-14 w-auto object-contain" />
        </header>
      <div className="max-w-[920px] mx-auto">
        <div className="grid grid-cols-[repeat(auto-fit,minmax(110px,1fr))] gap-3 px-4 mt-1 max-[420px]:grid-cols-3 max-[420px]:gap-2 min-[1280px]:grid-cols-[repeat(6,minmax(110px,1fr))] min-[1280px]:gap-[14px]">
          {sports.map((s) => (
            <button
              key={s.slug}
              className={`flex flex-col items-center gap-1.5 bg-white rounded-[14px] py-3 px-2 text-xs font-semibold cursor-pointer border transition-[0.2s_ease] shadow-[0_1px_2px_rgba(0,0,0,0.04)] max-[420px]:py-2.5 max-[420px]:px-1.5 max-[420px]:rounded-xl ${
                selectedSport === s.slug 
                  ? 'bg-gradient-to-br from-rose-50 via-orange-50/50 to-orange-50 border-rose-200 shadow-[0_0_0_3px_rgba(254,205,211,0.55)]' 
                  : 'border-gray-200'
              }`}
              onClick={() => setSelectedSport(s.slug)}
              aria-pressed={selectedSport === s.slug}
            >
              <span className="text-lg">{SPORT_ICONS[s.slug] || '🏆'}</span>
              <span>{s.name}</span>
            </button>
          ))}
        </div>

        <main className="p-4 min-[900px]:max-w-[560px] min-[900px]:mx-auto min-[1280px]:max-w-[680px]">
          {liveMatch ? (
            <>
              <h2 className="text-xs uppercase tracking-wider text-gray-500 mt-[22px] mb-2.5">
                NOW PLAYING: {currentSport?.name.toUpperCase()}
              </h2>

              <section className="bg-gradient-to-br from-rose-100/50 via-white to-orange-100 rounded-[18px] p-3.5 border border-rose-200 shadow-[0_6px_18px_rgba(255,192,186,0.35)_inset]">
                <div className="flex items-center gap-2 text-[13px]">
                  <span className="w-2 h-2 bg-red-600 rounded-full animate-pulse" />
                  Now Playing: {liveMatch.teamA} v/s {liveMatch.teamB}
                </div>

                <ScoreDisplay match={liveMatch} sportSlug={selectedSport || ''} variant="live" />

                {liveMatch.venue && (
                  <div className="text-xs text-gray-500 mt-2">📍 Venue: {liveMatch.venue}</div>
                )}
              </section>
            </>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <p className="text-lg mb-2">No live matches at the moment</p>
              <p className="text-sm">Check upcoming matches below</p>
            </div>
          )}

          {upcomingMatches.length > 0 && (
            <>
              <h2 className="text-xs uppercase tracking-wider text-gray-500 mt-[22px] mb-2.5">UP NEXT</h2>

              <section className="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-3">
                {upcomingMatches.map((match) => (
                  <div key={match.id} className="bg-white py-2.5 px-3 rounded-xl text-xs border border-[#eef2f7] shadow-[0_1px_3px_rgba(0,0,0,0.05)]">
                    <strong>
                      {match.startTime 
                        ? new Date(match.startTime).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
                        : 'TBA'}
                    </strong>
                    <span className="block">{match.teamA} v/s {match.teamB}</span>
                    {match.venue && <span className="block text-gray-400 mt-1">{match.venue}</span>}
                  </div>
                ))}
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
