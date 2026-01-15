import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '../../supabaseClient';
import { Sun, Moon, Menu, Trash2, X, PlusCircle, MinusCircle } from 'lucide-react';

interface Match {
  id: string;
  teamA: string;
  teamB: string;
  date: string;
  scoreA: number;
  scoreB: number;
}

export default function AdminDashboard() {
  const navigate = useNavigate();
  const [isDark, setIsDark] = useState(true);
  const [loading, setLoading] = useState(true);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'manage' | 'create'>('manage');
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const [matches, setMatches] = useState<Match[]>([
    { id: '1', teamA: 'Team A', teamB: 'Team B', date: '2026-01-14', scoreA: 0, scoreB: 0 },
  ]);
  
  const [createForm, setCreateForm] = useState({ teamA: '', teamB: '', date: '' });
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editScore, setEditScore] = useState({ scoreA: '0', scoreB: '0' });

  const theme = {
    bg: isDark ? 'bg-slate-950' : 'bg-slate-50',
    sidebar: isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200',
    card: isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200 shadow-sm',
    input: isDark ? 'bg-slate-800 border-slate-700 text-white' : 'bg-white border-slate-300 text-slate-900',
    text: isDark ? 'text-slate-100' : 'text-slate-900',
    subtext: isDark ? 'text-slate-500' : 'text-slate-400',
    buttonPrimary: 'bg-orange-500 text-white hover:bg-orange-600 shadow-lg shadow-orange-500/20',
    buttonSecondary: isDark ? 'bg-slate-800 text-slate-300 hover:bg-slate-700' : 'bg-slate-100 text-slate-600 hover:bg-slate-200',
    buttonLogout: 'text-red-500 border border-red-500/20 hover:bg-red-500 hover:text-white'
  };

  useEffect(() => {
    const initializeUser = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        navigate('/admin/login', { replace: true });
        return;
      }
      
      const { data: profile } = await supabase
        .from('User')
        .select(`
          username,
          sport:Sport (
            name
          )
        `)
        .eq('id', session.user.id)
        .single();

      setUserProfile(profile);
      setLoading(false);
    };
    initializeUser();
  }, [navigate]);

  const handleLogout = async () => {
    await supabase.auth.signOut();
    navigate('/admin/login', { replace: true });
  };

  const handleCreateMatch = (e: React.FormEvent) => {
    e.preventDefault();
    const newMatch: Match = {
      id: Date.now().toString(),
      teamA: createForm.teamA,
      teamB: createForm.teamB,
      date: createForm.date,
      scoreA: 0,
      scoreB: 0
    };
    setMatches([newMatch, ...matches]);
    setCreateForm({ teamA: '', teamB: '', date: '' });
    setActiveTab('manage');
  };

  const saveScore = (id: string) => {
    setMatches(matches.map(m => 
      m.id === id ? { ...m, scoreA: Number(editScore.scoreA), scoreB: Number(editScore.scoreB) } : m
    ));
    setEditingId(null);
  };

  const adjustScore = (side: 'A' | 'B', delta: number) => {
    setEditScore(prev => ({
      ...prev,
      [side === 'A' ? 'scoreA' : 'scoreB']: String(Math.max(0, Number(prev[side === 'A' ? 'scoreA' : 'scoreB']) + delta))
    }));
  };

  const deleteMatch = (id: string) => {
    if (window.confirm("Are you sure you want to delete/end this match?")) {
      setMatches(matches.filter(m => m.id !== id));
    }
  };

  if (loading) return <div className={`h-screen w-screen flex items-center justify-center ${theme.bg}`}><div className="animate-spin rounded-full h-8 w-8 border-t-2 border-orange-500"></div></div>;

  return (
    <div className={`flex h-screen font-sans ${theme.bg} ${theme.text} overflow-hidden transition-colors duration-300`}>
      
      {isMenuOpen && <div className="fixed inset-0 bg-black/60 z-40 md:hidden" onClick={() => setIsMenuOpen(false)} />}

      <aside className={`fixed md:relative z-50 h-full w-64 p-6 border-r transition-transform duration-300
        ${isMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'} ${theme.sidebar}`}>
        
        <div className="flex items-center justify-between mb-10 md:mb-12">
          <div className="flex flex-col">
            {/* MINIMAL LOGGED IN INDICATOR */}
            <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold mb-1">
              Logged in as <span className="text-orange-400/80">{userProfile?.username || 'admin'}</span>
            </span>
            <h2 className="text-lg font-bold truncate uppercase text-orange-500 leading-tight">
                {userProfile?.sport?.name ? `${userProfile.sport.name}` : 'Admin Panel'}
            </h2>
          </div>
          <button className="md:hidden" onClick={() => setIsMenuOpen(false)}><X size={20}/></button>
        </div>
        
        <nav className="flex flex-col gap-3">
          <TabBtn label="Manage Matches" active={activeTab === 'manage'} onClick={() => { setActiveTab('manage'); setIsMenuOpen(false); }} theme={theme} />
          <TabBtn label="Create Match" active={activeTab === 'create'} onClick={() => { setActiveTab('create'); setIsMenuOpen(false); }} theme={theme} />
        </nav>

        <button 
          onClick={() => setIsDark(!isDark)} 
          className={`mt-6 w-full flex items-center justify-center gap-2 p-3 rounded-xl border text-[10px] font-bold uppercase transition-all 
          ${isDark ? 'border-slate-800 text-slate-400 hover:bg-slate-800' : 'border-slate-200 text-slate-500 hover:bg-slate-50'}`}
        >
          {isDark ? <Sun size={14} className="text-orange-500" /> : <Moon size={14} className="text-slate-600" />}
          {isDark ? 'Light Mode' : 'Dark Mode'}
        </button>

        <div className="absolute bottom-8 left-6 right-6">
          <button onClick={handleLogout} className={`w-full px-4 py-3 rounded-xl text-[10px] font-bold uppercase transition-all ${theme.buttonLogout}`}>Logout</button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 flex items-center px-6 border-b border-slate-800/50 md:hidden">
          <button onClick={() => setIsMenuOpen(true)} className="p-2 -ml-2 rounded-lg text-orange-500"><Menu size={24} /></button>
          <span className="ml-4 font-bold text-xs uppercase tracking-widest">Admin Panel</span>
        </header>

        <main className="p-4 md:p-10 overflow-y-auto flex-1">
          <div className="max-w-4xl mx-auto space-y-6">
            
            {activeTab === 'manage' && (
              <div className="grid gap-4">
                <h2 className="text-xl font-bold mb-2">Live Management</h2>
                {matches.length === 0 ? (
                  <div className={`p-10 text-center border-2 border-dashed rounded-3xl opacity-20 uppercase font-bold text-xs ${theme.text}`}>No Active Matches</div>
                ) : matches.map(match => (
                  <div key={match.id} className={`p-5 md:p-6 rounded-[22px] border ${theme.card} flex flex-col md:flex-row md:items-center justify-between gap-6`}>
                    <div className="flex-1">
                      <h3 className="font-bold text-lg">{match.teamA} <span className="text-orange-500">vs</span> {match.teamB}</h3>
                      <p className={`text-[10px] uppercase mt-1 tracking-wider ${theme.subtext}`}>{match.date}</p>
                    </div>

                    <div className="flex flex-col md:flex-row items-center gap-4">
                      {editingId === match.id ? (
                        <div className="flex items-center gap-3">
                          <button onClick={() => adjustScore('A', -1)} className="text-red-500"><MinusCircle size={20}/></button>
                          <input type="number" className={`w-14 p-2 rounded-lg text-center font-bold ${theme.input}`} value={editScore.scoreA} onChange={e => setEditScore({...editScore, scoreA: e.target.value})} />
                          <button onClick={() => adjustScore('A', 1)} className="text-green-500"><PlusCircle size={20}/></button>
                          
                          <span className="opacity-20 mx-1">|</span>
                          
                          <button onClick={() => adjustScore('B', -1)} className="text-red-500"><MinusCircle size={20}/></button>
                          <input type="number" className={`w-14 p-2 rounded-lg text-center font-bold ${theme.input}`} value={editScore.scoreB} onChange={e => setEditScore({...editScore, scoreB: e.target.value})} />
                          <button onClick={() => adjustScore('B', 1)} className="text-green-500"><PlusCircle size={20}/></button>
                          
                          <button onClick={() => saveScore(match.id)} className={`ml-2 px-4 py-2 rounded-lg text-white font-bold text-[10px] uppercase ${theme.buttonPrimary}`}>Save</button>
                        </div>
                      ) : (
                        <div className="flex items-center gap-3 w-full md:w-auto">
                          <div className={`text-xl font-bold px-5 py-2 rounded-xl w-full text-center md:w-auto ${isDark ? 'bg-slate-800' : 'bg-slate-100'}`}>
                            {match.scoreA} : {match.scoreB}
                          </div>
                          <button onClick={() => { setEditingId(match.id); setEditScore({ scoreA: String(match.scoreA), scoreB: String(match.scoreB) }); }} className={`px-4 py-2 rounded-lg text-[10px] font-bold uppercase transition-all ${theme.buttonSecondary}`}>Update</button>
                          <button onClick={() => deleteMatch(match.id)} className="p-2 text-red-500/50 hover:text-red-500 transition-all"><Trash2 size={18} /></button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'create' && (
              <div className={`p-8 rounded-[30px] border ${theme.card} animate-in fade-in duration-300`}>
                <h2 className="text-xl font-bold mb-6 uppercase tracking-tight">Setup New Match</h2>
                <form onSubmit={handleCreateMatch} className="space-y-5">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input type="text" placeholder="Home Team" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`} value={createForm.teamA} onChange={e => setCreateForm({...createForm, teamA: e.target.value})} required />
                    <input type="text" placeholder="Away Team" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`} value={createForm.teamB} onChange={e => setCreateForm({...createForm, teamB: e.target.value})} required />
                  </div>
                  <input type="date" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm [color-scheme:${isDark ? 'dark' : 'light'}] ${theme.input}`} value={createForm.date} onChange={e => setCreateForm({...createForm, date: e.target.value})} required />
                  <button type="submit" className={`w-full p-4 rounded-2xl font-bold uppercase text-[10px] tracking-widest transition-all ${theme.buttonPrimary}`}>Create Match</button>
                </form>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function TabBtn({ label, active, onClick, theme }: any) {
  return (
    <button onClick={onClick} className={`w-full flex items-center px-4 py-3 rounded-xl text-sm font-bold transition-all ${active ? theme.buttonPrimary : 'text-slate-500 hover:bg-slate-800/50'}`}>
      {label}
    </button>
  );
}
