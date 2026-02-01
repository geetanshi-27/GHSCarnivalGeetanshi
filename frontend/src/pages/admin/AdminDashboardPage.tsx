import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Sun, Moon, Menu, Trash2, X, PlusCircle, MinusCircle } from 'lucide-react';
import { api, Match } from '../../api/client';
import ProfileSettings from '../../components/ProfileSettings';

interface AdminUser {
  id: string;
  email: string;
  username: string;
  role: string;
  sportId?: string;
  sport?: {
    id: string;
    name: string;
    slug: string;
  };
}

interface Sport {
  id: string;
  name: string;
  slug: string;
}

export default function AdminDashboard() {
  const navigate = useNavigate();
  const [isDark, setIsDark] = useState(true);
  const [loading, setLoading] = useState(true);
  const [userProfile, setUserProfile] = useState<AdminUser | null>(null);
  const [activeTab, setActiveTab] = useState<'manage' | 'create' | 'users' | 'profile'>('manage');
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const [matches, setMatches] = useState<Match[]>([]);
  const [loadingMatches, setLoadingMatches] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [sports, setSports] = useState<Sport[]>([]);
  const [selectedSportId, setSelectedSportId] = useState<string>(''); // For create form
  const [filterSportId, setFilterSportId] = useState<string>(''); // For manage filter
  const [createForm, setCreateForm] = useState({ teamA: '', teamB: '', startTime: '', venue: '' });
  const [editingId, setEditingId] = useState<string | null>(null);

  // User management state
  const [users, setUsers] = useState<any[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [userEditForm, setUserEditForm] = useState({ email: '', password: '' });

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

  const loadMatches = async (sportId?: string) => {
    setLoadingMatches(true);
    setError(null);
    try {
      const response = await api.admin.getMatches(sportId ? { sport_id: sportId } : {});
      setMatches(response.items);
    } catch (err) {
      console.error('Failed to load matches:', err);
      setError('Failed to load matches');
    } finally {
      setLoadingMatches(false);
    }
  };

  useEffect(() => {
    const initializeUser = async () => {
      const userStr = localStorage.getItem('admin_user');
      
      if (!userStr) {
        navigate('/ghs-control-panel-2026/login', { replace: true });
        return;
      }

      try {
        const user = JSON.parse(userStr);
        setUserProfile(user);
        setLoading(false);
        
        // Load sports list for super admins
        if (user.role === 'SUPER_ADMIN') {
          try {
            const sportsResponse = await api.getSports();
            setSports(sportsResponse.items);
          } catch (err) {
            console.error('Failed to load sports:', err);
          }
        }
        
        // Load matches after user is set
        await loadMatches(user.sportId);
      } catch (error) {
        console.error('Failed to parse user data:', error);
        navigate('/ghs-control-panel-2026/login', { replace: true });
      }
    };
    
    initializeUser();
  }, [navigate]);

  const handleLogout = async () => {
    try {
      await api.admin.logout();
    } catch (err) {
      console.error('Logout failed:', err);
    } finally {
      localStorage.removeItem('admin_user');
      navigate('/ghs-control-panel-2026/login', { replace: true });
    }
  };

  const handleCreateMatch = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Determine sport slug based on user role
    let sportSlug: string;
    if (userProfile?.role === 'SUPER_ADMIN') {
      if (!selectedSportId) {
        setError('Please select a sport');
        return;
      }
      const selectedSport = sports.find(s => s.id === selectedSportId);
      if (!selectedSport) {
        setError('Invalid sport selected');
        return;
      }
      sportSlug = selectedSport.slug;
    } else {
      if (!userProfile?.sport?.slug) {
        setError('Missing sport information');
        return;
      }
      sportSlug = userProfile.sport.slug;
    }

    try {
      setError(null);
      
      // Convert datetime-local format to ISO-8601 if provided
      let startTimeISO: string | undefined = undefined;
      if (createForm.startTime) {
        // datetime-local gives us YYYY-MM-DDTHH:MM, we need to add seconds
        startTimeISO = new Date(createForm.startTime).toISOString();
      }
      
      const response = await api.admin.createMatch({
        sportSlug,
        teamA: createForm.teamA,
        teamB: createForm.teamB,
        startTime: startTimeISO,
        venue: createForm.venue || undefined,
        status: 'UPCOMING'
      });
      
      setMatches([response.item, ...matches]);
      setCreateForm({ teamA: '', teamB: '', startTime: '', venue: '' });
      setSelectedSportId(''); // Reset sport selection for super admin
      setActiveTab('manage');
    } catch (err) {
      console.error('Failed to create match:', err);
      setError('Failed to create match. Please try again.');
    }
  };

  const startMatch = async (id: string) => {
    try {
      setError(null);
      const response = await api.admin.updateMatch(id, {
        status: 'LIVE'
      });
      
      setMatches(matches.map(m => m.id === id ? response.item : m));
    } catch (err) {
      console.error('Failed to start match:', err);
      setError('Failed to start match');
    }
  };

  const completeMatch = async (id: string) => {
    try {
      setError(null);
      const response = await api.admin.updateMatch(id, {
        status: 'COMPLETED'
      });
      
      setMatches(matches.map(m => m.id === id ? response.item : m));
    } catch (err) {
      console.error('Failed to complete match:', err);
      setError('Failed to complete match');
    }
  };

  const saveScore = async (id: string, scoreData: any) => {
    try {
      setError(null);
      const response = await api.admin.updateMatch(id, {
        score: scoreData
      });
      
      setMatches(matches.map(m => m.id === id ? response.item : m));
      setEditingId(null);
    } catch (err) {
      console.error('Failed to update score:', err);
      setError('Failed to update score');
    }
  };

  const deleteMatch = async (id: string) => {
    if (!window.confirm("Are you sure you want to delete/end this match?")) return;

    try {
      setError(null);
      await api.admin.deleteMatch(id);
      setMatches(matches.filter(m => m.id !== id));
    } catch (err) {
      console.error('Failed to delete match:', err);
      setError('Failed to delete match');
    }
  };

  const loadUsers = async () => {
    setLoadingUsers(true);
    setError(null);
    try {
      const response = await api.admin.getUsers();
      setUsers(response.items);
    } catch (err) {
      console.error('Failed to load users:', err);
      setError('Failed to load users');
    } finally {
      setLoadingUsers(false);
    }
  };

  const handleUpdateUser = async (userId: string) => {
    try {
      setError(null);
      const updateData: any = {};
      if (userEditForm.email) updateData.email = userEditForm.email;
      if (userEditForm.password) updateData.password = userEditForm.password;

      if (Object.keys(updateData).length === 0) {
        setError('Please provide email or password to update');
        return;
      }

      await api.admin.updateUser(userId, updateData);
      await loadUsers(); // Reload users
      setEditingUserId(null);
      setUserEditForm({ email: '', password: '' });
    } catch (err: any) {
      console.error('Failed to update user:', err);
      setError(err.message || 'Failed to update user');
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
                {userProfile?.role === 'SUPER_ADMIN' ? 'Super Admin' : (userProfile?.sport?.name || 'Admin Panel')}
            </h2>
          </div>
          <button className="md:hidden" onClick={() => setIsMenuOpen(false)}><X size={20}/></button>
        </div>
        
        <nav className="flex flex-col gap-3">
          <TabBtn label="Manage Matches" active={activeTab === 'manage'} onClick={() => { setActiveTab('manage'); setIsMenuOpen(false); }} theme={theme} />
          <TabBtn label="Create Match" active={activeTab === 'create'} onClick={() => { setActiveTab('create'); setIsMenuOpen(false); }} theme={theme} />
          {userProfile?.role === 'SUPER_ADMIN' && (
            <TabBtn label="Manage Users" active={activeTab === 'users'} onClick={() => { setActiveTab('users'); setIsMenuOpen(false); loadUsers(); }} theme={theme} />
          )}
          <TabBtn label="Profile Settings" active={activeTab === 'profile'} onClick={() => { setActiveTab('profile'); setIsMenuOpen(false); }} theme={theme} />
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
            
            {error && (
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-500 text-sm">
                {error}
              </div>
            )}

            {activeTab === 'manage' && (
              <div className="grid gap-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-2">
                  <h2 className="text-xl font-bold">Live Management</h2>
                  {userProfile?.role === 'SUPER_ADMIN' && sports.length > 0 && (
                    <select
                      className={`px-4 py-2 rounded-xl text-sm font-bold ${theme.input}`}
                      value={filterSportId}
                      onChange={async (e) => {
                        setFilterSportId(e.target.value);
                        await loadMatches(e.target.value || '');
                      }}
                    >
                      <option value="">All Sports</option>
                      {sports.map(sport => (
                        <option key={sport.id} value={sport.id}>{sport.name}</option>
                      ))}
                    </select>
                  )}
                </div>
                {loadingMatches ? (
                  <div className="flex justify-center py-10">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-orange-500"></div>
                  </div>
                ) : matches.length === 0 ? (
                  <div className={`p-10 text-center border-2 border-dashed rounded-3xl opacity-20 uppercase font-bold text-xs ${theme.text}`}>No Active Matches</div>
                ) : matches.map(match => {
                  return (
                  <div key={match.id} className={`p-5 md:p-6 rounded-[22px] border ${theme.card} flex flex-col gap-4`}>
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <h3 className="font-bold text-lg">{match.teamA} <span className="text-orange-500">vs</span> {match.teamB}</h3>
                          <span className={`px-2 py-1 rounded-lg text-[9px] font-bold uppercase ${
                            match.status === 'LIVE' ? 'bg-red-500/20 text-red-400 animate-pulse' :
                            match.status === 'COMPLETED' ? 'bg-green-500/20 text-green-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>{match.status}</span>
                          {userProfile?.role === 'SUPER_ADMIN' && match.sport && (
                            <span className={`px-2 py-1 rounded-lg text-[9px] font-bold uppercase bg-purple-500/20 text-purple-400`}>
                              {match.sport.name}
                            </span>
                          )}
                        </div>
                        <div className="flex gap-2 items-center">
                          {match.venue && <p className={`text-[10px] ${theme.subtext}`}>{match.venue}</p>}
                          {match.venue && match.startTime && <span className={theme.subtext}>•</span>}
                          {match.startTime && <p className={`text-[10px] ${theme.subtext}`}>{new Date(match.startTime).toLocaleString()}</p>}
                        </div>
                      </div>

                      <div className={`px-4 py-2 rounded-xl ${isDark ? 'bg-slate-800' : 'bg-slate-100'}`}>
                        <ScoreDisplay match={match} sportSlug={match.sport?.slug || ''} />
                      </div>
                    </div>

                    {editingId === match.id ? (
                      <div className={`pt-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                        <ScoreEditor 
                          match={match} 
                          sportSlug={match.sport?.slug || ''} 
                          onSave={saveScore}
                          onCancel={() => setEditingId(null)}
                          theme={theme}
                        />
                      </div>
                    ) : (
                      <div className={`flex flex-col md:flex-row items-stretch md:items-center gap-3 pt-3 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                        {match.status === 'UPCOMING' && (
                          <button onClick={() => startMatch(match.id)} className="px-4 py-2 rounded-lg text-[10px] font-bold uppercase bg-green-500 text-white hover:bg-green-600 transition-all">
                            Start Match
                          </button>
                        )}
                        {match.status === 'LIVE' && (
                          <button onClick={() => completeMatch(match.id)} className="px-4 py-2 rounded-lg text-[10px] font-bold uppercase bg-blue-500 text-white hover:bg-blue-600 transition-all">
                            Complete Match
                          </button>
                        )}
                        <button onClick={() => setEditingId(match.id)} className={`px-4 py-2 rounded-lg text-[10px] font-bold uppercase transition-all flex-1 md:flex-none ${theme.buttonSecondary}`}>Update Score</button>
                        <button onClick={() => deleteMatch(match.id)} className="px-4 py-2 rounded-lg text-[10px] font-bold uppercase text-red-500 border border-red-500/20 hover:bg-red-500 hover:text-white transition-all flex-1 md:flex-none">Delete</button>
                      </div>
                    )}
                  </div>
                  );
                })}
              </div>
            )}

            {activeTab === 'create' && (
              <div className={`p-8 rounded-[30px] border ${theme.card} animate-in fade-in duration-300`}>
                <h2 className="text-xl font-bold mb-6 uppercase tracking-tight">Setup New Match</h2>
                <form onSubmit={handleCreateMatch} className="space-y-5">
                  {userProfile?.role === 'SUPER_ADMIN' && (
                    <div>
                      <label className={`block text-xs font-bold mb-2 uppercase tracking-wide ${theme.subtext}`}>Select Sport</label>
                      <select 
                        className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`}
                        value={selectedSportId}
                        onChange={e => setSelectedSportId(e.target.value)}
                        required
                      >
                        <option value="">-- Choose a Sport --</option>
                        {sports.map(sport => (
                          <option key={sport.id} value={sport.id}>{sport.name}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input type="text" placeholder="Team A" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`} value={createForm.teamA} onChange={e => setCreateForm({...createForm, teamA: e.target.value})} required />
                    <input type="text" placeholder="Team B" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`} value={createForm.teamB} onChange={e => setCreateForm({...createForm, teamB: e.target.value})} required />
                  </div>
                  <input type="datetime-local" placeholder="Start Time (optional)" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm [color-scheme:${isDark ? 'dark' : 'light'}] ${theme.input}`} value={createForm.startTime} onChange={e => setCreateForm({...createForm, startTime: e.target.value})} />
                  <input type="text" placeholder="Venue (optional)" className={`w-full p-4 rounded-2xl border-2 outline-none font-bold text-sm focus:border-orange-500 ${theme.input}`} value={createForm.venue} onChange={e => setCreateForm({...createForm, venue: e.target.value})} />
                  <button type="submit" className={`w-full p-4 rounded-2xl font-bold uppercase text-[10px] tracking-widest transition-all ${theme.buttonPrimary}`}>Create Match</button>
                </form>
              </div>
            )}

            {activeTab === 'users' && userProfile?.role === 'SUPER_ADMIN' && (
              <div className="grid gap-4">
                <h2 className="text-xl font-bold">User Management</h2>
                
                {loadingUsers ? (
                  <div className="flex justify-center py-10">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-orange-500"></div>
                  </div>
                ) : users.length === 0 ? (
                  <div className={`p-10 text-center border-2 border-dashed rounded-3xl opacity-20 uppercase font-bold text-xs ${theme.text}`}>No Users Found</div>
                ) : (
                  <div className="space-y-4">
                    {users.map(user => (
                      <div key={user.id} className={`p-5 md:p-6 rounded-[22px] border ${theme.card}`}>
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                          <div className="flex-1">
                            <h3 className="font-bold text-lg">{user.username}</h3>
                            <p className={`text-sm ${theme.subtext}`}>{user.email}</p>
                            <div className="flex gap-2 mt-2 flex-wrap">
                              <span className={`px-2 py-1 rounded-lg text-[9px] font-bold uppercase ${
                                user.role === 'SUPER_ADMIN' ? 'bg-purple-500/20 text-purple-400' : 'bg-blue-500/20 text-blue-400'
                              }`}>{user.role}</span>
                              {user.sport && (
                                <span className="px-2 py-1 rounded-lg text-[9px] font-bold uppercase bg-green-500/20 text-green-400">
                                  {user.sport.name}
                                </span>
                              )}
                            </div>
                          </div>
                          
                          {user.id !== userProfile.id && (
                            <button
                              onClick={() => {
                                if (editingUserId === user.id) {
                                  setEditingUserId(null);
                                  setUserEditForm({ email: '', password: '' });
                                } else {
                                  setEditingUserId(user.id);
                                  setUserEditForm({ email: user.email, password: '' });
                                }
                              }}
                              className={`px-4 py-2 rounded-lg text-[10px] font-bold uppercase transition-all ${theme.buttonSecondary}`}
                            >
                              {editingUserId === user.id ? 'Cancel' : 'Edit'}
                            </button>
                          )}
                        </div>
                        
                        {editingUserId === user.id && (
                          <div className={`pt-4 border-t ${isDark ? 'border-slate-800' : 'border-slate-200'} space-y-3`}>
                            <div>
                              <label className={`block text-[10px] font-bold uppercase mb-1 ${theme.subtext}`}>New Email</label>
                              <input
                                type="email"
                                placeholder="Enter new email"
                                className={`w-full px-4 py-2 rounded-xl text-sm ${theme.input}`}
                                value={userEditForm.email}
                                onChange={e => setUserEditForm({ ...userEditForm, email: e.target.value })}
                              />
                            </div>
                            <div>
                              <label className={`block text-[10px] font-bold uppercase mb-1 ${theme.subtext}`}>New Password</label>
                              <input
                                type="password"
                                placeholder="Enter new password (leave empty to keep current)"
                                className={`w-full px-4 py-2 rounded-xl text-sm ${theme.input}`}
                                value={userEditForm.password}
                                onChange={e => setUserEditForm({ ...userEditForm, password: e.target.value })}
                              />
                            </div>
                            <button
                              onClick={() => handleUpdateUser(user.id)}
                              className="w-full px-4 py-2 rounded-lg text-[10px] font-bold uppercase bg-green-500 text-white hover:bg-green-600 transition-all"
                            >
                              Update User
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'profile' && (
              <ProfileSettings
                user={userProfile}
                isDark={isDark}
                onLogout={handleLogout}
                onProfileUpdate={(updatedUser) => setUserProfile(updatedUser)}
              />
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

function ScoreDisplay({ match, sportSlug }: { match: Match; sportSlug: string }) {
  const s: any = match.score || {};

  if (sportSlug === 'box-cricket') {
    const teamA: any = s.teamA || {};
    const teamB: any = s.teamB || {};
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-lg">{teamA.runs || 0}/{teamA.wickets || 0} <span className="text-xs opacity-50">({teamA.overs || 0})</span> vs {teamB.runs || 0}/{teamB.wickets || 0} <span className="text-xs opacity-50">({teamB.overs || 0})</span></div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.innings || '1st'} Innings</div>
      </div>
    );
  }

  if (['volleyball', 'table-tennis', 'badminton', 'squash'].includes(sportSlug)) {
    const teamAScore = typeof s.teamA === 'object' ? (s.teamA?.score || 0) : (s.teamA || 0);
    const teamBScore = typeof s.teamB === 'object' ? (s.teamB?.score || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAScore} - {teamBScore} <span className="text-[10px] opacity-50 uppercase tracking-widest">Sets</span></div>
        <div className="text-xs font-mono opacity-80">Set {s.set || 1}: {s.currentSetA || 0}-{s.currentSetB || 0}</div>
      </div>
    );
  }

  if (sportSlug === 'chess') {
    const teamAWins = typeof s.teamA === 'object' ? (s.teamA?.wins || 0) : (s.teamA || 0);
    const teamBWins = typeof s.teamB === 'object' ? (s.teamB?.wins || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAWins} - {teamBWins} <span className="text-[10px] opacity-50 uppercase tracking-widest">Wins</span></div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.draws ? `${s.draws} Draw${s.draws > 1 ? 's' : ''}` : (s.round || 'In Progress')}</div>
      </div>
    );
  }

  if (sportSlug === 'pool') {
    const teamAFrames = typeof s.teamA === 'object' ? (s.teamA?.frames || 0) : (s.teamA || 0);
    const teamBFrames = typeof s.teamB === 'object' ? (s.teamB?.frames || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAFrames} - {teamBFrames} <span className="text-[10px] opacity-50 uppercase tracking-widest">Frames</span></div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.round || 'In Progress'}</div>
      </div>
    );
  }

  if (sportSlug === 'tug-of-war') {
    const teamAWins = typeof s.teamA === 'object' ? (s.teamA?.wins || 0) : (s.teamA || 0);
    const teamBWins = typeof s.teamB === 'object' ? (s.teamB?.wins || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAWins} - {teamBWins} <span className="text-[10px] opacity-50 uppercase tracking-widest">Rounds</span></div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.round || 'In Progress'}</div>
      </div>
    );
  }

  if (sportSlug === 'power-lifting') {
    const teamAScore = typeof s.teamA === 'object' ? (s.teamA?.score || 0) : (s.teamA || 0);
    const teamBScore = typeof s.teamB === 'object' ? (s.teamB?.score || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAScore} - {teamBScore} <span className="text-[10px] opacity-50 uppercase tracking-widest">Score</span></div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.round || 'In Progress'}</div>
      </div>
    );
  }

  if (['futsal', 'football'].includes(sportSlug)) {
    const teamAScore = typeof s.teamA === 'object' ? (s.teamA?.score || 0) : (s.teamA || 0);
    const teamBScore = typeof s.teamB === 'object' ? (s.teamB?.score || 0) : (s.teamB || 0);
    return (
      <div className="flex flex-col items-end">
        <div className="font-bold text-xl">{teamAScore} - {teamBScore}</div>
        <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.period || '1st Half'} {s.time ? `• ${s.time}` : ''}</div>
      </div>
    );
  }
  
  // Default (Basketball etc)
  const teamAScore = typeof s.teamA === 'object' ? (s.teamA?.score || 0) : (s.teamA || 0);
  const teamBScore = typeof s.teamB === 'object' ? (s.teamB?.score || 0) : (s.teamB || 0);
  return (
    <div className="flex flex-col items-end">
      <div className="font-bold text-xl">{teamAScore} - {teamBScore}</div>
      <div className="text-[10px] uppercase opacity-60 font-bold tracking-widest">{s.period || '-'}</div>
    </div>
  );
}

function ScoreEditor({ match, sportSlug, onSave, onCancel, theme }: any) {
  const [data, setData] = useState<any>(match.score || {});

  const update = (key: string, val: any) => setData((p: any) => ({ ...p, [key]: val }));
  const updateDeep = (parent: string, key: string, val: any) => setData((p: any) => ({ ...p, [parent]: { ...(p[parent] || {}), [key]: val } }));

  if (sportSlug === 'box-cricket') {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="grid grid-cols-2 gap-4">
           {['teamA', 'teamB'].map((team) => (
             <div key={team} className="p-3 rounded-xl bg-black/5 border border-white/10">
               <div className="text-[10px] font-bold uppercase mb-2 opacity-50">{team === 'teamA' ? match.teamA : match.teamB}</div>
               <div className="grid grid-cols-3 gap-2">
                 <input placeholder="R" className={`p-2 rounded text-center font-bold ${theme.input} text-xs`} value={data[team]?.runs || ''} onChange={e => updateDeep(team, 'runs', e.target.value)} />
                 <input placeholder="W" className={`p-2 rounded text-center font-bold ${theme.input} text-xs`} value={data[team]?.wickets || ''} onChange={e => updateDeep(team, 'wickets', e.target.value)} />
                 <input placeholder="Ov" className={`p-2 rounded text-center font-bold ${theme.input} text-xs`} value={data[team]?.overs || ''} onChange={e => updateDeep(team, 'overs', e.target.value)} />
               </div>
             </div>
           ))}
        </div>
        <div className="flex gap-2">
          <select className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.innings || '1st'} onChange={e => update('innings', e.target.value)}>
            <option value="1st">1st Innings</option>
            <option value="2nd">2nd Innings</option>
          </select>
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Sets based sports
  if (['volleyball', 'table-tennis', 'badminton', 'squash'].includes(sportSlug)) {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center justify-between gap-4">
           <div className="flex flex-col items-center gap-1">
             <span className="text-[10px] font-bold uppercase opacity-50">Sets</span>
             <div className="flex gap-2">
               <input type="number" className={`w-12 p-2 rounded text-center font-bold ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
               <span className="self-center opacity-20">:</span>
               <input type="number" className={`w-12 p-2 rounded text-center font-bold ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
             </div>
           </div>
           <div className="flex flex-col items-center gap-1 flex-1">
             <span className="text-[10px] font-bold uppercase opacity-50">Current Set Pts</span>
             <div className="flex gap-2 w-full">
               <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.currentSetA || 0} onChange={e => update('currentSetA', e.target.value)} />
               <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.currentSetB || 0} onChange={e => update('currentSetB', e.target.value)} />
             </div>
           </div>
        </div>
        <div className="flex gap-2 items-center">
          <span className="text-[10px] font-bold uppercase opacity-50">Set #</span>
          <input type="number" className={`w-12 p-2 rounded text-center font-bold ${theme.input}`} value={data.set || 1} onChange={e => update('set', e.target.value)} />
          <div className="flex-1"></div>
          <button onClick={() => onSave(match.id, data)} className={`px-4 py-2 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 py-2 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Chess format
  if (sportSlug === 'chess') {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center justify-between gap-4">
          <div className="flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamA} Wins</span>
            <input type="number" className={`w-16 p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
          </div>
          <div className="flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">Draws</span>
            <input type="number" className={`w-16 p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.draws || 0} onChange={e => update('draws', e.target.value)} />
          </div>
          <div className="flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamB} Wins</span>
            <input type="number" className={`w-16 p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
          </div>
        </div>
        <div className="flex gap-2">
          <input type="text" placeholder="Round (e.g. Round 3)" className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.round || ''} onChange={e => update('round', e.target.value)} />
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Pool format (frames)
  if (sportSlug === 'pool') {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center gap-4">
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamA} Frames</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
          </div>
          <span className="self-end mb-3 opacity-20 font-bold text-xl">:</span>
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamB} Frames</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
          </div>
        </div>
        <div className="flex gap-2">
          <input type="text" placeholder="Round/Stage" className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.round || ''} onChange={e => update('round', e.target.value)} />
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Tug of War format (rounds won)
  if (sportSlug === 'tug-of-war') {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center gap-4">
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamA} Rounds</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
          </div>
          <span className="self-end mb-3 opacity-20 font-bold text-xl">:</span>
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamB} Rounds</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
          </div>
        </div>
        <div className="flex gap-2">
          <input type="text" placeholder="Current Round" className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.round || ''} onChange={e => update('round', e.target.value)} />
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Power Lifting format (total score)
  if (sportSlug === 'power-lifting') {
    return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center gap-4">
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamA} Score</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
          </div>
          <span className="self-end mb-3 opacity-20 font-bold text-xl">:</span>
          <div className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] font-bold uppercase opacity-50">{match.teamB} Score</span>
            <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
          </div>
        </div>
        <div className="flex gap-2">
          <input type="text" placeholder="Event/Category" className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.round || ''} onChange={e => update('round', e.target.value)} />
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
    );
  }

  // Default (Football, Basketball etc)
  return (
      <div className="flex flex-col gap-3 w-full animate-in slide-in-from-top-2">
        <div className="flex items-center gap-4">
           <div className="flex-1 flex gap-2">
               <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamA || 0} onChange={e => update('teamA', e.target.value)} />
               <span className="self-center opacity-20 font-bold text-xl">:</span>
               <input type="number" className={`w-full p-2 rounded text-center font-bold text-xl ${theme.input}`} value={data.teamB || 0} onChange={e => update('teamB', e.target.value)} />
           </div>
        </div>
        <div className="flex gap-2">
          <input type="text" placeholder="Period (e.g. 1st Half, Q1)" className={`flex-1 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.period || ''} onChange={e => update('period', e.target.value)} />
          {['futsal', 'football'].includes(sportSlug) && (
            <input type="text" placeholder="Time (e.g. 45')" className={`w-20 p-2 rounded-lg text-xs font-bold ${theme.input}`} value={data.time || ''} onChange={e => update('time', e.target.value)} />
          )}
          <button onClick={() => onSave(match.id, data)} className={`px-4 rounded-lg bg-green-500 text-white font-bold text-xs`}>SAVE</button>
          <button onClick={onCancel} className={`px-4 rounded-lg ${theme.buttonSecondary} text-xs`}>CANCEL</button>
        </div>
      </div>
  );
}
