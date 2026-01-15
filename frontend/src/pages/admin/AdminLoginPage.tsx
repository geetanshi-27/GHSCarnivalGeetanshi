import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '../../supabaseClient';

// Import Inter font in index.css or use this style:
// @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;900&display=swap');

export default function AdminLoginPage() {
  const [isDark, setIsDark] = useState(true);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const checkSession = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (session) navigate('/admin', { replace: true });
    };
    checkSession();
  }, [navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const internalEmail = `${username.trim().toLowerCase()}@ghs.local`;
      const { data, error } = await supabase.auth.signInWithPassword({
        email: internalEmail,
        password: password,
      });
      if (error) throw error;
      if (data.user) navigate('/admin', { replace: true });
    } catch (error: any) {
      alert("Invalid Username or Password");
    } finally {
      setLoading(false);
    }
  };

  const theme = {
    bg: isDark ? 'bg-[#0b0b0d]' : 'bg-[#f6f4f1]',
    card: isDark ? 'bg-[#141417] border-[#2e1065] shadow-2xl' : 'bg-white border-[#efe9e1] shadow-xl',
    input: isDark ? 'bg-[#0b0b0d] border-slate-800 text-white placeholder-slate-600' : 'bg-gray-50 border-gray-200 text-gray-800 placeholder-gray-400',
    text: isDark ? 'text-white' : 'text-gray-800',
    subtext: isDark ? 'text-slate-400' : 'text-gray-500'
  };

  const inputStyle = `w-full h-14 px-6 rounded-2xl outline-none border transition-all duration-300
   focus:ring-4 focus:ring-orange-500/10 focus:border-orange-500 ${theme.input} font-inter`;
  const btnStyle = `w-full h-14 mt-4 text-white font-bold rounded-2xl bg-gradient-to-br from-[#f97316] to-[#ea580c]
  hover:scale-[1.02] active:scale-[0.98] transition-all duration-300 uppercase tracking-[0.2em] text-sm font-inter disabled:opacity-50`;

  return (
    <div className={`min-h-screen flex items-center justify-center p-5 relative transition-colors duration-500 ${theme.bg} font-inter`}>
      <BackgroundGlow isDark={isDark} />
      <ThemeToggle isDark={isDark} onToggle={() => setIsDark(!isDark)} />

      <div className={`w-full max-w-[400px] rounded-[32px] p-10 border z-10 text-center 
        transition-all duration-500 transform hover:-translate-y-2 ${theme.card}`}>
        <div className="mb-10 group">
          <h2 className={`text-2xl font-black tracking-[0.25em] uppercase ${theme.text} font-inter`}>
            Admin Login
          </h2>
          <div className="h-1 w-12 bg-orange-500 mx-auto mt-2 rounded-full" />
        </div>

        <form onSubmit={handleLogin} className="flex flex-col gap-5">
          <div className="relative group">
            <input
              type="text"
              placeholder="Username"
              className={inputStyle}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="relative group">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              className={inputStyle}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-orange-500 transition-colors"
            >
              {showPassword ? <EyeOffIcon /> : <EyeIcon />}
            </button>
          </div>

          <button type="submit" className={btnStyle} disabled={loading}>
            <span className="relative z-10">{loading ? 'Verifying...' : 'Authenticate'}</span>
          </button>
        </form>

        <p className={`mt-10 text-[9px] uppercase tracking-[0.3em] opacity-30 font-bold ${theme.subtext}`}>
          Secured Gateway
        </p>
      </div>
    </div>
  );
}


// Components for theme toggle 
const EyeIcon = () => (
  <svg 
    width="20" 
    height="20" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round"
  >
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg 
    width="20" 
    height="20" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round"
  >
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

interface DarkModeProps {
  isDark: boolean;
}

function BackgroundGlow({ isDark }: DarkModeProps) {
  const glowColor = isDark ? 'bg-orange-600/5' : 'bg-orange-400/15';

  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden">
      <div 
        className={`absolute top-[10%] left-[-5%] w-[500px] h-[500px] rounded-full blur-[120px] ${glowColor}`} 
      />
    </div>
  );
}

interface ThemeToggleProps extends DarkModeProps {
  onToggle: () => void;
}

function ThemeToggle({ isDark, onToggle }: ThemeToggleProps) {
  return (
    <button 
      type="button" 
      onClick={onToggle} 
      className="absolute top-8 right-8 p-3 rounded-2xl border bg-white/5 border-white/10 z-50"
    >
      {isDark ? "🌙" : "☀️"}
    </button>
  );
}
