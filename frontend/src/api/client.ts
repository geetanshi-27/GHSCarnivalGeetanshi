const API_BASE = import.meta.env.VITE_API_URL || '/api';

export interface Sport {
  id: string;
  name: string;
  slug: string;
  createdAt: string;
  updatedAt: string;
}

export interface Match {
  id: string;
  sportId: string;
  sport?: Sport;
  teamA: string;
  teamB: string;
  status: 'UPCOMING' | 'LIVE' | 'COMPLETED';
  startTime?: string;
  venue?: string;
  score?: {
    teamA?: {
      score?: string;
      detail?: string;
    };
    teamB?: {
      score?: string;
      detail?: string;
    };
    [key: string]: any;
  };
  createdAt: string;
  updatedAt: string;
}

export interface Announcement {
  id: string;
  title: string;
  body: string;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
}

// Helper to get CSRF token from cookie
function getCSRFToken(): string | null {
  const match = document.cookie.match(/csrf_token=([^;]+)/);
  return match ? match[1] : null;
}

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  try {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options?.headers,
    };

    // Add CSRF token for state-changing operations
    const method = options?.method?.toUpperCase() || 'GET';
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method)) {
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        (headers as Record<string, string>)['X-CSRF-Token'] = csrfToken;
      }
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      credentials: 'include', // Include cookies
      headers,
    });

    if (!response.ok) {
      // Try to get error details from response
      let errorMessage = `API Error: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errorMessage = errorData.detail;
        }
      } catch {
        // If response is not JSON, use status text
      }
      throw new Error(errorMessage);
    }

    return response.json();
  } catch (error) {
    // Network errors or other fetch failures
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Network error: Unable to connect to server');
  }
}

export const api = {
  // Sports
  getSports: () => fetchAPI<{ items: Sport[] }>('/public/sports'),
  getSport: (slug: string) => fetchAPI<{ item: Sport }>(`/public/sports/${slug}`),

  // Matches
  getMatches: (params?: { sport_slug?: string; status?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.sport_slug) searchParams.set('sport_slug', params.sport_slug);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return fetchAPI<{ items: Match[] }>(`/public/matches${query}`);
  },
  
  getMatch: (matchId: string) => fetchAPI<{ item: Match }>(`/public/matches/${matchId}`),

  // Announcements
  getAnnouncements: (limit = 20) => 
    fetchAPI<{ items: Announcement[] }>(`/public/announcements?limit=${limit}`),

  // Live Stream (SSE)
  createLiveStream: (params?: { sport_slug?: string; interval?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.sport_slug) searchParams.set('sport_slug', params.sport_slug);
    if (params?.interval) searchParams.set('interval', params.interval.toString());
    
    const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
    return new EventSource(`${API_BASE}/public/live-stream${query}`);
  },

  createMatchStream: (matchId: string, interval = 3) => {
    return new EventSource(`${API_BASE}/public/live-stream/match/${matchId}?interval=${interval}`);
  },

  // Admin endpoints (require authentication via HttpOnly cookies)
  admin: {
    // Auth
    login: (email: string, password: string) =>
      fetchAPI<{ user: any; csrf_token: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      }),
    
    me: () => fetchAPI<{ item: any }>('/auth/me'),
    
    logout: () => 
      fetchAPI<{ message: string }>('/auth/logout', { method: 'POST' }),
    
    updateProfile: (email?: string, password?: string, currentPassword?: string) =>
      fetchAPI<{ message: string; user: any }>('/auth/profile', {
        method: 'PATCH',
        body: JSON.stringify({
          email: email || undefined,
          password: password || undefined,
          current_password: currentPassword
        })
      }),

    // Match Management
    createMatch: (data: { sportSlug: string; teamA: string; teamB: string; status?: string; startTime?: string; venue?: string; score?: any }) =>
      fetchAPI<{ item: Match }>('/admin/matches', {
        method: 'POST',
        body: JSON.stringify(data)
      }),
    
    getMatches: (params?: { sport_id?: string; status?: string }) => {
      const searchParams = new URLSearchParams();
      if (params?.sport_id) searchParams.set('sport_id', params.sport_id);
      if (params?.status) searchParams.set('status', params.status);
      const query = searchParams.toString() ? `?${searchParams.toString()}` : '';
      return fetchAPI<{ items: Match[] }>(`/admin/matches${query}`);
    },

    getMatch: (matchId: string) =>
      fetchAPI<{ item: Match }>(`/admin/matches/${matchId}`),

    updateMatch: (matchId: string, data: { teamA?: string; teamB?: string; status?: string; startTime?: string; venue?: string; score?: any }) =>
      fetchAPI<{ item: Match }>(`/admin/matches/${matchId}`, {
        method: 'PATCH',
        body: JSON.stringify(data)
      }),

    deleteMatch: (matchId: string) =>
      fetchAPI<{ message: string }>(`/admin/matches/${matchId}`, {
        method: 'DELETE'
      }),

    // User Management (SUPER_ADMIN only)
    getUsers: () =>
      fetchAPI<{ items: any[] }>('/admin/users'),

    updateUser: (userId: string, data: { email?: string; password?: string }) =>
      fetchAPI<{ item: any }>(`/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify(data)
      })
  }
};
