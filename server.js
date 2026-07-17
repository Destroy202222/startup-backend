const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===== НАСТРОЙКИ =====
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ===== ПОДКЛЮЧЕНИЕ К НОВОЙ SUPABASE =====
const SUPABASE_URL = 'https://dlprylagddsmtzpmzxqy.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRscHJ5bGFnZGRzbXR6cG16eHF5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQzMDY5MjcsImV4cCI6MjA5OTg4MjkyN30.xyRO-nChHDfqFgtYkhsMOkM3F8BsZGOvacQ0zhjBuRI';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const SUPER_ADMIN_EMAIL = 'startup@mail.ru';

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, username: user.username },
        process.env.JWT_SECRET || 'default_secret_key',
        { expiresIn: '7d' }
    );
}

function verifyToken(token) {
    try { return jwt.verify(token, process.env.JWT_SECRET || 'default_secret_key'); } 
    catch { return null; }
}

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Неверный токен' });
    req.user = decoded;
    next();
}

async function isAdmin(email) {
    const { data, error } = await supabase
        .from('admins')
        .select('email')
        .eq('email', email)
        .single();
    return !error && data !== null;
}

async function adminMiddleware(req, res, next) {
    const user = req.user;
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    if (user.email === SUPER_ADMIN_EMAIL) return next();
    if (await isAdmin(user.email)) return next();
    return res.status(403).json({ error: 'Недостаточно прав' });
}

// ====================================================
// ===== АУТЕНТИФИКАЦИЯ =====
// ====================================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, standoffId, password } = req.body;
        
        if (!username || !email || !standoffId || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Имя от 3 до 20 символов' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Неверный email' });
        }
        if (!/^\d+$/.test(standoffId)) {
            return res.status(400).json({ error: 'ID только цифры' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'Пароль минимум 8 символов' });
        }

        // Проверка существующего пользователя
        const { data: existing, error: checkError } = await supabase
            .from('users')
            .select('email, username, standoffId')
            .or(`email.eq.${email},username.eq.${username},standoffId.eq.${standoffId}`);

        if (existing && existing.length > 0) {
            const u = existing[0];
            if (u.email === email) return res.status(400).json({ error: 'Email уже используется' });
            if (u.username === username) return res.status(400).json({ error: 'Имя уже используется' });
            if (u.standoffId === standoffId) return res.status(400).json({ error: 'ID уже используется' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: uuidv4(),
            username,
            email,
            standoffId,
            password: hashedPassword,
            matches: 0,
            kills: 0,
            deaths: 0,
            serverMatches: 0,
            kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            registered: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };

        const { data, error } = await supabase
            .from('users')
            .insert([newUser])
            .select()
            .single();

        if (error) throw error;

        if (email === SUPER_ADMIN_EMAIL) {
            await supabase.from('admins').upsert([{ email }], { onConflict: 'email' });
        }

        const token = generateToken(data);
        res.json({
            success: true,
            token,
            user: {
                id: data.id,
                username: data.username,
                email: data.email,
                standoffId: data.standoffId,
                matches: data.matches,
                serverMatches: data.serverMatches || 0,
                kills: data.kills,
                deaths: data.deaths,
                kdHistory: data.kdHistory
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        await supabase
            .from('users')
            .update({ lastLogin: new Date().toISOString() })
            .eq('id', user.id);

        const token = generateToken(user);
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                standoffId: user.standoffId,
                matches: user.matches,
                serverMatches: user.serverMatches || 0,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ===== ВХОД ЧЕРЕЗ TELEGRAM =====
app.post('/api/auth/telegram', async (req, res) => {
    try {
        const { telegramId, firstName, lastName, username } = req.body;
        
        if (!telegramId) {
            return res.status(400).json({ error: 'Telegram ID обязателен' });
        }

        const { data: existing, error: checkError } = await supabase
            .from('users')
            .select('*')
            .eq('vkId', telegramId.toString())
            .maybeSingle();

        if (existing) {
            const token = generateToken(existing);
            return res.json({
                success: true,
                token,
                user: {
                    id: existing.id,
                    username: existing.username,
                    email: existing.email,
                    standoffId: existing.standoffId,
                    matches: existing.matches,
                    serverMatches: existing.serverMatches || 0,
                    kills: existing.kills,
                    deaths: existing.deaths,
                    kdHistory: existing.kdHistory
                }
            });
        }

        const newUsername = username || firstName.toLowerCase() + '_' + telegramId;
        const email = `${telegramId}@telegram.com`;
        const standoffId = telegramId.toString().slice(0, 9);

        const hashedPassword = await bcrypt.hash(`tg_${telegramId}`, 10);
        const newUser = {
            id: uuidv4(),
            username: newUsername,
            email,
            standoffId,
            password: hashedPassword,
            vkId: telegramId.toString(),
            matches: 0,
            kills: 0,
            deaths: 0,
            serverMatches: 0,
            kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            registered: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };

        const { data, error } = await supabase
            .from('users')
            .insert([newUser])
            .select()
            .single();

        if (error) throw error;

        const token = generateToken(data);
        res.json({
            success: true,
            token,
            user: {
                id: data.id,
                username: data.username,
                email: data.email,
                standoffId: data.standoffId,
                matches: data.matches,
                serverMatches: data.serverMatches || 0,
                kills: data.kills,
                deaths: data.deaths,
                kdHistory: data.kdHistory
            }
        });
    } catch (error) {
        console.error('Telegram auth error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', req.user.id)
            .single();

        if (error || !user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            standoffId: user.standoffId,
            matches: user.matches,
            serverMatches: user.serverMatches || 0,
            kills: user.kills,
            deaths: user.deaths,
            kdHistory: user.kdHistory,
            registered: user.registered,
            lastLogin: user.lastLogin
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== СЕРВЕРА =====
// ====================================================

app.get('/api/servers', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('servers')
            .select('*')
            .order('createdAt', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Get servers error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, lobby, playerId, map } = req.body;
        if (!name || !lobby || !playerId || !map) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }

        const newServer = {
            id: Date.now(),
            name,
            lobby,
            playerId,
            map,
            status: 'online',
            pending: [],
            createdAt: new Date().toISOString(),
            createdBy: req.user.id
        };

        const { data, error } = await supabase
            .from('servers')
            .insert([newServer])
            .select()
            .single();

        if (error) throw error;
        res.json({ success: true, server: data });
    } catch (error) {
        console.error('Create server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/servers/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const serverId = parseInt(req.params.id);
        const { error } = await supabase
            .from('servers')
            .delete()
            .eq('id', serverId);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Delete server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== ОЧЕРЕДИ =====
// ====================================================

app.get('/api/servers/:serverId/pending', authMiddleware, async (req, res) => {
    try {
        const serverId = parseInt(req.params.serverId);
        const { data, error } = await supabase
            .from('servers')
            .select('pending')
            .eq('id', serverId)
            .single();

        if (error) throw error;
        res.json(data?.pending || []);
    } catch (error) {
        console.error('Get pending error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/pending', authMiddleware, async (req, res) => {
    try {
        const serverId = parseInt(req.params.serverId);
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Имя пользователя обязательно' });

        const { data: server, error: serverError } = await supabase
            .from('servers')
            .select('pending')
            .eq('id', serverId)
            .single();

        if (serverError || !server) {
            return res.status(404).json({ error: 'Сервер не найден' });
        }

        const pending = server.pending || [];
        if (pending.includes(username)) {
            return res.status(400).json({ error: 'Игрок уже в очереди' });
        }

        pending.push(username);
        const { data, error } = await supabase
            .from('servers')
            .update({ pending })
            .eq('id', serverId)
            .select();

        if (error) throw error;
        res.json({ success: true, queue: pending });
    } catch (error) {
        console.error('Add pending error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/servers/:serverId/pending/:username', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const serverId = parseInt(req.params.serverId);
        const username = req.params.username;

        const { data: server, error: serverError } = await supabase
            .from('servers')
            .select('pending')
            .eq('id', serverId)
            .single();

        if (serverError || !server) {
            return res.status(404).json({ error: 'Сервер не найден' });
        }

        const pending = (server.pending || []).filter(p => p !== username);
        const { data, error } = await supabase
            .from('servers')
            .update({ pending })
            .eq('id', serverId)
            .select();

        if (error) throw error;
        res.json({ success: true, queue: pending });
    } catch (error) {
        console.error('Remove pending error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/credit/:username', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const serverId = parseInt(req.params.serverId);
        const username = req.params.username;

        const { data: server, error: serverError } = await supabase
            .from('servers')
            .select('pending')
            .eq('id', serverId)
            .single();

        if (serverError || !server) {
            return res.status(404).json({ error: 'Сервер не найден' });
        }

        const pending = (server.pending || []).filter(p => p !== username);
        await supabase
            .from('servers')
            .update({ pending })
            .eq('id', serverId);

        const { data: user, error: userError } = await supabase
            .from('users')
            .select('serverMatches')
            .eq('username', username)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const newMatches = (user.serverMatches || 0) + 1;
        await supabase
            .from('users')
            .update({ serverMatches: newMatches })
            .eq('username', username);

        res.json({ 
            success: true, 
            message: `Игрок ${username} зачислен`,
            queue: pending
        });
    } catch (error) {
        console.error('Credit player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== АДМИНЫ =====
// ====================================================

app.get('/api/admins', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('admins')
            .select('email');

        if (error) throw error;
        res.json(data.map(a => a.email) || []);
    } catch (error) {
        console.error('Get admins error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/admins', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email обязателен' });

        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('email', email)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const { data, error } = await supabase
            .from('admins')
            .insert([{ email }])
            .select();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: 'Уже администратор' });
            }
            throw error;
        }

        res.json({ success: true, admins: data.map(a => a.email) });
    } catch (error) {
        console.error('Add admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/admins/:email', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const email = decodeURIComponent(req.params.email);
        if (email === SUPER_ADMIN_EMAIL) {
            return res.status(400).json({ error: 'Нельзя удалить главного администратора' });
        }

        const { error } = await supabase
            .from('admins')
            .delete()
            .eq('email', email);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Remove admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== ПОИСК 5v5 =====
// ====================================================

app.get('/api/search-players', authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('search_players')
            .select('username')
            .order('addedAt', { ascending: true });

        if (error) throw error;
        res.json(data.map(p => p.username) || []);
    } catch (error) {
        console.error('Get search players error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/search-players', authMiddleware, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Имя пользователя обязательно' });

        const { data, error } = await supabase
            .from('search_players')
            .insert([{ username }])
            .select();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: 'Уже в поиске' });
            }
            throw error;
        }

        res.json({ success: true, players: data.map(p => p.username) });
    } catch (error) {
        console.error('Add search player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/search-players', authMiddleware, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Имя пользователя обязательно' });

        const { error } = await supabase
            .from('search_players')
            .delete()
            .eq('username', username);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Remove search player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== МАТЧИ 5v5 =====
// ====================================================

app.get('/api/matches', authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('matches')
            .select('*')
            .order('createdAt', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        console.error('Get matches error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/matches/:id', authMiddleware, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('matches')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error || !data) {
            return res.status(404).json({ error: 'Матч не найден' });
        }

        res.json(data);
    } catch (error) {
        console.error('Get match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/matches', authMiddleware, async (req, res) => {
    try {
        const { players } = req.body;
        if (!players || players.length < 10) {
            return res.status(400).json({ error: 'Нужно минимум 10 игроков' });
        }

        const matchId = 'match_' + Date.now();
        
        const shuffled = [...players].sort(() => Math.random() - 0.5);
        const half = Math.ceil(shuffled.length / 2);
        const terrorist = shuffled.slice(0, half).map(p => ({ username: p, captain: false }));
        const counter = shuffled.slice(half).map(p => ({ username: p, captain: false }));
        
        if (terrorist.length > 0) terrorist[0].captain = true;
        if (counter.length > 0) counter[0].captain = true;

        const newMatch = {
            id: matchId,
            terrorist: terrorist,
            counter: counter,
            bans: [],
            selectedMap: null,
            link: null,
            resultImage: null,
            status: 'ban_phase',
            currentBanTurn: 'terrorist',
            createdAt: new Date().toISOString(),
            createdBy: req.user.id
        };

        const { data, error } = await supabase
            .from('matches')
            .insert([newMatch])
            .select()
            .single();

        if (error) throw error;
        res.json({ success: true, match: data });
    } catch (error) {
        console.error('Create match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/matches/:id', authMiddleware, async (req, res) => {
    try {
        const matchId = req.params.id;
        const updates = req.body;

        const { data, error } = await supabase
            .from('matches')
            .update(updates)
            .eq('id', matchId)
            .select()
            .single();

        if (error) throw error;
        res.json({ success: true, match: data });
    } catch (error) {
        console.error('Update match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/matches/:id', authMiddleware, async (req, res) => {
    try {
        const matchId = req.params.id;
        const { error } = await supabase
            .from('matches')
            .delete()
            .eq('id', matchId);

        if (error) throw error;
        res.json({ success: true });
    } catch (error) {
        console.error('Delete match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== СТАТИСТИКА =====
// ====================================================

app.get('/api/stats', async (req, res) => {
    try {
        const { count: totalUsers, error: usersError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });

        if (usersError) throw usersError;

        const { count: serversCount, error: serversError } = await supabase
            .from('servers')
            .select('*', { count: 'exact', head: true });

        if (serversError) throw serversError;

        const { count: matchesCount, error: matchesError } = await supabase
            .from('matches')
            .select('*', { count: 'exact', head: true });

        if (matchesError) throw matchesError;

        const { data: searchData, error: searchError } = await supabase
            .from('search_players')
            .select('username');

        if (searchError) throw searchError;

        const { data: serversData, error: serversDataError } = await supabase
            .from('servers')
            .select('pending');

        if (serversDataError) throw serversDataError;

        let pendingCount = 0;
        for (const server of serversData || []) {
            if (server.pending) {
                pendingCount += server.pending.length;
            }
        }

        res.json({
            online: Math.floor(Math.random() * 150) + 50,
            tournaments: 0,
            servers: serversCount || 0,
            totalUsers: totalUsers || 0,
            pendingCount: pendingCount,
            matches: matchesCount || 0,
            searchCount: searchData ? searchData.length : 0
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== ТОП ИГРОКОВ =====
// ====================================================

app.get('/api/top-players', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('username, standoffId, kills, matches, serverMatches, deaths')
            .order('serverMatches', { ascending: false })
            .limit(10);

        if (error) throw error;

        const topPlayers = (data || []).map(user => ({
            username: user.username,
            standoffId: user.standoffId,
            kills: user.kills || 0,
            matches: user.matches || 0,
            serverMatches: user.serverMatches || 0,
            kd: user.deaths > 0 ? (user.kills / user.deaths).toFixed(2) : (user.kills > 0 ? user.kills.toFixed(2) : '0.00')
        }));

        res.json(topPlayers);
    } catch (error) {
        console.error('Get top players error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== СИНХРОНИЗАЦИЯ =====
// ====================================================

app.post('/api/sync', authMiddleware, async (req, res) => {
    try {
        const { users, servers, admins } = req.body;
        const results = [];

        if (users) {
            for (const user of users) {
                const { data, error } = await supabase
                    .from('users')
                    .upsert([user], { onConflict: 'id' })
                    .select();
                results.push({ table: 'users', data, error });
            }
        }

        if (servers) {
            for (const server of servers) {
                const { data, error } = await supabase
                    .from('servers')
                    .upsert([server], { onConflict: 'id' })
                    .select();
                results.push({ table: 'servers', data, error });
            }
        }

        if (admins) {
            for (const admin of admins) {
                const { data, error } = await supabase
                    .from('admins')
                    .upsert([{ email: admin }], { onConflict: 'email' })
                    .select();
                results.push({ table: 'admins', data, error });
            }
        }

        res.json({ success: true, results });
    } catch (error) {
        console.error('Sync error:', error);
        res.status(500).json({ error: 'Ошибка синхронизации' });
    }
});

app.get('/api/sync', authMiddleware, async (req, res) => {
    try {
        const [users, servers, admins] = await Promise.all([
            supabase.from('users').select('*'),
            supabase.from('servers').select('*'),
            supabase.from('admins').select('email')
        ]);

        res.json({
            users: users.data || [],
            servers: servers.data || [],
            admins: (admins.data || []).map(a => a.email)
        });
    } catch (error) {
        console.error('Get sync data error:', error);
        res.status(500).json({ error: 'Ошибка получения данных' });
    }
});

// ====================================================
// ===== ЗАПУСК =====
// ====================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Connected to Supabase`);
    console.log(`👑 Супер-админ: ${SUPER_ADMIN_EMAIL}`);
});

process.on('uncaughtException', (error) => {
    console.error('🔥 Uncaught exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 Unhandled rejection:', reason);
});
