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

// ===== ПОДКЛЮЧЕНИЕ К SUPABASE =====
const SUPABASE_URL = 'https://juxdegzpajulauxecyml.supabase.co';
const SUPABASE_KEY = 'sb_publishable_diBYI198jT9-OvGLj6-6-w_I9xTMx9_';

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

// ===== НОВЫЙ ЭНДПОИНТ ДЛЯ ТЕЛЕГРАМ =====
app.post('/api/auth/telegram', async (req, res) => {
    try {
        const { telegramId, firstName, lastName, username } = req.body;
        
        if (!telegramId) {
            return res.status(400).json({ error: 'Telegram ID обязателен' });
        }

        // Проверяем, есть ли пользователь с таким telegramId
        const { data: existing, error: checkError } = await supabase
            .from('users')
            .select('*')
            .eq('vkId', telegramId.toString())
            .maybeSingle();

        if (existing) {
            // Пользователь уже есть — логиним
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

        // Создаём нового пользователя
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

        res.json({
            online: Math.floor(Math.random() * 150) + 50,
            tournaments: 0,
            servers: serversCount || 0,
            totalUsers: totalUsers || 0,
            pendingCount: 0,
            matches: 0
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
