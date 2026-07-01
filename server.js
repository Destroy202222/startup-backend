const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

const SUPER_ADMIN_EMAIL = 'startup@mail.ru';
const DB_PATH = path.join(__dirname, 'database', 'db.json');

// ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =====
function initDB() {
    const dbDir = path.join(__dirname, 'database');
    if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
    
    if (!fs.existsSync(DB_PATH)) {
        const initialDB = {
            users: [],
            servers: [],
            admins: [SUPER_ADMIN_EMAIL],
            stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 },
            matches: [] // <-- НОВОЕ: хранилище матчей 5v5
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(initialDB, null, 2));
        console.log('? База данных создана с супер-админом:', SUPER_ADMIN_EMAIL);
    } else {
        const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
        if (!db.matches) {
            db.matches = [];
            fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
        }
    }
}

function readDB() {
    try {
        const data = fs.readFileSync(DB_PATH, 'utf8');
        const db = JSON.parse(data);
        if (!db.matches) db.matches = [];
        return db;
    } catch (error) {
        console.error('? Ошибка чтения БД:', error);
        return { users: [], servers: [], admins: [SUPER_ADMIN_EMAIL], stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 }, matches: [] };
    }
}

function writeDB(data) {
    try {
        if (!data.matches) data.matches = [];
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('? Ошибка записи БД:', error);
        return false;
    }
}

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
function findUserByEmail(email) {
    const db = readDB();
    return db.users.find(u => u.email === email);
}

function findUserByUsername(username) {
    const db = readDB();
    return db.users.find(u => u.username === username);
}

function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, username: user.username },
        process.env.JWT_SECRET || 'default_secret_key_change_me',
        { expiresIn: '7d' }
    );
}

function verifyToken(token) {
    try { return jwt.verify(token, process.env.JWT_SECRET || 'default_secret_key_change_me'); } 
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

function adminMiddleware(req, res, next) {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.status(403).json({ error: 'Пользователь не найден' });
    if (!db.admins.includes(user.email) && user.email !== SUPER_ADMIN_EMAIL)
        return res.status(403).json({ error: 'Недостаточно прав' });
    if (user.email === SUPER_ADMIN_EMAIL && !db.admins.includes(user.email)) {
        db.admins.push(user.email);
        writeDB(db);
    }
    next();
}

// ===== АУТЕНТИФИКАЦИЯ =====
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, standoffId, password } = req.body;
        if (!username || !email || !standoffId || !password)
            return res.status(400).json({ error: 'Все поля обязательны' });
        if (username.length < 3 || username.length > 20)
            return res.status(400).json({ error: 'Имя от 3 до 20 символов' });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ error: 'Неверный email' });
        if (!/^\d+$/.test(standoffId)) return res.status(400).json({ error: 'ID только цифры' });
        if (password.length < 8) return res.status(400).json({ error: 'Пароль минимум 8 символов' });
        
        const db = readDB();
        if (findUserByEmail(email)) return res.status(400).json({ error: 'Email уже используется' });
        if (findUserByUsername(username)) return res.status(400).json({ error: 'Имя уже используется' });
        if (db.users.find(u => u.standoffId === standoffId))
            return res.status(400).json({ error: 'ID Standoff 2 уже используется' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: uuidv4(),
            username,
            email,
            standoffId,
            password: hashedPassword,
            vkId: null,
            matches: 0,
            kills: 0,
            deaths: 0,
            serverMatches: 0,
            kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            registered: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };
        db.users.push(newUser);
        if (email === SUPER_ADMIN_EMAIL && !db.admins.includes(email)) db.admins.push(email);
        writeDB(db);
        
        const token = generateToken(newUser);
        res.json({
            success: true,
            token,
            user: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email,
                standoffId: newUser.standoffId,
                matches: newUser.matches,
                serverMatches: newUser.serverMatches,
                kills: newUser.kills,
                deaths: newUser.deaths,
                kdHistory: newUser.kdHistory
            }
        });
    } catch (error) {
        console.error('? Registration error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
        const user = findUserByEmail(email);
        if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
        if (!await bcrypt.compare(password, user.password))
            return res.status(401).json({ error: 'Неверный email или пароль' });
        
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === user.id);
        if (userIndex !== -1) {
            db.users[userIndex].lastLogin = new Date().toISOString();
            if (email === SUPER_ADMIN_EMAIL && !db.admins.includes(email)) db.admins.push(email);
            writeDB(db);
        }
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
        console.error('? Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/auth/vk', async (req, res) => {
    try {
        const { vkId, vkName, vkAvatar } = req.body;
        if (!vkId) return res.status(400).json({ error: 'ID VK обязателен' });
        const db = readDB();
        let user = db.users.find(u => u.vkId === vkId);
        if (!user) {
            const username = vkName.replace(/\s/g, '_').toLowerCase();
            let finalUsername = username;
            let counter = 1;
            while (findUserByUsername(finalUsername)) { finalUsername = `${username}_${counter}`; counter++; }
            const newUser = {
                id: uuidv4(),
                username: finalUsername,
                email: `${vkId}@vk.com`,
                standoffId: vkId.toString().slice(0, 9),
                password: await bcrypt.hash(`vk_${vkId}`, 10),
                vkId: vkId.toString(),
                vkAvatar: vkAvatar || '',
                matches: 0,
                serverMatches: 0,
                kills: 0,
                deaths: 0,
                kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                registered: new Date().toISOString(),
                lastLogin: new Date().toISOString()
            };
            db.users.push(newUser);
            writeDB(db);
            user = newUser;
        } else {
            const userIndex = db.users.findIndex(u => u.id === user.id);
            if (userIndex !== -1) { db.users[userIndex].lastLogin = new Date().toISOString(); writeDB(db); }
        }
        const token = generateToken(user);
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                standoffId: user.standoffId,
                vkId: user.vkId,
                vkAvatar: user.vkAvatar,
                matches: user.matches,
                serverMatches: user.serverMatches || 0,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) {
        console.error('? VK auth error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const user = db.users.find(u => u.id === req.user.id);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            standoffId: user.standoffId,
            vkId: user.vkId,
            vkAvatar: user.vkAvatar,
            matches: user.matches,
            serverMatches: user.serverMatches || 0,
            kills: user.kills,
            deaths: user.deaths,
            kdHistory: user.kdHistory,
            registered: user.registered,
            lastLogin: user.lastLogin
        });
    } catch (error) {
        console.error('? Get user error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ===== СЕРВЕРА =====
app.get('/api/servers', (req, res) => {
    try {
        const db = readDB();
        res.json(db.servers);
    } catch (error) {
        console.error('? Get servers error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { name, lobby, playerId, map } = req.body;
        if (!name || !lobby || !playerId || !map)
            return res.status(400).json({ error: 'Все поля обязательны' });
        const db = readDB();
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
        db.servers.push(newServer);
        writeDB(db);
        res.json({ success: true, server: newServer });
    } catch (error) {
        console.error('? Create server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/servers/:id', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const serverId = parseInt(req.params.id);
        const db = readDB();
        db.servers = db.servers.filter(s => s.id !== serverId);
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        console.error('? Delete server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ===== АДМИНЫ =====
app.get('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try { const db = readDB(); res.json(db.admins); } 
    catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email обязателен' });
        const db = readDB();
        const user = db.users.find(u => u.email === email);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        if (db.admins.includes(email)) return res.status(400).json({ error: 'Уже администратор' });
        db.admins.push(email);
        writeDB(db);
        res.json({ success: true, admins: db.admins });
    } catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/admins/:email', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const email = decodeURIComponent(req.params.email);
        const db = readDB();
        db.admins = db.admins.filter(e => e !== email);
        writeDB(db);
        res.json({ success: true, admins: db.admins });
    } catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ====================================================
// ===== НОВЫЙ РАЗДЕЛ: МАТЧИ 5v5 =====
// ====================================================

// Получить все матчи
app.get('/api/matches', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db.matches || []);
    } catch (error) {
        console.error('? Get matches error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получить конкретный матч по ID
app.get('/api/matches/:id', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const match = db.matches.find(m => m.id === req.params.id);
        if (!match) return res.status(404).json({ error: 'Матч не найден' });
        res.json(match);
    } catch (error) {
        console.error('? Get match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Создать новый матч
app.post('/api/matches', authMiddleware, (req, res) => {
    try {
        const { players } = req.body;
        if (!players || players.length < 10) {
            return res.status(400).json({ error: 'Нужно минимум 10 игроков' });
        }

        const db = readDB();
        const matchId = 'match_' + Date.now();
        
        // Перемешиваем игроков
        const shuffled = [...players].sort(() => Math.random() - 0.5);
        const half = Math.ceil(shuffled.length / 2);
        const terrorist = shuffled.slice(0, half).map(p => ({ username: p, captain: false }));
        const counter = shuffled.slice(half).map(p => ({ username: p, captain: false }));
        
        // Назначаем капитанов
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

        db.matches.push(newMatch);
        writeDB(db);
        
        res.json({ success: true, match: newMatch });
    } catch (error) {
        console.error('? Create match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Обновить матч (баны, статус, ссылка, результат)
app.put('/api/matches/:id', authMiddleware, (req, res) => {
    try {
        const matchId = req.params.id;
        const updates = req.body;
        const db = readDB();
        
        const matchIndex = db.matches.findIndex(m => m.id === matchId);
        if (matchIndex === -1) return res.status(404).json({ error: 'Матч не найден' });
        
        // Обновляем только разрешённые поля
        const match = db.matches[matchIndex];
        if (updates.bans) match.bans = updates.bans;
        if (updates.selectedMap) match.selectedMap = updates.selectedMap;
        if (updates.link !== undefined) match.link = updates.link;
        if (updates.resultImage !== undefined) match.resultImage = updates.resultImage;
        if (updates.status) match.status = updates.status;
        if (updates.currentBanTurn) match.currentBanTurn = updates.currentBanTurn;
        
        db.matches[matchIndex] = match;
        writeDB(db);
        
        res.json({ success: true, match: match });
    } catch (error) {
        console.error('? Update match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Удалить матч
app.delete('/api/matches/:id', authMiddleware, (req, res) => {
    try {
        const matchId = req.params.id;
        const db = readDB();
        db.matches = db.matches.filter(m => m.id !== matchId);
        writeDB(db);
        res.json({ success: true });
    } catch (error) {
        console.error('? Delete match error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ====================================================
// ===== СТАТИСТИКА =====
// ====================================================

app.post('/api/users/:userId/stats', authMiddleware, (req, res) => {
    try {
        const userId = req.params.userId;
        const { kills, deaths } = req.body;
        if (userId !== req.user.id) return res.status(403).json({ error: 'Недостаточно прав' });
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === userId);
        if (userIndex === -1) return res.status(404).json({ error: 'Пользователь не найден' });
        const user = db.users[userIndex];
        user.kills += kills || 0;
        user.deaths += deaths || 0;
        user.matches += 1;
        const kd = user.deaths > 0 ? (user.kills / user.deaths) : user.kills;
        user.kdHistory.push(parseFloat(kd.toFixed(2)));
        if (user.kdHistory.length > 10) user.kdHistory.shift();
        writeDB(db);
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                matches: user.matches,
                serverMatches: user.serverMatches || 0,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/top-players', (req, res) => {
    try {
        const db = readDB();
        const topPlayers = db.users.map(user => ({
            username: user.username,
            standoffId: user.standoffId,
            kills: user.kills,
            matches: user.matches,
            serverMatches: user.serverMatches || 0,
            kd: user.deaths > 0 ? (user.kills / user.deaths).toFixed(2) : user.kills.toFixed(2)
        })).sort((a, b) => b.serverMatches - a.serverMatches).slice(0, 10);
        res.json(topPlayers);
    } catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/stats', (req, res) => {
    try {
        const db = readDB();
        res.json({
            online: Math.floor(Math.random() * 150) + 50,
            tournaments: db.stats.totalTournaments || 0,
            servers: db.servers.length,
            totalUsers: db.users.length,
            matches: db.matches ? db.matches.length : 0
        });
    } catch (error) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ===== ЗАПУСК =====
initDB();

app.listen(PORT, '0.0.0.0', () => {
    console.log(`?? Server running on port ${PORT}`);
    console.log(`?? Database: ${DB_PATH}`);
    console.log(`?? Супер-админ: ${SUPER_ADMIN_EMAIL}`);
    console.log(`?? JWT_SECRET: ${process.env.JWT_SECRET ? '? Установлен' : '? НЕ УСТАНОВЛЕН (используется default)'}`);
});

process.on('uncaughtException', (error) => {
    console.error('?? Необработанное исключение:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('?? Необработанный rejection:', reason);
});
