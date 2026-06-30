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
 
// ===== НАСТРОЙКИ =====
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json());
 
// ===== СУПЕР-АДМИН =====
const SUPER_ADMIN_EMAIL = 'startup@mail.ru';
 
// ===== БАЗА ДАННЫХ =====
const DB_PATH = path.join(__dirname, 'database', 'db.json');
 
function initDB() {
    const dbDir = path.join(__dirname, 'database');
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }
    
    let db;
    if (!fs.existsSync(DB_PATH)) {
        db = {
            users: [],
            servers: [],
            admins: [SUPER_ADMIN_EMAIL],
            stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 },
            pendingPlayers: [] // Новая очередь игроков
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
        console.log('✅ База данных создана с супер-админом:', SUPER_ADMIN_EMAIL);
    } else {
        db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
        if (!db.admins) db.admins = [];
        if (!db.admins.includes(SUPER_ADMIN_EMAIL)) {
            db.admins.push(SUPER_ADMIN_EMAIL);
            fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
            console.log('✅ Супер-админ добавлен в существующую БД:', SUPER_ADMIN_EMAIL);
        }
        if (!db.pendingPlayers) {
            db.pendingPlayers = [];
            fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
        }
    }
}
 
function readDB() {
    try {
        const data = fs.readFileSync(DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('❌ Ошибка чтения БД:', error);
        return { users: [], servers: [], admins: [SUPER_ADMIN_EMAIL], stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 }, pendingPlayers: [] };
    }
}
 
function writeDB(data) {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Ошибка записи БД:', error);
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
    try {
        return jwt.verify(token, process.env.JWT_SECRET || 'default_secret_key_change_me');
    } catch (error) {
        return null;
    }
}
 
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Неверный токен' });
    }
    req.user = decoded;
    next();
}
 
function adminMiddleware(req, res, next) {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(403).json({ error: 'Пользователь не найден' });
    }
    if (!db.admins.includes(user.email) && user.email !== SUPER_ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
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
        
        const db = readDB();
        if (findUserByEmail(email)) {
            return res.status(400).json({ error: 'Email уже используется' });
        }
        if (findUserByUsername(username)) {
            return res.status(400).json({ error: 'Имя уже используется' });
        }
        if (db.users.find(u => u.standoffId === standoffId)) {
            return res.status(400).json({ error: 'ID Standoff 2 уже используется' });
        }
        
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
            serverMatches: 0, // Новая статистика
            kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            registered: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };
        
        db.users.push(newUser);
        if (email === SUPER_ADMIN_EMAIL && !db.admins.includes(email)) {
            db.admins.push(email);
        }
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
        console.error('❌ Registration error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }
        const user = findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === user.id);
        if (userIndex !== -1) {
            db.users[userIndex].lastLogin = new Date().toISOString();
            if (email === SUPER_ADMIN_EMAIL && !db.admins.includes(email)) {
                db.admins.push(email);
            }
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
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/auth/vk', async (req, res) => {
    try {
        const { vkId, vkName, vkAvatar } = req.body;
        if (!vkId) {
            return res.status(400).json({ error: 'ID VK обязателен' });
        }
        const db = readDB();
        let user = db.users.find(u => u.vkId === vkId);
        
        if (!user) {
            const username = vkName.replace(/\s/g, '_').toLowerCase();
            let finalUsername = username;
            let counter = 1;
            while (findUserByUsername(finalUsername)) {
                finalUsername = `${username}_${counter}`;
                counter++;
            }
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
            if (userIndex !== -1) {
                db.users[userIndex].lastLogin = new Date().toISOString();
                writeDB(db);
            }
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
        console.error('❌ VK auth error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.get('/api/auth/me', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const user = db.users.find(u => u.id === req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
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
        console.error('❌ Get user error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== НОВЫЙ ЭНДПОИНТ: ПОЛУЧИТЬ ИГРОКОВ В ОЧЕРЕДИ =====
app.get('/api/pending-players', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db.pendingPlayers || []);
    } catch (error) {
        console.error('❌ Get pending players error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== НОВЫЙ ЭНДПОИНТ: ДОБАВИТЬ ИГРОКА В ОЧЕРЕДЬ =====
app.post('/api/pending-players', authMiddleware, (req, res) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: 'Имя пользователя обязательно' });
        }
        
        const db = readDB();
        const user = db.users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        // Проверяем, не в очереди ли уже
        if (db.pendingPlayers.some(p => p.username === username)) {
            return res.status(400).json({ error: 'Игрок уже в очереди' });
        }
        
        db.pendingPlayers.push({
            username: username,
            addedAt: new Date().toISOString()
        });
        writeDB(db);
        
        res.json({ success: true, pendingPlayers: db.pendingPlayers });
    } catch (error) {
        console.error('❌ Add pending player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== НОВЫЙ ЭНДПОИНТ: ЗАЧИСЛИТЬ ИГРОКА (увеличить serverMatches) =====
app.post('/api/pending-players/:username/credit', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const username = req.params.username;
        const db = readDB();
        
        // Находим игрока в очереди
        const pendingIndex = db.pendingPlayers.findIndex(p => p.username === username);
        if (pendingIndex === -1) {
            return res.status(404).json({ error: 'Игрок не найден в очереди' });
        }
        
        // Находим пользователя в базе
        const user = db.users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        // Увеличиваем serverMatches
        user.serverMatches = (user.serverMatches || 0) + 1;
        
        // Удаляем из очереди
        db.pendingPlayers.splice(pendingIndex, 1);
        writeDB(db);
        
        res.json({ 
            success: true, 
            message: `Игроку ${username} зачислена игра`,
            serverMatches: user.serverMatches,
            pendingPlayers: db.pendingPlayers
        });
    } catch (error) {
        console.error('❌ Credit player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== НОВЫЙ ЭНДПОИНТ: ОТМЕНИТЬ ИГРОКА (удалить из очереди) =====
app.delete('/api/pending-players/:username', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const username = req.params.username;
        const db = readDB();
        
        const pendingIndex = db.pendingPlayers.findIndex(p => p.username === username);
        if (pendingIndex === -1) {
            return res.status(404).json({ error: 'Игрок не найден в очереди' });
        }
        
        db.pendingPlayers.splice(pendingIndex, 1);
        writeDB(db);
        
        res.json({ 
            success: true, 
            message: `Игрок ${username} удалён из очереди`,
            pendingPlayers: db.pendingPlayers
        });
    } catch (error) {
        console.error('❌ Cancel player error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== СЕРВЕРА =====
app.get('/api/servers', (req, res) => {
    try {
        const db = readDB();
        res.json(db.servers);
    } catch (error) {
        console.error('❌ Get servers error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/servers', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { name, lobby, playerId, map } = req.body;
        if (!name || !lobby || !playerId || !map) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        const db = readDB();
        const newServer = {
            id: Date.now(),
            name,
            lobby,
            playerId,
            map,
            status: 'online',
            createdAt: new Date().toISOString(),
            createdBy: req.user.id
        };
        db.servers.push(newServer);
        writeDB(db);
        res.json({ success: true, server: newServer });
    } catch (error) {
        console.error('❌ Create server error:', error);
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
        console.error('❌ Delete server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== АДМИНЫ =====
app.get('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db.admins);
    } catch (error) {
        console.error('❌ Get admins error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: 'Email обязателен' });
        }
        const db = readDB();
        const user = db.users.find(u => u.email === email);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        if (db.admins.includes(email)) {
            return res.status(400).json({ error: 'Уже администратор' });
        }
        db.admins.push(email);
        writeDB(db);
        res.json({ success: true, admins: db.admins });
    } catch (error) {
        console.error('❌ Add admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.delete('/api/admins/:email', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const email = decodeURIComponent(req.params.email);
        const db = readDB();
        db.admins = db.admins.filter(e => e !== email);
        writeDB(db);
        res.json({ success: true, admins: db.admins });
    } catch (error) {
        console.error('❌ Remove admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== СТАТИСТИКА =====
app.post('/api/users/:userId/stats', authMiddleware, (req, res) => {
    try {
        const userId = req.params.userId;
        const { kills, deaths } = req.body;
        if (userId !== req.user.id) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        const user = db.users[userIndex];
        user.kills += kills || 0;
        user.deaths += deaths || 0;
        user.matches += 1;
        const kd = user.deaths > 0 ? (user.kills / user.deaths) : user.kills;
        user.kdHistory.push(parseFloat(kd.toFixed(2)));
        if (user.kdHistory.length > 10) {
            user.kdHistory.shift();
        }
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
    } catch (error) {
        console.error('❌ Update stats error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ТОП ИГРОКОВ (по количеству игр на сервере) =====
app.get('/api/top-players', (req, res) => {
    try {
        const db = readDB();
        const topPlayers = db.users
            .map(user => ({
                username: user.username,
                standoffId: user.standoffId,
                kills: user.kills,
                matches: user.matches,
                serverMatches: user.serverMatches || 0,
                kd: user.deaths > 0 ? (user.kills / user.deaths).toFixed(2) : user.kills.toFixed(2)
            }))
            .sort((a, b) => b.serverMatches - a.serverMatches)
            .slice(0, 10);
        res.json(topPlayers);
    } catch (error) {
        console.error('❌ Get top players error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.get('/api/stats', (req, res) => {
    try {
        const db = readDB();
        const onlineCount = Math.floor(Math.random() * 150) + 50;
        res.json({
            online: onlineCount,
            tournaments: db.stats.totalTournaments || 0,
            servers: db.servers.length,
            totalUsers: db.users.length,
            pendingCount: db.pendingPlayers ? db.pendingPlayers.length : 0
        });
    } catch (error) {
        console.error('❌ Get stats error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ЗАПУСК =====
initDB();
 
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Database: ${DB_PATH}`);
    console.log(`👑 Супер-админ: ${SUPER_ADMIN_EMAIL}`);
    console.log(`🔐 JWT_SECRET: ${process.env.JWT_SECRET ? '✅ Установлен' : '❌ НЕ УСТАНОВЛЕН (используется default)'}`);
});
 
process.on('uncaughtException', (error) => {
    console.error('🔥 Необработанное исключение:', error);
});
 
process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 Необработанный rejection:', reason);
});
